// Package pipeline is the gateway request path: the ordered stages of
// architecture §4.2, from ingress to the usage and audit event.
//
//	1 Ingress   size limits; parse the wire format             reject
//	2 Identity  virtual key to caller, from the snapshot       reject
//	3 Limits    concurrency cap, requests per minute           reject
//	4 Inspect   fast detectors, then the Guard if configured   closed
//	5 Enforce   policy actions; masked request; value map      closed
//	6 Cache     exact lookup, then semantic lookup if eligible open: skip
//	7 Coalesce  identical requests in flight share one call    open
//	8 Route     hard constraints; the router's decision        closed
//	9 Upstream  call; next key before the first byte           error
//	10 Respond  rehydrate; the caller's wire format            stop the stream
//	11 After    cache admission; usage and audit event         open, except audit
//
// Tokens per minute and budgets are checked after the caches, so a hit costs
// nothing.
package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Kytherion/KyGate/internal/audit"
	"github.com/Kytherion/KyGate/internal/cache"
	"github.com/Kytherion/KyGate/internal/detect"
	"github.com/Kytherion/KyGate/internal/detect/guard"
	"github.com/Kytherion/KyGate/internal/events"
	"github.com/Kytherion/KyGate/internal/identity"
	"github.com/Kytherion/KyGate/internal/ingress"
	"github.com/Kytherion/KyGate/internal/limits"
	"github.com/Kytherion/KyGate/internal/mask"
	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/provider"
	anthropicp "github.com/Kytherion/KyGate/internal/provider/anthropic"
	openaip "github.com/Kytherion/KyGate/internal/provider/openai"
	"github.com/Kytherion/KyGate/internal/router"
	"github.com/Kytherion/KyGate/internal/store"
	"github.com/Kytherion/KyGate/internal/telemetry"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Gateway serves the model API.
type Gateway struct {
	Policies *policy.Holder
	Keys     *identity.Resolver
	Registry *provider.Registry
	Client   *provider.Client
	Catalog  *router.Catalog
	Cache    *cache.Exact
	Semantic *cache.Semantic // nil: no semantic cache
	NearMiss *cache.NearMiss // explains exact-cache misses; nil: off
	// Feedback records callers' ratings of answers (OB-4); nil: off.
	Feedback store.QualityStore
	Router   *router.Router  // routing decisions (OP-4); nil: off
	Budgets  *limits.Budgets // budget counters (OP-5); nil: off
	Rates    limits.Limiter  // rate limits per key (OP-5); nil: off
	// IdP checks user tokens from the company's identity provider (AC-3);
	// nil: only applications' own tokens are accepted.
	IdP       *identity.IdP
	Flights   *cache.Flights // coalescing (OP-6); nil: off
	Guard     *guard.Client  // nil: no Guard configured
	Memo      *guard.Memo    // the Guard's findings per segment
	Spool     *events.Spool
	Limit     *limits.Concurrency
	MasterKey []byte
	Metrics   *telemetry.Registry
	Logf      func(format string, a ...any)
	Version   string
}

// Handler returns the HTTP handler of the model API.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		g.serve(w, r, ingress.OpenAI, ingress.Chat, "/v1/chat/completions")
	})
	mux.HandleFunc("POST /v1/embeddings", func(w http.ResponseWriter, r *http.Request) {
		g.serve(w, r, ingress.OpenAI, ingress.Embeddings, "/v1/embeddings")
	})
	mux.HandleFunc("POST /v1/messages", func(w http.ResponseWriter, r *http.Request) {
		g.serve(w, r, ingress.Anthropic, ingress.Messages, "/v1/messages")
	})
	mux.HandleFunc("POST /v1/messages/count_tokens", func(w http.ResponseWriter, r *http.Request) {
		g.serve(w, r, ingress.Anthropic, ingress.CountTokens, "/v1/messages/count_tokens")
	})
	mux.HandleFunc("GET /v1/models", g.models)
	mux.HandleFunc("POST /kygate/v1/feedback", g.feedback)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /readyz", g.ready)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fam := ingress.OpenAI
		if r.Header.Get("Anthropic-Version") != "" {
			fam = ingress.Anthropic
		}
		writeError(w, fam, 404, "not_found", fmt.Sprintf("KyGate does not serve %s %s. It serves POST /v1/chat/completions, POST /v1/embeddings, POST /v1/messages, POST /v1/messages/count_tokens, and GET /v1/models.", r.Method, r.URL.Path))
	})
	return mux
}

func (g *Gateway) ready(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	n := len(g.Registry.All())
	if n == 0 {
		w.WriteHeader(503)
		w.Write([]byte(`{"status":"not_ready","reason":"no provider key or local model server is configured"}`))
		return
	}
	if g.Spool.Full() && g.Policies.Current().Audit.OnSpoolFull == "block" {
		w.WriteHeader(503)
		w.Write([]byte(`{"status":"not_ready","reason":"the event spool is full"}`))
		return
	}
	fmt.Fprintf(w, `{"status":"ready","connections":%d}`, n)
}

func (g *Gateway) orgKey(purpose, org string) []byte {
	return store.DeriveKey(g.MasterKey, purpose, org)
}

// stages records how long each stage took.
type stages struct {
	m    map[string]int
	last time.Time
	seq  []stageSpan // in order, for traces
}

type stageSpan struct {
	name       string
	start, end time.Time
}

func newStages(t time.Time) *stages { return &stages{m: map[string]int{}, last: t} }

func (s *stages) mark(name string) {
	now := time.Now()
	s.m[name] += int(now.Sub(s.last).Microseconds())
	s.seq = append(s.seq, stageSpan{name, s.last, now})
	s.last = now
}

// decision is the outcome of the enforce stage.
type decision struct {
	refuse       string // non-empty: the request is refused with this message
	outcome      string // blocked | refused
	vm           *mask.ValueMap
	masked       int
	sensitiveOut bool // protected values leave unmasked (monitor mode, or to a local target)
	injected     bool // a threat was flagged: the answer is never cached
	alert        bool
	counts       []store.FindingCount
	blockedTypes []string
}

type serveCtx struct {
	g      *Gateway
	w      http.ResponseWriter
	r      *http.Request
	req    *ingress.Request
	pol    *policy.Policy
	caller identity.Caller
	ev     *store.Event
	st     *stages
	start  time.Time
	family ingress.Family
	wrote  bool
	tags   []string // X-KyGate-Cache-Tags, for the stored answer's labels
	span   trace.Span
	tctx   context.Context
	out    *detect.OutputInspector // output inspection of the answer (PR-6), or nil
	// nearMissScope is set on an exact-cache miss: the request is compared
	// with the same key's recent requests when the event is written.
	nearMissScope  string
	route          router.Decision // the router's shadow decision, when it ran
	budget         limits.Check    // the budget reservation, settled when the event is written
	tokenEstimate  int             // tokens taken from the key's rate limit before the call
	tokenLimit     int
	userTokenLimit int      // the person's tokens per minute, when a user token named one
	downgraded     bool     // past a soft limit, the request went to a cheaper model
	markers        []string // provider prompt-cache markers KyGate added (OP-2)
}

func (g *Gateway) serve(w http.ResponseWriter, r *http.Request, family ingress.Family, endpoint ingress.Endpoint, path string) {
	start := time.Now()
	pol := g.Policies.Current()
	ev := &store.Event{ID: identity.NewID("req_"), Time: start, Family: string(family), Endpoint: string(endpoint),
		Cache: "off", Mode: string(pol.Mode), PolicyVersion: pol.Version, Outcome: "ok"}
	sc := &serveCtx{g: g, w: w, r: r, pol: pol, ev: ev, st: newStages(start), start: start, family: family}
	// A trace span for the request, when tracing is on (OB-5). The caller's
	// trace context is honoured; it is never forwarded to a provider.
	tctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	tctx, sc.span = telemetry.Tracer().Start(tctx, "kygate "+path, trace.WithSpanKind(trace.SpanKindServer), trace.WithTimestamp(start))
	sc.tctx = tctx
	w.Header().Set("X-KyGate-Request-Id", ev.ID)
	defer sc.finish()

	// 1 Ingress
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxBodyBytes)
	body, err := ingress.Decode(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			sc.fail(413, "client_error", "request_too_large", fmt.Sprintf("The request is larger than %d MB.", limits.MaxBodyBytes>>20))
			return
		}
		sc.fail(400, "client_error", "invalid_request", err.Error())
		return
	}
	req, err := ingress.Parse(family, endpoint, body)
	if err != nil {
		sc.fail(400, "client_error", "invalid_request", err.Error())
		return
	}
	sc.req = req
	ev.ModelRequested, ev.Stream = req.Model, req.Stream
	ev.Unreadable = req.Unreadable
	sc.st.mark("ingress")

	// 2 Identity
	caller, ok := g.Keys.Resolve(identity.FromRequest(r))
	if !ok {
		sc.fail(401, "client_error", "invalid_api_key", "KyGate did not recognize this API key. Use a KyGate virtual key (kg-...), not a provider key. Create one with 'kygate key create <name>'.")
		return
	}
	ev.OrgID, ev.KeyID, ev.KeyName = caller.OrgID, caller.KeyID, caller.KeyName
	ev.TeamName, ev.ProjectName = caller.TeamName, caller.ProjectName
	// The person behind the request, from a signed user token (AC-3). The
	// header is never forwarded to a provider.
	if err := g.Keys.User(r.Context(), &caller, r.Header.Get(identity.UserHeader), g.IdP, g.orgKey("user", caller.OrgID), time.Now()); err != nil {
		sc.caller = caller
		status, code := 401, "invalid_user_token"
		if errors.Is(err, identity.ErrIdPUnavailable) {
			status, code = 503, "user_token_unverifiable"
		}
		sc.fail(status, "client_error", code, "KyGate refused this request: "+identity.UserHeader+": "+err.Error()+". (request "+ev.ID+")")
		return
	}
	sc.caller = caller
	ev.User = caller.User
	// The caller's effective policy: the organization's, merged with its
	// team's, project's, and key's files (AC-4, architecture §3.6).
	if p := g.Policies.For(caller.TeamName, caller.ProjectName, caller.KeyName); p != pol {
		pol, sc.pol = p, p
		ev.Mode, ev.PolicyVersion = string(p.Mode), p.Version
	}
	sc.st.mark("identity")

	// The audit trail is not optional: with a full spool and on_spool_full:
	// block, no request goes out unrecorded.
	if g.Spool.Full() && pol.Audit.OnSpoolFull == "block" {
		sc.fail(503, "error", "audit_unavailable", "KyGate cannot record this request because its event spool is full, and the policy refuses unrecorded requests.")
		return
	}

	// 3 Limits
	if !g.Limit.TryAcquire() {
		sc.fail(503, "error", "overloaded", "KyGate is at its limit of concurrent requests. Retry shortly.")
		return
	}
	defer g.Limit.Release()
	if !g.rateRequest(sc) || !g.rateUser(sc) {
		return
	}
	sc.st.mark("limits")

	// 8 Route, hard constraints first: the enforce stage needs to know
	// whether the target is local.
	target, terr := router.Resolve(g.Registry, string(family), req.Model)
	regionRefusal, regionAlert := "", false
	if terr == nil {
		ev.Hosting = target.Hosting
		target, regionRefusal, regionAlert = pinRegions(pol, target)
	}

	// 4 Inspect
	findings := g.inspect(pol, req)
	sc.st.mark("inspect")
	// 4b The Guard, for the data types only its ML detectors find. Security
	// fails closed (invariant 2): without an answer, on_guard_unavailable decides.
	mlFindings, threats, gr := g.guardInspect(r.Context(), pol, req)
	ev.Guard = gr.status
	guardDown := gr.err != nil
	if guardDown {
		if r.Context().Err() != nil {
			ev.Outcome, ev.Reason = "canceled", "the client closed the connection"
			return
		}
		g.Metrics.Add("kygate_guard_unavailable_total", 1, "on_guard_unavailable", pol.Data.OnGuardUnavailable)
		if msg := guardRefusal(pol, gr, terr == nil && target.Hosting == "local", req.Model); msg != "" {
			sc.fail(503, "refused", "guard_unavailable", msg+" (request "+ev.ID+")")
			return
		}
	} else {
		findings = append(findings, mlFindings...)
	}
	if gr.status != "" {
		sc.st.mark("guard")
	}

	// 5 Enforce
	known := knownHosts(req) // before masking changes the text
	d := g.enforce(pol, req, findings, target, terr == nil)
	sc.out = outputInspector(pol, endpoint, known, d.vm)
	td := decideThreats(pol, req, threats)
	d.counts = append(d.counts, td.counts...)
	d.injected = td.flagged
	for _, c := range td.counts {
		g.Metrics.Add("kygate_threats_total", float64(c.Count), "type", c.Type, "action", c.Action, "applied", strconv.FormatBool(c.Applied))
	}
	ev.Findings, ev.Alert = d.counts, d.alert || guardDown || td.flagged || regionAlert
	if regionAlert {
		ev.Reason = "region: no connection in the policy's regions (monitor mode: sent anyway)"
	}
	sc.st.mark("enforce")
	if d.refuse != "" {
		w.Header().Set("X-KyGate-Blocked", strings.Join(d.blockedTypes, ","))
		sc.fail(403, d.outcome, "policy_"+d.outcome, d.refuse+" (request "+ev.ID+")")
		return
	}
	if len(td.block) > 0 {
		w.Header().Set("X-KyGate-Blocked", strings.Join(td.block, ","))
		sc.fail(403, "blocked", "policy_blocked", fmt.Sprintf("KyGate blocked this request: a %s looks like %s (score %.2f), which the policy blocks. (request %s)",
			td.where, strings.ToLower(strings.ReplaceAll(strings.Join(td.block, ", "), "_", " ")), td.best, ev.ID))
		return
	}
	if terr != nil {
		sc.fail(503, "refused", "no_target", terr.Error())
		return
	}
	if regionRefusal != "" {
		w.Header().Set("X-KyGate-Blocked", "REGION")
		sc.fail(403, "refused", "region_pinned", regionRefusal+" (request "+ev.ID+")")
		return
	}
	if d.masked > 0 {
		w.Header().Set("X-KyGate-Masked", strconv.Itoa(d.masked))
	}
	if pol.Mode == policy.Monitor {
		w.Header().Set("X-KyGate-Mode", "monitor")
	}

	// 6 Cache
	conversation := ""
	if len(req.Conversation) > 0 {
		sum := sha256.Sum256(req.Conversation)
		conversation = hex.EncodeToString(sum[:16])
	}
	fp, cacheable := g.cacheCheck(sc, d)
	var sem *semReq
	if cacheable {
		if e, hit := g.Cache.Get(r.Context(), g.orgKey("cache", caller.OrgID), caller.OrgID, fp); hit {
			sc.st.mark("cache")
			g.serveHit(sc, e, d.vm, conversation)
			return
		}
		ev.Cache = "miss"
		// Why it missed: the same question with a volatile detail changed
		// (a measurement; it changes nothing). Worked out when the
		// event is written, after the answer.
		sc.nearMissScope = "key:" + caller.KeyID + "/" + string(family) + "/" + string(endpoint) + "/" + req.Model
		sc.st.mark("cache")
		// 6b Semantic cache: a look-alike last message.
		if sem = g.semanticEligible(sc, d, fp); sem != nil {
			m, serve := g.semanticLookup(sc, sem)
			sc.st.mark("semantic")
			if serve {
				g.serveHit(sc, m.Entry, d.vm, conversation)
				ev.CacheReason = fmt.Sprintf("semantic match, similarity %.3f", m.Similarity)
				return
			}
		}
	}
	sc.st.mark("cache")

	// 7 Coalesce: an identical request already in flight shares its answer.
	// A follower calls no model, so, like a cache hit, it is not budgeted.
	var fl *cache.Flight
	var resp *http.Response
	connName := ""
	follower := false
	if cacheable && g.Flights != nil {
		key := fp + "|stream=" + strconv.FormatBool(req.Stream)
		var lead bool
		fl, lead = g.Flights.Join(key)
		if lead {
			lf := fl
			defer func() { lf.Abort(); g.Flights.Leave(key, lf) }()
		} else if fr, cn, ok := fl.Wait(r.Context()); ok {
			follower, resp, connName = true, fr, cn
			ev.Cache, ev.CacheReason = "coalesced", "an identical request was in flight; it shared that answer"
			fl = nil
		} else {
			fl = nil // the leader gave up before answering: this request calls on its own
		}
		sc.st.mark("coalesce")
	}

	wantUsage := true
	if family == ingress.OpenAI && endpoint == ingress.Chat && req.Stream {
		so := obj(req.Body["stream_options"])
		wantUsage = so != nil && so["include_usage"] == true
	}
	var upBody []byte
	if !follower {
		// 3b Budgets and tokens per minute, after the caches: a hit costs
		// nothing. Past a soft limit the router may send the request one tier down.
		if !g.budgetStage(sc, &target, conversation) {
			return
		}

		// 8 Route, in shadow mode: recorded, and the request is unchanged.
		g.routeShadow(sc, target, conversation)
		sc.st.mark("route")

		// 9 Upstream
		if target.UpstreamModel != req.Model {
			req.Body["model"] = target.UpstreamModel
		}
		if family == ingress.OpenAI && endpoint == ingress.Chat && req.Stream {
			so := obj(req.Body["stream_options"])
			if so == nil {
				so = map[string]any{}
				req.Body["stream_options"] = so
			}
			so["include_usage"] = true // the provider's reported usage is the billing truth
		}
		sc.markers = g.addCacheMarkers(sc)
		var hdr http.Header
		if family == ingress.Anthropic {
			hdr = anthropicp.ForwardHeaders(r.Header)
		} else {
			hdr = openaip.ForwardHeaders(r.Header)
		}
		upBody = req.Encode()
		ctx := r.Context()
		if fl != nil {
			// Others may follow: the call outlives this caller's connection.
			ctx = context.WithoutCancel(ctx)
		}
		up, conn, attempts, err := g.Client.Do(ctx, target.Pool, provider.Call{
			Method: http.MethodPost, Path: path, Query: r.URL.RawQuery, Body: upBody, Header: hdr, Conversation: conversation,
		})
		ev.Attempts = attempts
		if conn != nil {
			ev.Connection, connName = conn.Name, conn.Name
		}
		sc.st.mark("upstream")
		if err != nil {
			if r.Context().Err() != nil {
				ev.Outcome, ev.Reason = "canceled", "the client closed the connection"
				return
			}
			g.Metrics.Add("kygate_upstream_failures_total", 1, "provider", target.Provider)
			sc.fail(502, "error", "upstream_unreachable", "KyGate could not reach the model provider: "+err.Error())
			return
		}
		resp = up
		if fl != nil {
			resp = fl.Start(up, connName)
		}
	} else {
		ev.Connection = connName
		g.Metrics.Add("kygate_coalesced_total", 1)
	}
	defer resp.Body.Close()
	ev.Status = resp.StatusCode
	g.copyResponseHeaders(w, resp, family)
	w.Header().Set("X-KyGate-Connection", connName)
	switch {
	case follower:
		w.Header().Set("X-KyGate-Cache", "coalesced")
	case cacheable:
		w.Header().Set("X-KyGate-Cache", "miss")
	default:
		w.Header().Set("X-KyGate-Cache", ev.Cache)
	}
	if len(sc.markers) > 0 {
		w.Header().Set("X-KyGate-Prompt-Cache", "marked "+strings.Join(sc.markers, ","))
	}

	if resp.StatusCode >= 400 {
		ev.Outcome = "error"
		if resp.StatusCode < 500 && resp.StatusCode != 429 {
			ev.Outcome = "client_error"
		}
		ev.Reason = fmt.Sprintf("the provider answered %d", resp.StatusCode)
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		sc.wrote = true
		sc.ttfb()
		io.Copy(w, io.LimitReader(resp.Body, 8<<20))
		return
	}

	// 10 Respond
	var answer map[string]any
	isStream := req.Stream && strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream")
	if isStream {
		answer = g.relayStream(sc, resp, d.vm, wantUsage)
	} else {
		answer = g.relayJSON(sc, resp, d.vm)
	}
	sc.st.mark("respond")
	if answer == nil {
		return
	}

	// 11 After
	usage := usageOf(family, obj(answer["usage"]))
	if endpoint == ingress.Embeddings {
		usage = router.Usage{Input: num(obj(answer["usage"])["prompt_tokens"])}
	}
	served := str(answer["model"])
	if served == "" {
		served = target.UpstreamModel
	}
	ev.ModelServed = served
	ev.InputTokens, ev.CachedTokens, ev.CacheWrite, ev.OutputTokens = usage.Input, usage.CachedInput, usage.CacheWrite, usage.Output
	cost, priced := g.Catalog.Cost(served, target.Hosting, usage)
	if !priced {
		cost, priced = g.Catalog.Cost(req.Model, target.Hosting, usage)
	}
	ev.CostUSD, ev.Unpriced = cost, !priced && endpoint != ingress.CountTokens
	if follower {
		// The leader paid for the call; this request avoided it.
		ev.CostUSD, ev.CostAvoidedUSD = 0, cost
	}
	g.routeSaving(sc, cost, target.Hosting, usage)
	if sc.downgraded {
		// What the answer would have cost on the model the request names.
		if would, ok := g.Catalog.Cost(req.Model, target.Hosting, usage); ok && would > cost {
			ev.RouteSavingUSD = would - cost
		}
	}
	// A cheaper model's answer is not stored under the requested model's
	// fingerprint: once the budget resets, that model answers again.
	if cacheable && !follower && ev.Outcome == "ok" && !sc.out.Flagged() && !sc.downgraded && clean(family, endpoint, answer) {
		e := &cache.Entry{Family: string(family), Body: ingress.Marshal(answer), Model: served, Connection: connName,
			Hosting: target.Hosting, Usage: usage, CostUSD: cost, Created: time.Now()}
		if err := g.Cache.Put(g.orgKey("cache", caller.OrgID), caller.OrgID, fp, e, time.Duration(pol.Cache.Exact.TTL), g.cacheLabels(sc)...); err != nil {
			g.Logf("cache: store failed: %v", err)
		}
		g.semanticAfter(sc, sem, e, answer)
	}
	if pol.Audit.CapturePayloads == "masked" && !d.sensitiveOut && upBody != nil {
		g.capture(ev, upBody, answer)
	}
	sc.st.mark("after")
}

// inspect runs the fast detectors on every segment.
func (g *Gateway) inspect(pol *policy.Policy, req *ingress.Request) []detect.Finding {
	var all []detect.Finding
	det := pol.Detectors()
	for i, s := range req.Segments {
		all = append(all, det.Scan(i, s.Text)...)
	}
	return all
}

// enforce applies the policy actions. In monitor mode it records what it
// would have done and changes nothing (principle 6).
func (g *Gateway) enforce(pol *policy.Policy, req *ingress.Request, findings []detect.Finding, target router.Target, routable bool) decision {
	d := decision{vm: mask.NewValueMap()}
	enforce := pol.Mode == policy.Enforce
	local := routable && target.Hosting == "local"
	type key struct {
		typ    string
		action policy.Action
	}
	counts := map[key]int{}
	var blockTypes, localTypes []string
	spans := map[int][]mask.Span{}

	for _, f := range findings {
		a := pol.ActionFor(f.Type)
		if req.Endpoint == ingress.Embeddings && (a == policy.Mask || a == policy.Redact) {
			// Embedding requests are never masked, because masking changes the vectors.
			a = pol.Data.Embeddings
			if a == policy.Allow {
				d.sensitiveOut = true
			}
		}
		counts[key{f.Type, a}]++
		switch a {
		case policy.Block:
			blockTypes = appendUnique(blockTypes, f.Type)
		case policy.LocalOnly:
			if local {
				d.sensitiveOut = true
			} else {
				localTypes = appendUnique(localTypes, f.Type)
			}
		case policy.Mask, policy.Redact:
			if enforce {
				spans[f.Segment] = append(spans[f.Segment], mask.Span{Start: f.Start, End: f.End, Entity: f.Type, Redact: a == policy.Redact})
			} else {
				d.sensitiveOut = true
			}
		case policy.Alert:
			d.alert = true
		}
	}
	for _, kind := range req.Unreadable {
		a := pol.Data.UnreadableContent
		counts[key{"UNREADABLE/" + strings.ToUpper(kind), a}]++
		switch a {
		case policy.Block:
			blockTypes = appendUnique(blockTypes, kind)
		case policy.LocalOnly:
			if !local {
				localTypes = appendUnique(localTypes, kind)
			}
		}
	}
	if !enforce && (len(blockTypes) > 0 || len(localTypes) > 0) {
		d.sensitiveOut = true
	}

	refusing := enforce && (len(blockTypes) > 0 || len(localTypes) > 0)
	for k, n := range counts {
		applied := enforce
		if k.action == policy.Allow || k.action == policy.Alert {
			applied = true
		}
		if refusing && (k.action == policy.Mask || k.action == policy.Redact) {
			applied = false // the request never left
		}
		d.counts = append(d.counts, store.FindingCount{Type: k.typ, Action: string(k.action), Count: n, Applied: applied})
	}
	sort.Slice(d.counts, func(i, j int) bool {
		if d.counts[i].Type != d.counts[j].Type {
			return d.counts[i].Type < d.counts[j].Type
		}
		return d.counts[i].Action < d.counts[j].Action
	})
	for _, c := range d.counts {
		g.Metrics.Add("kygate_findings_total", float64(c.Count), "type", c.Type, "action", c.Action, "applied", strconv.FormatBool(c.Applied))
	}

	if enforce && len(blockTypes) > 0 {
		d.outcome, d.blockedTypes = "blocked", blockTypes
		d.refuse = "KyGate blocked this request: it contains " + humanList(blockTypes) + ", which the policy blocks. Remove it and send the request again."
		return d
	}
	if enforce && len(localTypes) > 0 {
		d.outcome, d.blockedTypes = "refused", localTypes
		where := "an external provider"
		if !routable {
			where = "no available target"
		}
		d.refuse = fmt.Sprintf("KyGate refused this request: it contains %s, which the policy keeps on local models, and model %q is served by %s. Use a model from a local model server.", humanList(localTypes), req.Model, where)
		return d
	}
	if enforce {
		for i, seg := range req.Segments {
			if sp, ok := spans[i]; ok {
				sp = mergeSpans(sp)
				seg.Set(d.vm.Apply(seg.Text, sp))
				d.masked += len(sp)
			}
		}
	}
	return d
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

func humanList(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// cacheCheck decides whether the exact cache may be used, and computes the
// fingerprint. A request is never cached when its answer depends on hidden
// state, when protected values would be stored unmasked, when the client asks
// for no cache, or when the same caller repeats it within the repeat window.
func (g *Gateway) cacheCheck(sc *serveCtx, d decision) (string, bool) {
	pol, req, ev := sc.pol, sc.req, sc.ev
	bypass := func(reason string) (string, bool) {
		ev.Cache, ev.CacheReason = "bypass", reason
		return "", false
	}
	if !pol.CacheEnabled() {
		ev.Cache = "off"
		return "", false
	}
	switch {
	case req.Endpoint == ingress.CountTokens:
		ev.Cache = "off"
		return "", false
	case req.HiddenState != "":
		return bypass("depends on " + req.HiddenState)
	case d.sensitiveOut:
		return bypass("protected values are not masked in this request")
	case d.injected:
		return bypass("the request was flagged as a threat (prompt injection)")
	}
	hint := strings.ToLower(sc.r.Header.Get("X-KyGate-Cache"))
	if hint == "no-cache" || hint == "bypass" || strings.Contains(strings.ToLower(sc.r.Header.Get("Cache-Control")), "no-cache") {
		return bypass("the client asked for no cache")
	}
	tags, err := parseCacheTags(sc.r.Header)
	if err != nil {
		// Never store an answer without the tags its application expects to
		// purge it by.
		return bypass(err.Error())
	}
	sc.tags = tags
	scope := "org:" + sc.caller.OrgID
	if pol.Cache.Exact.Scope == "key" || hint == "scope=key" {
		scope = "key:" + sc.caller.KeyID
	}
	fp := cache.Fingerprint(g.orgKey("fingerprint", sc.caller.OrgID),
		[]byte(scope), []byte(req.Family), []byte(req.Endpoint), []byte(req.Model), cache.Canonical(req.Body), []byte(pol.CacheVersion))
	if g.Cache.Repeat(sc.caller.KeyID, fp, pol.RepeatWindow()) {
		return bypass("the same key repeated this request within the repeat window")
	}
	return fp, true
}

// serveHit answers from the cache. The stored answer is in placeholder form
// and receives the caller's own values (architecture §3.3).
func (g *Gateway) serveHit(sc *serveCtx, e *cache.Entry, vm *mask.ValueMap, conversation string) {
	ev, w, req := sc.ev, sc.w, sc.req
	ev.Cache, ev.Status = "hit", 200
	kind := "exact"
	switch e.Tier {
	case cache.TierDisk:
		ev.CacheReason = "served from the cache file"
	case cache.TierSemantic:
		kind = "semantic"
	}
	w.Header().Set("X-KyGate-Cache-Kind", kind)
	ev.ModelServed, ev.Connection, ev.Hosting = e.Model, e.Connection, e.Hosting
	ev.CostAvoidedUSD = e.CostUSD
	if e.CostUSD == 0 && e.Hosting != "local" {
		if _, priced := g.Catalog.Cost(e.Model, e.Hosting, e.Usage); !priced {
			ev.Unpriced = true
		}
	}
	// The next turn of this conversation goes to the account that produced the
	// answer, because reasoning signatures and prompt caches are per account.
	g.Registry.Pin(conversation, e.Connection)

	body, err := decodeObj(e.Body)
	if err != nil {
		sc.fail(500, "error", "cache_error", "KyGate could not read a cached answer.")
		return
	}
	w.Header().Set("X-KyGate-Cache", "hit")
	inspectAnswer(sc.family, body, sc.out)
	if sc.refuseBlockedAnswer() {
		return
	}
	sc.markRemoved()
	rehydrate(sc.family, body, vm)
	w.Header().Set("X-KyGate-Model", e.Model)
	if req.Stream {
		wantUsage := true
		if sc.family == ingress.OpenAI {
			so := obj(req.Body["stream_options"])
			wantUsage = so != nil && so["include_usage"] == true
		}
		var evs []sseEvent
		if sc.family == ingress.Anthropic {
			evs = synthAnthropic(body)
		} else {
			evs = synthOpenAI(body, wantUsage)
		}
		sw := newSSEWriter(w)
		sc.wrote = true
		for _, x := range evs {
			if err := sw.write(encodeSSE(sc.family, x)); err != nil {
				return
			}
			sc.ttfb()
		}
		return
	}
	b := ingress.Marshal(body)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(200)
	sc.wrote = true
	sc.ttfb()
	w.Write(b)
}

// relayJSON rehydrates and writes a non-streamed answer. It returns the
// masked answer for the cache.
func (g *Gateway) relayJSON(sc *serveCtx, resp *http.Response, vm *mask.ValueMap) map[string]any {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		sc.fail(502, "error", "upstream_read", "KyGate lost the connection to the model provider while reading the answer.")
		return nil
	}
	masked, err := decodeObj(raw)
	if err != nil {
		// Not JSON: pass it through as it came.
		sc.w.WriteHeader(resp.StatusCode)
		sc.wrote = true
		sc.ttfb()
		sc.w.Write(raw)
		return nil
	}
	out, _ := decodeObj(raw)
	inspectAnswer(sc.family, out, sc.out)
	if sc.refuseBlockedAnswer() {
		return masked // the call is still counted; the answer is never cached
	}
	sc.markRemoved()
	rehydrate(sc.family, out, vm)
	if m := str(out["model"]); m != "" {
		sc.w.Header().Set("X-KyGate-Model", m)
	}
	b := ingress.Marshal(out)
	sc.w.Header().Set("Content-Type", "application/json")
	sc.w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	sc.w.WriteHeader(resp.StatusCode)
	sc.wrote = true
	sc.ttfb()
	sc.w.Write(b)
	return masked
}

// relayStream rehydrates and relays a streamed answer. It returns the masked
// answer, assembled, for the cache.
func (g *Gateway) relayStream(sc *serveCtx, resp *http.Response, vm *mask.ValueMap, wantUsage bool) map[string]any {
	w := sc.w
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	sc.wrote = true
	sw := newSSEWriter(w)

	var handle func(sseEvent) []sseEvent
	var oa *openaiStream
	var an *anthropicStream
	if sc.family == ingress.Anthropic {
		an = newAnthropicStream(vm, sc.out)
		handle = an.handle
	} else {
		oa = newOpenAIStream(vm, sc.out, wantUsage)
		handle = oa.handle
	}
	clientGone := false
	err := readSSE(resp.Body, func(ev sseEvent) error {
		for _, out := range handle(ev) {
			if oa != nil && string(out.Data) == "[DONE]" {
				for _, f := range oa.flushAll() {
					if err := sw.write(encodeSSE(sc.family, f)); err != nil {
						clientGone = true
						return err
					}
				}
			}
			if err := sw.write(encodeSSE(sc.family, out)); err != nil {
				clientGone = true
				return err
			}
			sc.ttfb()
			if sc.out != nil && len(sc.out.Blocked) > 0 {
				return errOutputBlocked
			}
		}
		return nil
	})
	ev := sc.ev
	if clientGone || sc.r.Context().Err() != nil {
		ev.Outcome, ev.Reason = "canceled", "the client closed the connection during the stream"
		return nil
	}
	if errors.Is(err, errOutputBlocked) {
		// Output inspection stops the stream (architecture §4.2, stage 10). The
		// headers are already sent: the reason goes in an error event.
		msg := outputBlockMessage(sc.out, ev.ID)
		ev.Outcome, ev.Reason = "blocked", msg
		if sc.family == ingress.Anthropic {
			sw.write(encodeSSE(sc.family, sseEvent{Event: "error", Data: ingress.Marshal(map[string]any{"type": "error", "error": map[string]any{"type": "permission_error", "message": msg}})}))
			return an.acc.build()
		}
		sw.write(encodeSSE(sc.family, sseEvent{Data: ingress.Marshal(map[string]any{"error": map[string]any{"type": "permission_error", "code": "policy_blocked", "message": msg}})}))
		return oa.acc.build()
	}
	if err != nil {
		// A failure in mid-stream ends the stream with an error event.
		ev.Outcome, ev.Reason = "error", "the provider stream broke: "+err.Error()
		msg := "KyGate lost the connection to the model provider during the answer."
		if sc.family == ingress.Anthropic {
			sw.write(encodeSSE(sc.family, sseEvent{Event: "error", Data: ingress.Marshal(map[string]any{"type": "error", "error": map[string]any{"type": "api_error", "message": msg}})}))
		} else {
			sw.write(encodeSSE(sc.family, sseEvent{Data: ingress.Marshal(map[string]any{"error": map[string]any{"type": "api_error", "message": msg}})}))
		}
	}
	if an != nil {
		if an.failed || !an.acc.done {
			if ev.Outcome == "ok" {
				ev.Outcome, ev.Reason = "error", "the provider stream ended without a final event"
			}
		}
		return an.acc.build()
	}
	if oa.failed {
		ev.Outcome, ev.Reason = "error", "the provider sent an error in the stream"
	} else if !oa.acc.done {
		for _, f := range oa.flushAll() {
			sw.write(encodeSSE(sc.family, f))
		}
	}
	return oa.acc.build()
}

func (g *Gateway) copyResponseHeaders(w http.ResponseWriter, resp *http.Response, family ingress.Family) {
	list := openaip.ResponseHeaders
	if family == ingress.Anthropic {
		list = anthropicp.ResponseHeaders
	}
	for _, h := range list {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
}

// capture stores the masked request and answer in the event, encrypted.
func (g *Gateway) capture(ev *store.Event, request []byte, answer map[string]any) {
	plain := ingress.Marshal(map[string]any{"request": jsonRaw(request), "response": answer})
	sealed, err := store.Seal(g.orgKey("payload", ev.OrgID), plain, []byte(ev.OrgID+"/"+ev.ID))
	if err == nil {
		ev.Payload = sealed
	}
}

type jsonRaw []byte

func (j jsonRaw) MarshalJSON() ([]byte, error) { return j, nil }

// fail answers with an error in the caller's format.
func (sc *serveCtx) fail(status int, outcome, kind, msg string) {
	sc.ev.Status, sc.ev.Outcome = status, outcome
	if sc.ev.Reason == "" {
		sc.ev.Reason = msg
	}
	if sc.wrote {
		return
	}
	sc.wrote = true
	sc.ttfb()
	writeError(sc.w, sc.family, status, kind, msg)
}

func (sc *serveCtx) ttfb() {
	if sc.ev.TTFBMS == 0 {
		sc.ev.TTFBMS = time.Since(sc.start).Milliseconds()
		if sc.ev.TTFBMS == 0 {
			sc.ev.TTFBMS = 1
		}
	}
}

// finish writes the usage and audit event and the metrics.
func (sc *serveCtx) finish() {
	sc.recordOutput()
	sc.g.settleLimits(sc)
	if sc.nearMissScope != "" {
		sc.ev.NearMiss = sc.g.NearMiss.Observe(sc.nearMissScope, sc.req.Body)
	}
	g, ev := sc.g, sc.ev
	if ev.Status == 0 {
		ev.Status = 200
	}
	ev.TotalMS = time.Since(sc.start).Milliseconds()
	ev.Stages = sc.st.m
	if ev.OrgID == "" {
		ev.OrgID = "unknown"
	}
	// The gateway's signature, checked before the event is sealed into the
	// audit ledger (GV-3): a row written behind KyGate's back has none.
	if len(g.MasterKey) > 0 {
		ev.MAC = audit.NewKeys(g.MasterKey, ev.OrgID).Sign(*ev)
	}
	if err := g.Spool.Append(ev); err != nil {
		g.Logf("event %s not recorded: %v", ev.ID, err)
		g.Metrics.Add("kygate_events_dropped_total", 1)
	}
	g.Metrics.Add("kygate_requests_total", 1, "family", ev.Family, "endpoint", ev.Endpoint, "outcome", ev.Outcome, "cache", ev.Cache)
	g.Metrics.Observe("kygate_request_duration_seconds", time.Since(sc.start).Seconds(), "endpoint", ev.Endpoint)
	if ev.InputTokens+ev.CachedTokens+ev.CacheWrite+ev.OutputTokens > 0 {
		g.Metrics.Add("kygate_tokens_total", float64(ev.InputTokens), "kind", "input")
		g.Metrics.Add("kygate_tokens_total", float64(ev.CachedTokens), "kind", "cached_input")
		g.Metrics.Add("kygate_tokens_total", float64(ev.CacheWrite), "kind", "cache_write")
		g.Metrics.Add("kygate_tokens_total", float64(ev.OutputTokens), "kind", "output")
	}
	g.Metrics.Add("kygate_cost_usd_total", ev.CostUSD)
	g.Metrics.Add("kygate_cost_avoided_usd_total", ev.CostAvoidedUSD)
	sc.endSpan()
}

// endSpan records the request in its trace span: metadata only, never text,
// never a value, never a key (invariants 3 and 10).
func (sc *serveCtx) endSpan() {
	span, ev := sc.span, sc.ev
	if span == nil || !span.IsRecording() {
		return
	}
	for _, st := range sc.st.seq {
		_, s := telemetry.Tracer().Start(sc.tctx, "kygate."+st.name, trace.WithTimestamp(st.start))
		s.End(trace.WithTimestamp(st.end))
	}
	attrs := []attribute.KeyValue{
		attribute.String("kygate.request_id", ev.ID),
		attribute.String("kygate.family", ev.Family),
		attribute.String("kygate.endpoint", ev.Endpoint),
		attribute.String("kygate.outcome", ev.Outcome),
		attribute.String("kygate.cache", ev.Cache),
		attribute.String("kygate.mode", ev.Mode),
		attribute.String("kygate.policy_version", ev.PolicyVersion),
		attribute.Bool("kygate.stream", ev.Stream),
		attribute.Int("http.response.status_code", ev.Status),
		attribute.Int64("kygate.tokens.input", ev.InputTokens),
		attribute.Int64("kygate.tokens.cached_input", ev.CachedTokens),
		attribute.Int64("kygate.tokens.output", ev.OutputTokens),
		attribute.Float64("kygate.cost_usd", ev.CostUSD),
		attribute.Float64("kygate.cost_avoided_usd", ev.CostAvoidedUSD),
	}
	for k, v := range map[string]string{
		"kygate.org_id": ev.OrgID, "kygate.key_id": ev.KeyID, "kygate.model.requested": ev.ModelRequested,
		"kygate.model.served": ev.ModelServed, "kygate.connection": ev.Connection, "kygate.hosting": ev.Hosting,
		"kygate.semantic": ev.Semantic, "kygate.semantic_check": ev.SemanticCheck,
	} {
		if v != "" {
			attrs = append(attrs, attribute.String(k, v))
		}
	}
	if ev.Attempts > 0 {
		attrs = append(attrs, attribute.Int("kygate.attempts", ev.Attempts))
	}
	if len(ev.Findings) > 0 {
		var f []string
		for _, c := range ev.Findings {
			f = append(f, fmt.Sprintf("%s:%s:%d", c.Type, c.Action, c.Count))
		}
		attrs = append(attrs, attribute.StringSlice("kygate.findings", f))
	}
	span.SetAttributes(attrs...)
	if ev.Outcome == "error" {
		span.SetStatus(codes.Error, ev.Outcome)
	}
	span.End()
}

// sseWriter writes events with a per-write deadline, because a single
// server-wide write timeout would cut long answers (architecture §5.6).
type sseWriter struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func newSSEWriter(w http.ResponseWriter) *sseWriter {
	return &sseWriter{w: w, rc: http.NewResponseController(w)}
}

func (s *sseWriter) write(b []byte) error {
	s.rc.SetWriteDeadline(time.Now().Add(2 * time.Minute))
	if _, err := s.w.Write(b); err != nil {
		return err
	}
	return s.rc.Flush()
}

// models lists the models KyGate can serve, in the caller's format.
func (g *Gateway) models(w http.ResponseWriter, r *http.Request) {
	family := ingress.OpenAI
	if r.Header.Get("Anthropic-Version") != "" || (r.Header.Get("X-Api-Key") != "" && r.Header.Get("Authorization") == "") {
		family = ingress.Anthropic
	}
	if _, ok := g.Keys.Resolve(identity.FromRequest(r)); !ok {
		writeError(w, family, 401, "invalid_api_key", "KyGate did not recognize this API key. Use a KyGate virtual key (kg-...).")
		return
	}
	type m struct{ id, owner string }
	var list []m
	seen := map[string]bool{}
	addFamily := func(fam, owner string) {
		for _, x := range g.Catalog.Models(fam) {
			if !seen[x.ID] {
				seen[x.ID] = true
				list = append(list, m{x.ID, owner})
			}
		}
	}
	if family == ingress.Anthropic {
		if len(g.Registry.ByProvider(provider.Anthropic)) > 0 {
			addFamily("anthropic", "anthropic")
		}
	} else {
		if len(g.Registry.ByProvider(provider.OpenAI)) > 0 {
			addFamily("openai", "openai")
		}
		for _, c := range g.Registry.ByProvider(provider.Local) {
			for _, id := range c.Models() {
				if !seen[id] {
					seen[id] = true
					list = append(list, m{id, c.Name})
				}
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if family == ingress.Anthropic {
		data := make([]any, 0, len(list))
		for _, x := range list {
			data = append(data, map[string]any{"type": "model", "id": x.id, "display_name": x.id, "created_at": "1970-01-01T00:00:00Z"})
		}
		out := map[string]any{"data": data, "has_more": false, "first_id": nil, "last_id": nil}
		if len(list) > 0 {
			out["first_id"], out["last_id"] = list[0].id, list[len(list)-1].id
		}
		w.Write(ingress.Marshal(out))
		return
	}
	data := make([]any, 0, len(list))
	for _, x := range list {
		data = append(data, map[string]any{"id": x.id, "object": "model", "created": 0, "owned_by": x.owner})
	}
	w.Write(ingress.Marshal(map[string]any{"object": "list", "data": data}))
}

// Shutdown is a no-op hook kept for symmetry with later roles.
func (g *Gateway) Shutdown(context.Context) {}
