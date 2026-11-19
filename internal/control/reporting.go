package control

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Kytherion/KyGate/internal/cache"
	"github.com/Kytherion/KyGate/internal/detect/guard"
	"github.com/Kytherion/KyGate/internal/edition"
	"github.com/Kytherion/KyGate/internal/events"
	"github.com/Kytherion/KyGate/internal/identity"
	"github.com/Kytherion/KyGate/internal/limits"
	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/provider"
	"github.com/Kytherion/KyGate/internal/store"
	"github.com/Kytherion/KyGate/internal/telemetry"
)

// Console serves the console and the read-only reporting API on their own
// port, apart from the model API (architecture §4.9). The reporting API is the
// read-only part of the admin API.
type Console struct {
	Config    store.ConfigStore
	Events    store.EventStore
	Registry  *provider.Registry
	Policies  *policy.Holder
	Keys      *identity.Resolver
	Cache     *cache.Exact
	Semantic  *cache.Semantic
	Guard     *guard.Client // nil: no Guard configured
	Memo      *guard.Memo
	Spool     *events.Spool
	Metrics   *telemetry.Registry
	MasterKey []byte
	OrgID     string
	Version   string
	Started   time.Time
	Budgets   *limits.Budgets // the gateway's budget counters; nil: none
	Logf      func(format string, a ...any)
	SSO       *SSO // single sign-on (AC-3); nil: the admin token only
	// Purger runs cache and event purges (GV-4); nil disables them.
	Purger *Purger
	// Audit is the audit ledger and SIEM export (GV-3); nil outside the
	// control process.
	Audit    *Audit
	Static   fs.FS
	ModelAPI string
	// SCIM keeps provisioned users and groups (GV-2); nil turns /scim/v2 off.
	SCIM   store.SCIMStore
	scimMu sync.Mutex // one SCIM change at a time
}

// Handler returns the console handler.
func (c *Console) Handler() http.Handler {
	mux := http.NewServeMux()
	api := http.NewServeMux()
	api.HandleFunc("GET /api/v1/info", c.info)
	api.HandleFunc("GET /api/v1/summary", c.summary)
	api.HandleFunc("GET /api/v1/timeseries", c.timeseries)
	api.HandleFunc("GET /api/v1/breakdown", c.breakdown)
	api.HandleFunc("GET /api/v1/findings", c.findings)
	api.HandleFunc("GET /api/v1/security", c.security)
	api.HandleFunc("GET /api/v1/nearmiss", c.nearMiss)
	api.HandleFunc("GET /api/v1/routing", c.routing)
	api.HandleFunc("GET /api/v1/budgets", c.budgets)
	api.HandleFunc("GET /api/v1/requests", c.requests)
	api.HandleFunc("GET /api/v1/requests/{id}", c.request)
	api.HandleFunc("GET /api/v1/connections", c.connections)
	api.HandleFunc("GET /api/v1/keys", c.keys)
	api.HandleFunc("GET /api/v1/fleet", c.fleet)
	api.HandleFunc("GET /api/v1/quality", c.quality)
	c.adminRoutes(api)
	api.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			apiError(w, 405, "the reporting API is read-only; changes go through /api/v1/admin/ or the command line")
			return
		}
		apiError(w, 404, "not found")
	})
	mux.Handle("/api/", c.auth(api))
	// For probes: the console process answers. No data, no sign-in.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /auth/config", c.authConfig)
	mux.HandleFunc("GET /auth/me", c.me)
	mux.HandleFunc("POST /auth/token", c.tokenLogin)
	mux.HandleFunc("POST /auth/logout", c.logout)
	mux.HandleFunc("GET /auth/login", c.ssoLogin)
	mux.HandleFunc("GET /auth/callback", c.ssoCallback)
	// SCIM provisioning (GV-2): its own token, not a session or the admin token.
	mux.Handle("/scim/v2/", c.scimHandler())
	if c.Metrics != nil {
		mux.Handle("GET /metrics", c.Metrics.Handler())
	}
	mux.Handle("/", http.FileServerFS(c.Static))
	return secure(mux)
}

// secure adds headers that keep the console from being framed or from loading
// anything from elsewhere.
func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Frame-Options", "DENY")
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/scim/") {
			hd.Set("Cache-Control", "no-store")
		}
		h.ServeHTTP(w, r)
	})
}

func apiError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// rangeOf reads ?range=24h|7d|30d|90d, or ?from= and ?to= in RFC 3339.
func rangeOf(r *http.Request) store.Range {
	rg := rangeOfQuery(r)
	if p := PrincipalOf(r); p.Role == RoleTeamLead {
		rg.Team = p.TeamName // a team lead sees their team only
	}
	return rg
}

func rangeOfQuery(r *http.Request) store.Range {
	now := time.Now()
	q := r.URL.Query()
	if f, err := time.Parse(time.RFC3339, q.Get("from")); err == nil {
		to := now
		if t, err := time.Parse(time.RFC3339, q.Get("to")); err == nil {
			to = t
		}
		return store.Range{From: f, To: to}
	}
	d := 7 * 24 * time.Hour
	switch q.Get("range") {
	case "1h":
		d = time.Hour
	case "24h":
		d = 24 * time.Hour
	case "30d":
		d = 30 * 24 * time.Hour
	case "90d":
		d = 90 * 24 * time.Hour
	}
	return store.Range{From: now.Add(-d), To: now.Add(time.Minute)}
}

func (c *Console) info(w http.ResponseWriter, r *http.Request) {
	p := c.Policies.Current()
	writeJSON(w, map[string]any{
		"version":   c.Version,
		"edition":   edition.Name,
		"profile":   "solo",
		"org_id":    c.OrgID,
		"started":   c.Started,
		"model_api": c.ModelAPI,
		"policy": map[string]any{
			"path": p.Path, "version": p.Version, "mode": p.Mode, "warnings": p.Warnings,
			"entities": p.Data.Entities, "threats": p.Threats, "routing": p.Route, "output": p.Output, "output_on": p.OutputOn(), "unreadable_content": p.Data.UnreadableContent, "embeddings": p.Data.Embeddings,
			"cache_enabled": p.CacheEnabled(), "cache_scope": p.Cache.Exact.Scope, "cache_ttl": time.Duration(p.Cache.Exact.TTL).String(),
			"cache_persist": p.CachePersist(), "cache_max_disk_mb": p.Cache.Exact.MaxDiskMB,
			"cache_repeat_window": p.RepeatWindow().String(),
			"capture_payloads":    p.Audit.CapturePayloads, "retention_days": p.Audit.RetentionDays,
			"semantic": map[string]any{
				"enabled": p.SemanticEnabled(), "mode": p.Cache.Semantic.Mode, "scope": p.Cache.Semantic.Scope,
				"ttl": time.Duration(p.Cache.Semantic.TTL).String(), "min_similarity": p.Cache.Semantic.MinSimilarity,
				"max_prompt_tokens": p.Cache.Semantic.MaxPromptTokens,
				"connection":        p.Cache.Semantic.Embeddings.Connection, "model": p.Cache.Semantic.Embeddings.Model,
				"connected": p.Cache.Semantic.Embeddings.Connection != "" && c.Registry.ByName(p.Cache.Semantic.Embeddings.Connection) != nil,
			},
		},
		"cache":       c.Cache.Stats(),
		"semantic":    c.semanticStats(r),
		"guard":       c.guardState(),
		"spool_bytes": c.Spool.Bytes(),
		"keys":        c.Keys.Count(),
		"connections": len(c.Registry.All()),
	})
}

// guardState is the Guard's state for the console: its address, readiness,
// models, and latency, or null when no Guard is configured.
func (c *Console) guardState() any {
	p := c.Policies.Current()
	out := map[string]any{"configured": c.Guard != nil, "needed_for": append(p.GuardEntities(), p.GuardThreats()...), "on_unavailable": p.Data.OnGuardUnavailable}
	if c.Guard != nil {
		out["state"] = c.Guard.State()
	}
	if c.Memo != nil {
		out["memo"] = c.Memo.Stats()
	}
	return out
}

func (c *Console) semanticStats(r *http.Request) any {
	if c.Semantic == nil {
		return nil
	}
	return c.Semantic.Stats(r.Context())
}

func (c *Console) summary(w http.ResponseWriter, r *http.Request) {
	rg := rangeOf(r)
	t, err := c.Events.Totals(r.Context(), rg)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	span := rg.To.Sub(rg.From)
	prev, _ := c.Events.Totals(r.Context(), store.Range{From: rg.From.Add(-span), To: rg.From})
	writeJSON(w, map[string]any{"from": rg.From, "to": rg.To, "totals": t, "previous": prev})
}

func (c *Console) timeseries(w http.ResponseWriter, r *http.Request) {
	rg := rangeOf(r)
	by := "day"
	if rg.To.Sub(rg.From) <= 49*time.Hour {
		by = "hour"
	}
	g, err := c.Events.GroupBy(r.Context(), rg, by)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"bucket": by, "from": rg.From, "to": rg.To, "series": nonNil(g)})
}

func (c *Console) breakdown(w http.ResponseWriter, r *http.Request) {
	by := r.URL.Query().Get("by")
	g, err := c.Events.GroupBy(r.Context(), rangeOf(r), by)
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"by": by, "rows": nonNil(g)})
}

func (c *Console) findings(w http.ResponseWriter, r *http.Request) {
	f, err := c.Events.Findings(r.Context(), rangeOf(r))
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	if f == nil {
		f = []store.FindingRow{}
	}
	writeJSON(w, map[string]any{"rows": f, "mode": c.Policies.Current().Mode})
}

// budgets reports each budget against its limits (OP-5): the organization's,
// and each active key's, this month and today (UTC), from the gateway's
// counters, reservations in flight included.
func (c *Console) budgets(w http.ResponseWriter, r *http.Request) {
	p := c.Policies.Current()
	type row struct {
		Scope   string           `json:"scope"` // org | key
		Name    string           `json:"name"`
		Monthly float64          `json:"monthly_usd"`
		Daily   float64          `json:"daily_usd"`
		Limits  policy.BudgetSet `json:"limits"`
		State   string           `json:"state"` // ok | soft | hard
	}
	state := func(s policy.BudgetSet, m, d float64) string {
		switch {
		case (s.Monthly.Hard > 0 && m >= s.Monthly.Hard) || (s.Daily.Hard > 0 && d >= s.Daily.Hard):
			return "hard"
		case (s.Monthly.Soft > 0 && m >= s.Monthly.Soft) || (s.Daily.Soft > 0 && d >= s.Daily.Soft):
			return "soft"
		}
		return "ok"
	}
	rows := []row{}
	now := time.Now()
	if c.Budgets != nil {
		m, d := c.Budgets.Spent(r.Context(), "org", now)
		rows = append(rows, row{"org", "organization", m, d, p.Budget.Org, state(p.Budget.Org, m, d)})
		// Teams and projects: their own budgets, from their policy files.
		ts, _ := c.Config.ListTeams(r.Context())
		teamName := map[string]string{}
		for _, t := range ts {
			teamName[t.ID] = t.Name
			s := c.Policies.For(t.Name, "", "").Budget.Team
			m, d := c.Budgets.Spent(r.Context(), "team:"+t.ID, now)
			rows = append(rows, row{"team", t.Name, m, d, s, state(s, m, d)})
		}
		ps, _ := c.Config.ListProjects(r.Context())
		projOf := map[string]store.Project{}
		for _, pr := range ps {
			projOf[pr.ID] = pr
		}
		for _, pr := range ps {
			s := c.Policies.For(teamName[pr.TeamID], pr.Name, "").Budget.Project
			m, d := c.Budgets.Spent(r.Context(), "project:"+pr.ID, now)
			rows = append(rows, row{"project", pr.Name, m, d, s, state(s, m, d)})
		}
		ks, err := c.Config.ListKeys(r.Context())
		if err != nil {
			apiError(w, 500, err.Error())
			return
		}
		for _, k := range ks {
			if k.RevokedAt != nil {
				continue
			}
			pr := projOf[k.ProjectID]
			s := c.Policies.For(teamName[pr.TeamID], pr.Name, k.Name).Budget.ForKey(k.Name)
			m, d := c.Budgets.Spent(r.Context(), "key:"+k.ID, now)
			rows = append(rows, row{"key", k.Name, m, d, s, state(s, m, d)})
		}
	}
	if pr := PrincipalOf(r); !pr.ReadsAll() {
		mine := map[string]bool{"team:" + pr.TeamName: true}
		ps, _ := c.Config.ListProjects(r.Context())
		for _, x := range ps {
			if x.TeamID == pr.TeamID {
				mine["project:"+x.Name] = true
			}
		}
		ks, _ := c.Config.ListKeys(r.Context())
		for _, k := range c.keysOfTeam(r, ks, pr.TeamID) {
			mine["key:"+k.Name] = true
		}
		var keep []row
		for _, x := range rows {
			if mine[x.Scope+":"+x.Name] {
				keep = append(keep, x)
			}
		}
		rows = append([]row{}, keep...)
	}
	writeJSON(w, map[string]any{"rows": rows, "on": p.Budget.On(), "at_soft": p.Budget.AtSoft, "rate_limits": p.RateLimits})
}

// routing is the routing report (OP-4): the router's shadow decisions, with
// the money they would have saved.
func (c *Console) routing(w http.ResponseWriter, r *http.Request) {
	rows, err := c.Events.Routing(r.Context(), rangeOf(r))
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	if rows == nil {
		rows = []store.RouteRow{}
	}
	writeJSON(w, map[string]any{"rows": rows, "mode": c.Policies.Current().Route.Mode})
}

// quality is the quality report (OB-4): callers' ratings of answers, by how
// each was served (exact or semantic cache, or the model), the model, and
// whether the router would have sent it elsewhere; and the semantic cache's
// shadow comparisons, its measured false-hit signal.
func (c *Console) quality(w http.ResponseWriter, r *http.Request) {
	rg := rangeOf(r)
	rows := []store.QualityRow{}
	if qs, ok := c.Events.(store.QualityStore); ok {
		got, err := qs.Quality(r.Context(), rg)
		if err != nil {
			apiError(w, 500, err.Error())
			return
		}
		if got != nil {
			rows = got
		}
	}
	t, err := c.Events.Totals(r.Context(), rg)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"rows": rows, "semantic": map[string]int64{
		"hits": t.SemanticHits, "would_hit": t.SemanticWouldHit, "agree": t.SemanticAgree, "disagree": t.SemanticDisagree,
	}, "cache_hits": t.CacheHits, "requests": t.Requests})
}

// nearMiss is the near-miss report of the exact cache: which
// fields, changed between two askings of the same question, made it miss.
func (c *Console) nearMiss(w http.ResponseWriter, r *http.Request) {
	rows, err := c.Events.NearMisses(r.Context(), rangeOf(r))
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	if rows == nil {
		rows = []store.NearMissRow{}
	}
	writeJSON(w, map[string]any{"rows": rows})
}

// security is the security report (OB-3): who the findings, threats, blocks,
// and changed answers come from, and when. Metadata only: counts per virtual
// key name and per time bucket, never a value or a text.
func (c *Console) security(w http.ResponseWriter, r *http.Request) {
	rg := rangeOf(r)
	bucket := "day"
	if rg.To.Sub(rg.From) <= 49*time.Hour {
		bucket = "hour"
	}
	sources, err := c.Events.Security(r.Context(), rg, "key")
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	series, err := c.Events.Security(r.Context(), rg, bucket)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	if sources == nil {
		sources = []store.SecurityRow{}
	}
	if series == nil {
		series = []store.SecurityRow{}
	}
	writeJSON(w, map[string]any{"bucket": bucket, "sources": sources, "series": series})
}

func (c *Console) requests(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EventFilter{Range: rangeOf(r), Outcome: q.Get("outcome"), Cache: q.Get("cache"), KeyID: q.Get("key"), User: q.Get("user"), Model: q.Get("model")}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	if b, err := time.Parse(time.RFC3339Nano, q.Get("before")); err == nil {
		f.Before = b
	}
	evs, err := c.Events.ListEvents(r.Context(), f)
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	if evs == nil {
		evs = []store.Event{}
	}
	writeJSON(w, map[string]any{"rows": evs})
}

func (c *Console) request(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	e, err := c.Events.GetEvent(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, 404, "no such request")
		return
	}
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	if p := PrincipalOf(r); !p.ReadsAll() && e.TeamName != p.TeamName {
		apiError(w, 404, "no such request")
		return
	}
	out := map[string]any{"event": e}
	if len(e.Payload) > 0 {
		// Captured payloads are masked: placeholders, never real values.
		plain, err := store.Open(store.DeriveKey(c.MasterKey, "payload", e.OrgID), e.Payload, []byte(e.OrgID+"/"+e.ID))
		if err == nil {
			out["payload"] = json.RawMessage(plain)
		}
	}
	e.Payload = nil
	writeJSON(w, out)
}

func (c *Console) connections(w http.ResponseWriter, r *http.Request) {
	var list []provider.State
	for _, conn := range c.Registry.All() {
		list = append(list, conn.Snapshot())
	}
	if list == nil {
		list = []provider.State{}
	}
	writeJSON(w, map[string]any{"rows": list})
}

func (c *Console) keys(w http.ResponseWriter, r *http.Request) {
	ks, err := c.Config.ListKeys(r.Context())
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	if p := PrincipalOf(r); !p.ReadsAll() {
		ks = c.keysOfTeam(r, ks, p.TeamID)
	}
	if ks == nil {
		ks = []store.VirtualKey{}
	}
	writeJSON(w, map[string]any{"rows": ks})
}

func nonNil(g []store.Group) []store.Group {
	if g == nil {
		return []store.Group{}
	}
	return g
}

// WatchConfig reloads keys and provider connections when the configuration
// version changes, for example after 'kygate key revoke' from another shell.
// A revoked key stops working within one interval.
func WatchConfig(ctx context.Context, cs store.ConfigStore, every time.Duration, reload func() error, logf func(string, ...any)) {
	last, _ := cs.ConfigVersion(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			v, err := cs.ConfigVersion(ctx)
			if err != nil || v == last {
				continue
			}
			if err := reload(); err != nil {
				logf("configuration reload failed: %v", err)
				continue
			}
			last = v
			logf("configuration reloaded (version %d)", v)
		}
	}
}
