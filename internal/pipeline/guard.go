package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Kytherion/KyGate/internal/detect"
	"github.com/Kytherion/KyGate/internal/detect/guard"
	"github.com/Kytherion/KyGate/internal/detect/guard/guardpb"
	"github.com/Kytherion/KyGate/internal/ingress"
	"github.com/Kytherion/KyGate/internal/mask"
	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store"
)

// The Guard on the request path (stage 4, architecture §4.2, §4.4). The fast
// detectors run in the gateway; the segments a policy needs ML detection for
// go to the Guard, except those the findings memo already knows.

// errNoGuard means the policy needs the Guard and none is configured.
var errNoGuard = errors.New("no Guard is configured (start KyGate with --guard ADDR or KYGATE_GUARD)")

// guardResult is the outcome of the Guard for one request.
type guardResult struct {
	status string // "" (not needed) | ok | unavailable
	err    error
	asked  int // segments sent to the Guard
	memo   int // segments answered by the memo
}

// guardSegments are the segments the Guard inspects:
//   - for personal data, prose from every role. Tool results and JSON
//     (tool-call arguments) get the fast detectors only, because secrets are
//     the main risk there and name detection raises many false alarms
//     (architecture §4.4). Assistant turns are included: a client resends
//     earlier answers, with real values put back.
//   - for threats, the untrusted segments the policy names: user turns and
//     tool results, whatever their content. The system prompt is the
//     operator's own instructions and is never scanned for threats.
//
// A segment sent for threats alone is marked structured, so the Guard does
// not look for personal data in it; Untrusted is set only where threats are
// looked for.
func guardSegments(req *ingress.Request, pii bool, threatRoles map[string]bool) []guard.Segment {
	var out []guard.Segment
	for i, s := range req.Segments {
		if strings.TrimSpace(s.Text) == "" {
			continue
		}
		forPII := pii && !s.JSON && s.Role != ingress.RoleToolResult
		forThreat := s.Untrusted && ((s.Role == ingress.RoleUser && threatRoles["user"]) || (s.Role == ingress.RoleToolResult && threatRoles["tool_result"]))
		if !forPII && !forThreat {
			continue
		}
		role := guardpb.Role_ROLE_USER
		switch s.Role {
		case ingress.RoleSystem:
			role = guardpb.Role_ROLE_SYSTEM
		case ingress.RoleAssistant:
			role = guardpb.Role_ROLE_ASSISTANT
		case ingress.RoleInput:
			role = guardpb.Role_ROLE_INPUT
		case ingress.RoleToolResult:
			role = guardpb.Role_ROLE_TOOL_RESULT
		}
		kind := guardpb.ContentKind_CONTENT_KIND_PROSE
		if !forPII {
			kind = guardpb.ContentKind_CONTENT_KIND_STRUCTURED
		}
		out = append(out, guard.Segment{Index: i, ID: s.ID, Role: role, Kind: kind, Untrusted: forThreat, Text: s.Text})
	}
	return out
}

// guardInspect returns the Guard's findings and threats for the request, from
// the memo where it can.
func (g *Gateway) guardInspect(ctx context.Context, pol *policy.Policy, req *ingress.Request) ([]detect.Finding, []guard.Threat, guardResult) {
	if !pol.NeedsGuard() {
		return nil, nil, guardResult{}
	}
	if g.Guard == nil {
		return nil, nil, guardResult{status: "unavailable", err: errNoGuard}
	}
	types, threatTypes := pol.GuardEntities(), pol.GuardThreats()
	// A model the policy requires (detection: model), and a detector for each
	// threat it names, must be there: without one, the Guard counts as
	// unavailable for this request. Removing a pack never silently removes the
	// protection the policy asks for.
	if required := append(pol.ModelRequired(), threatTypes...); len(required) > 0 {
		levels, known := g.Guard.Levels()
		if !known {
			return nil, nil, guardResult{status: "unavailable", err: fmt.Errorf("the Guard has not reported its detectors yet, and the policy requires %s", strings.Join(required, ", "))}
		}
		var noModel, noDetector []string
		for _, t := range pol.ModelRequired() {
			if levels[t] != "model" {
				noModel = append(noModel, t)
			}
		}
		for _, t := range threatTypes {
			if levels[t] == "" {
				noDetector = append(noDetector, t)
			}
		}
		if len(noModel) > 0 {
			return nil, nil, guardResult{status: "unavailable", err: fmt.Errorf("the Guard has no model for %s (detection: model); install one with 'kygate-guard models pull'", strings.Join(noModel, ", "))}
		}
		if len(noDetector) > 0 {
			return nil, nil, guardResult{status: "unavailable", err: fmt.Errorf("the Guard has no detector for %s, which the policy names under threats; install one, such as 'kygate-guard models pull prompt-injection'", strings.Join(noDetector, ", "))}
		}
	}
	threatRoles := map[string]bool{}
	for _, t := range threatTypes {
		r, _ := pol.ThreatRuleFor(t)
		for _, sg := range r.Segments {
			threatRoles[sg] = true
		}
	}
	models := g.Guard.State().Version
	var found []detect.Finding
	var threats []guard.Threat
	var ask []guard.Segment
	keys := map[int]string{}
	res := guardResult{status: "ok"}
	for _, s := range guardSegments(req, len(types) > 0, threatRoles) {
		if g.Memo != nil {
			k := g.Memo.Key(pol.CacheVersion, models, types, threatTypes, s)
			if f, t, ok := g.Memo.Get(k, s.Index); ok {
				found = append(found, f...)
				threats = append(threats, t...)
				res.memo++
				continue
			}
			keys[s.Index] = k
		}
		ask = append(ask, s)
	}
	if len(ask) == 0 {
		return found, threats, res
	}
	res.asked = len(ask)
	f, th, err := g.Guard.Inspect(ctx, ask, types, threatTypes, pol.CacheVersion)
	if err != nil {
		return nil, nil, guardResult{status: "unavailable", err: err, asked: len(ask)}
	}
	// Keep only what the policy asked for, and memoize per segment.
	wanted := map[string]bool{}
	for _, t := range append(append([]string{}, types...), threatTypes...) {
		wanted[t] = true
	}
	bySeg := map[int][]detect.Finding{}
	for _, x := range f {
		if wanted[x.Type] {
			bySeg[x.Segment] = append(bySeg[x.Segment], x)
		}
	}
	thBySeg := map[int][]guard.Threat{}
	for _, x := range th {
		if wanted[x.Type] {
			thBySeg[x.Segment] = append(thBySeg[x.Segment], x)
		}
	}
	for _, s := range ask {
		if g.Memo != nil {
			g.Memo.Put(keys[s.Index], bySeg[s.Index], thBySeg[s.Index])
		}
		found = append(found, bySeg[s.Index]...)
		threats = append(threats, thBySeg[s.Index]...)
	}
	return found, threats, res
}

// threatDecision applies the policy's threat rules to the Guard's scores. A
// threat counts when its score reaches the rule's min_score in a kind of
// segment the rule names. Block refuses the request in enforce mode; alert
// lets it go and flags it. Either way a flagged request is never cached.
type threatDecision struct {
	counts  []store.FindingCount
	flagged bool
	block   []string // threat types that block the request
	best    float64
	where   string
}

func decideThreats(pol *policy.Policy, req *ingress.Request, threats []guard.Threat) threatDecision {
	var d threatDecision
	type key struct {
		typ    string
		action policy.Action
	}
	n := map[key]int{}
	for _, t := range threats {
		rule, ok := pol.ThreatRuleFor(t.Type)
		if !ok || rule.Action == policy.Allow || t.Score < rule.MinScore || t.Segment >= len(req.Segments) {
			continue
		}
		role := "user"
		if req.Segments[t.Segment].Role == ingress.RoleToolResult {
			role = "tool_result"
		}
		inScope := false
		for _, sg := range rule.Segments {
			inScope = inScope || sg == role
		}
		if !inScope {
			continue
		}
		d.flagged = true
		n[key{t.Type, rule.Action}]++
		if t.Score > d.best {
			d.best, d.where = t.Score, map[string]string{"user": "user turn", "tool_result": "tool result"}[role]
		}
		if rule.Action == policy.Block {
			d.block = appendUnique(d.block, t.Type)
		}
	}
	enforce := pol.Mode == policy.Enforce
	for k, c := range n {
		applied := k.action == policy.Alert || enforce
		d.counts = append(d.counts, store.FindingCount{Type: k.typ, Action: string(k.action), Count: c, Applied: applied})
	}
	sort.Slice(d.counts, func(i, j int) bool {
		return d.counts[i].Type+string(d.counts[i].Action) < d.counts[j].Type+string(d.counts[j].Action)
	})
	if !enforce {
		d.block = nil // monitor mode records what it would have done
	}
	return d
}

// guardRefusal applies data.on_guard_unavailable when the Guard did not
// answer. It returns the refusal message, or "" when the request may go on with
// the fast detectors' findings alone.
func guardRefusal(pol *policy.Policy, gr guardResult, local bool, model string) string {
	needs := strings.Join(append(pol.GuardEntities(), pol.GuardThreats()...), ", ")
	switch pol.Data.OnGuardUnavailable {
	case "fast_detectors_only":
		return ""
	case "local_only":
		if local {
			return ""
		}
		return fmt.Sprintf("KyGate refused this request: the policy needs the Guard to look for %s, the Guard is unavailable, and the policy then keeps requests on local models; model %q is external. (%v)", needs, model, gr.err)
	}
	return fmt.Sprintf("KyGate refused this request: the policy needs the Guard to look for %s, and the Guard is unavailable. (%v)", needs, gr.err)
}

// mergeSpans sorts a segment's spans and merges overlapping ones into one
// covering span, so that no part of a detected value is left unmasked when two
// detectors disagree on its edges. The merged span takes the type of the
// longer span; it is redacted if either was.
func mergeSpans(spans []mask.Span) []mask.Span {
	if len(spans) < 2 {
		return spans
	}
	sort.SliceStable(spans, func(i, j int) bool {
		if spans[i].Start != spans[j].Start {
			return spans[i].Start < spans[j].Start
		}
		return spans[i].End > spans[j].End
	})
	out := []mask.Span{spans[0]}
	for _, s := range spans[1:] {
		last := &out[len(out)-1]
		if s.Start >= last.End {
			out = append(out, s)
			continue
		}
		if s.End-s.Start > last.End-last.Start {
			last.Entity = s.Entity
		}
		if s.End > last.End {
			last.End = s.End
		}
		last.Redact = last.Redact || s.Redact
	}
	return out
}
