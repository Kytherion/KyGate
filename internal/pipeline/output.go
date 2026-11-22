package pipeline

// Output inspection (PR-6), on the response path: every answer, streamed or
// not, fresh or from the cache, is inspected in its masked form before real
// values are put back (internal/detect/output.go has the checks).

import (
	"errors"
	"strconv"
	"strings"

	"github.com/Kytherion/KyGate/internal/detect"
	"github.com/Kytherion/KyGate/internal/ingress"
	"github.com/Kytherion/KyGate/internal/mask"
	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store"
)

// errOutputBlocked stops a stream whose answer output inspection blocks.
var errOutputBlocked = errors.New("output inspection blocked the answer")

// knownHosts lists the sites the request's own instructions name: the system
// prompt and the user's turns. Tool results do not count, since an injection
// could plant a site there. Call it before masking.
func knownHosts(req *ingress.Request) map[string]bool {
	known := map[string]bool{}
	for _, s := range req.Segments {
		if s.Role == ingress.RoleSystem || s.Role == ingress.RoleUser {
			detect.MentionedHosts(s.Text, known)
		}
	}
	return known
}

// outputInspector returns the answer inspector of one request, or nil when the
// policy checks nothing or the endpoint has no answer text.
func outputInspector(pol *policy.Policy, endpoint ingress.Endpoint, known map[string]bool, vm *mask.ValueMap) *detect.OutputInspector {
	if !pol.OutputOn() || (endpoint != ingress.Chat && endpoint != ingress.Messages) {
		return nil
	}
	o := pol.Output
	r := detect.OutputRules{
		Secrets: string(o.Secrets.Action), Images: string(o.Images.Action),
		ProtectedURLs: string(o.ProtectedURLs.Action), Links: string(o.Links.Action),
		Enforce: pol.Mode == policy.Enforce, Allowed: o.AllowedDomains, Known: known,
	}
	if vm != nil && vm.Len() > 0 {
		r.HasPlaceholder = vm.Holds
	}
	return detect.NewOutputInspector(r)
}

// inspectAnswer inspects a complete masked answer in place: its text, and the
// arguments of its tool calls. Reasoning blocks pass through untouched.
func inspectAnswer(family ingress.Family, body map[string]any, in *detect.OutputInspector) {
	if in == nil {
		return
	}
	args := func(s string) string { return in.Text(s, true) }
	if family == ingress.Anthropic {
		for _, b := range arr(body["content"]) {
			bm := obj(b)
			switch str(bm["type"]) {
			case "text":
				bm["text"] = in.Text(str(bm["text"]), false)
			case toolUse, serverToolUse, mcpToolUse:
				if v, ok := bm["input"]; ok {
					bm["input"] = mapStrings(v, args)
				}
			}
		}
		return
	}
	for _, c := range arr(body["choices"]) {
		msg := obj(obj(c)["message"])
		if msg == nil {
			continue
		}
		if s, ok := msg["content"].(string); ok {
			msg["content"] = in.Text(s, false)
		}
		for _, tc := range arr(msg["tool_calls"]) {
			if fn := obj(obj(tc)["function"]); fn != nil {
				if s, ok := fn["arguments"].(string); ok {
					fn["arguments"] = args(s)
				}
			}
			if cu := obj(obj(tc)["custom"]); cu != nil {
				if s, ok := cu["input"].(string); ok {
					cu["input"] = args(s)
				}
			}
		}
	}
}

// outputBlockMessage is the refusal text when output inspection blocks an answer.
func outputBlockMessage(in *detect.OutputInspector, id string) string {
	return "KyGate blocked the model's answer: it contained " + humanList(outputNames(in.Blocked)) +
		", which the policy blocks (output). (request " + id + ")"
}

func outputNames(types []string) []string {
	names := map[string]string{
		detect.OutputSecret: "a secret", detect.OutputImage: "an image from an unknown site",
		detect.OutputProtectedURL: "an address carrying protected data", detect.OutputLink: "a link to an unknown site",
	}
	out := make([]string, len(types))
	for i, t := range types {
		out[i] = names[t]
	}
	return out
}

// refuseBlockedAnswer answers 403 when output inspection blocked a complete
// answer. It reports whether it did.
func (sc *serveCtx) refuseBlockedAnswer() bool {
	if sc.out == nil || len(sc.out.Blocked) == 0 {
		return false
	}
	sc.w.Header().Set("X-KyGate-Blocked", strings.Join(sc.out.Blocked, ","))
	sc.fail(403, "blocked", "policy_blocked", outputBlockMessage(sc.out, sc.ev.ID))
	return true
}

// markRemoved names, on a non-streamed answer, the output types removed from it.
func (sc *serveCtx) markRemoved() {
	if sc.out == nil || !sc.out.Removed {
		return
	}
	var types []string
	for _, c := range sc.out.Counts() {
		if c.Action == "remove" && c.Applied {
			types = append(types, c.Type)
		}
	}
	sc.w.Header().Set("X-KyGate-Output", "removed="+strings.Join(types, ","))
}

// recordOutput adds output findings to the event and the metrics.
func (sc *serveCtx) recordOutput() {
	if sc.out == nil {
		return
	}
	for _, c := range sc.out.Counts() {
		sc.ev.Findings = append(sc.ev.Findings, store.FindingCount{Type: c.Type, Action: c.Action, Count: c.Count, Applied: c.Applied})
		sc.g.Metrics.Add("kygate_output_findings_total", float64(c.Count), "type", c.Type, "action", c.Action, "applied", strconv.FormatBool(c.Applied))
	}
	if sc.out.Alerted() {
		sc.ev.Alert = true
	}
}

// channel is one text channel of a streamed answer: output inspection on the
// masked text, then rehydration.
type channel struct {
	o *detect.OutputStream
	m *mask.Stream
}

func newChannel(in *detect.OutputInspector, vm *mask.ValueMap, args, jsonString bool) *channel {
	return &channel{o: in.NewStream(args), m: vm.NewStream(jsonString)}
}

func (c *channel) Push(t string) string { return c.m.Push(c.o.Push(t)) }

func (c *channel) Pending() bool { return c.o.Pending() || c.m.Pending() }

func (c *channel) Flush() string {
	out := ""
	if c.o.Pending() {
		out = c.m.Push(c.o.Flush())
	}
	return out + c.m.Flush()
}
