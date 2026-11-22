package pipeline_test

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"

	"github.com/Kytherion/KyGate/internal/detect/guard"
	"github.com/Kytherion/KyGate/internal/detect/guard/guardpb"
	"github.com/Kytherion/KyGate/internal/policy"
)

// fakeGuard stands in for the Python Guard: it finds the names it knows, by
// UTF-8 byte offsets, and records what it was asked.
type fakeGuard struct {
	guardpb.UnimplementedGuardServer
	mu      sync.Mutex
	names   []string
	asked   []string // segment texts sent to Inspect
	badSpan bool     // answer with offsets that do not fit
	level   string   // the level it reports for PERSON: "model" (default) or "list"
	// injections are phrases that score as a prompt injection; nil: the Guard
	// has no injection detector.
	injections map[string]float32
	threatAsks int  // Inspect calls that asked for threats
	noScores   bool // answer without the threat scores asked for
}

func (f *fakeGuard) Inspect(_ context.Context, req *guardpb.InspectRequest) (*guardpb.InspectResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	resp := &guardpb.InspectResponse{}
	if len(req.ThreatTypes) > 0 {
		f.threatAsks++
	}
	for _, s := range req.Segments {
		f.asked = append(f.asked, s.Text)
		if s.Untrusted && len(req.ThreatTypes) > 0 && f.injections != nil && !f.noScores {
			var best float32
			for phrase, score := range f.injections {
				if strings.Contains(strings.ToLower(s.Text), phrase) && score > best {
					best = score
				}
			}
			resp.Threats = append(resp.Threats, &guardpb.Threat{SegmentId: s.Id, Type: "PROMPT_INJECTION", Score: best, Detector: "fake-injection/1"})
		}
		if len(req.EntityTypes) == 0 && len(req.ThreatTypes) > 0 {
			continue
		}
		if f.badSpan {
			resp.Findings = append(resp.Findings, &guardpb.Finding{SegmentId: s.Id, EntityType: "PERSON", Start: 0, End: uint32(len(s.Text) + 5)})
			continue
		}
		for _, n := range f.names {
			from := 0
			for {
				i := strings.Index(s.Text[from:], n)
				if i < 0 {
					break
				}
				start := from + i
				resp.Findings = append(resp.Findings, &guardpb.Finding{SegmentId: s.Id, EntityType: "PERSON", Start: uint32(start), End: uint32(start + len(n)), Score: 0.97, Detector: "fake/1", Language: "fr"})
				from = start + len(n)
			}
		}
	}
	return resp, nil
}

func (f *fakeGuard) Info(context.Context, *guardpb.InfoRequest) (*guardpb.InfoResponse, error) {
	level := f.level
	if level == "" {
		level = "model"
	}
	info := &guardpb.InfoResponse{Version: "fake-1", Ready: true, EntityTypes: []string{"PERSON"}, Languages: []string{"en", "fr"},
		Coverage: []*guardpb.Coverage{{EntityType: "PERSON", Level: level, Detectors: []string{"fake/" + level}}}}
	if f.injections != nil {
		info.ThreatTypes = []string{"PROMPT_INJECTION"}
		info.Coverage = append(info.Coverage, &guardpb.Coverage{EntityType: "PROMPT_INJECTION", Level: "model", Detectors: []string{"fake-injection/1"}})
	}
	return info, nil
}

func (f *fakeGuard) askedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked)
}

// startGuard runs the fake Guard and connects the gateway to it.
func (h *harness) startGuard(f *fakeGuard) {
	h.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		h.t.Fatal(err)
	}
	srv := grpc.NewServer()
	guardpb.RegisterGuardServer(srv, f)
	go srv.Serve(ln)
	h.t.Cleanup(srv.Stop)
	h.connectGuard(ln.Addr().String())
}

func (h *harness) connectGuard(addr string) {
	h.t.Helper()
	c, err := guard.Dial(addr)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { c.Close() })
	c.Info(context.Background())
	h.g.Guard, h.g.Memo = c, guard.NewMemo([]byte("test-memo-key-32-bytes-long-0000"), 1000)
}

// guardPolicy is the starter policy with PERSON masked, and the given
// on_guard_unavailable.
func guardPolicy(onUnavailable string) string {
	p := strings.Replace(string(policy.Starter()), "    EMAIL:       { action: allow }   # counted in the console, sent unchanged",
		"    EMAIL:       { action: mask }\n    PERSON:      { action: mask }", 1)
	if onUnavailable != "" {
		p = strings.Replace(p, "data:\n", "data:\n  on_guard_unavailable: "+onUnavailable+"\n", 1)
	}
	return p
}

// The Guard's findings are masked like any other: the model sees a
// placeholder, the caller gets the real name back. Offsets are bytes, so
// accented names are cut where they should be.
func TestGuardFindingsAreMasked(t *testing.T) {
	h := newHarness(t, guardPolicy(""))
	f := &fakeGuard{names: []string{"Hélène Dubois", "Alice"}}
	h.startGuard(f)
	resp, body := h.post("/v1/messages", h.keyA, messages("Écris à Hélène Dubois et à Alice.", false))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if got := lastUserText(h.up.lastBody()); got != "Écris à [PERSON_1] et à [PERSON_2]." {
		t.Fatalf("the model saw %q", got)
	}
	if !strings.Contains(body, "You said: Écris à Hélène Dubois et à Alice.") {
		t.Fatalf("not rehydrated: %s", body)
	}
	e := h.event(resp.Header.Get("X-KyGate-Request-Id"))
	if e.Guard != "ok" || len(e.Findings) != 1 || e.Findings[0].Type != "PERSON" || e.Findings[0].Count != 2 || !e.Findings[0].Applied {
		t.Fatalf("event %+v", e)
	}
}

// The memo: each turn asks the Guard only about content it has not seen, and
// the earlier turn keeps the masking it was first sent with (invariant 4).
func TestGuardMemoAsksOnlyNewContent(t *testing.T) {
	h := newHarness(t, guardPolicy(""))
	f := &fakeGuard{names: []string{"Alice"}}
	h.startGuard(f)
	turn1 := []any{map[string]any{"role": "user", "content": "Write to Alice."}}
	h.post("/v1/messages", h.keyA, map[string]any{"model": "claude-opus-5-5", "max_tokens": 10, "messages": turn1})
	first := lastUserText(h.up.lastBody())
	asked := f.askedCount()
	turn2 := append(append([]any{}, turn1...),
		map[string]any{"role": "assistant", "content": "Done, I wrote to Alice."},
		map[string]any{"role": "user", "content": "Now write to Alice again."})
	h.post("/v1/messages", h.keyA, map[string]any{"model": "claude-opus-5-5", "max_tokens": 10, "messages": turn2})
	if n := f.askedCount() - asked; n != 2 {
		t.Fatalf("the second turn must ask about its 2 new segments only, asked %d", n)
	}
	msgs := h.up.lastBody()["messages"].([]any)
	if msgs[0].(map[string]any)["content"] != first || first != "Write to [PERSON_1]." {
		t.Fatalf("turn 1 changed: %v then %v", first, msgs[0])
	}
	if st := h.g.Memo.Stats(); st.Hits != 1 {
		t.Fatalf("memo %+v", st)
	}
}

// Security fails closed (invariant 2).
func TestGuardUnavailable(t *testing.T) {
	down := func(h *harness) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := ln.Addr().String()
		ln.Close()
		h.connectGuard(addr)
	}
	t.Run("block, the default", func(t *testing.T) {
		h := newHarness(t, guardPolicy(""))
		down(h)
		calls := h.up.calls
		resp, body := h.post("/v1/messages", h.keyA, messages("Write to Alice.", false))
		if resp.StatusCode != 503 || !strings.Contains(body, "Guard is unavailable") || h.up.calls != calls {
			t.Fatalf("must refuse without calling the model: %d %s", resp.StatusCode, body)
		}
		if e := h.event(resp.Header.Get("X-KyGate-Request-Id")); e.Outcome != "refused" || e.Guard != "unavailable" {
			t.Fatalf("event %+v", e)
		}
	})
	t.Run("no Guard configured", func(t *testing.T) {
		h := newHarness(t, guardPolicy(""))
		resp, body := h.post("/v1/messages", h.keyA, messages("Write to Alice.", false))
		if resp.StatusCode != 503 || !strings.Contains(body, "no Guard is configured") {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
	})
	t.Run("fast_detectors_only", func(t *testing.T) {
		h := newHarness(t, guardPolicy("fast_detectors_only"))
		down(h)
		resp, _ := h.post("/v1/chat/completions", h.keyA, chat("Charge card "+cardA+" for Alice", false))
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if got := lastUserText(h.up.lastBody()); got != "Charge card [CREDIT_CARD_1] for Alice" {
			t.Fatalf("the fast detectors still mask: %q", got)
		}
		if e := h.event(resp.Header.Get("X-KyGate-Request-Id")); !e.Alert || e.Guard != "unavailable" {
			t.Fatalf("a request served without the Guard is flagged: %+v", e)
		}
	})
	t.Run("local_only refuses an external model", func(t *testing.T) {
		h := newHarness(t, guardPolicy("local_only"))
		down(h)
		resp, body := h.post("/v1/messages", h.keyA, messages("Write to Alice.", false))
		if resp.StatusCode != 503 || !strings.Contains(body, "local models") {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
	})
	t.Run("a policy without ML types needs no Guard", func(t *testing.T) {
		h := newHarness(t, "")
		down(h)
		if resp, _ := h.post("/v1/messages", h.keyA, messages("Write to Alice.", false)); resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
}

// An answer that does not fit the request is a Guard failure, never applied.
func TestGuardBadOffsetsFailClosed(t *testing.T) {
	h := newHarness(t, guardPolicy(""))
	h.startGuard(&fakeGuard{badSpan: true})
	resp, body := h.post("/v1/messages", h.keyA, messages("Write to Alice.", false))
	if resp.StatusCode != 503 || !strings.Contains(body, "does not fit") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

// Two detectors that disagree on a value's edges: the merged span covers both,
// so nothing of either value reaches the model.
func TestOverlappingFindingsLeaveNothingUnmasked(t *testing.T) {
	h := newHarness(t, guardPolicy(""))
	h.startGuard(&fakeGuard{names: []string{"Alice Martin alice"}}) // overlaps the email's start
	h.post("/v1/messages", h.keyA, messages("Mail Alice Martin alice.martin@example.com now", false))
	got := lastUserText(h.up.lastBody())
	if strings.Contains(got, "alice") || strings.Contains(got, "example.com") || strings.Contains(got, "Martin") {
		t.Fatalf("part of a value reached the model: %q", got)
	}
}

// A data type the policy sends to the Guard and that no detector there finds
// follows on_guard_unavailable: it is never sent on unchecked. Here the Guard
// finds PERSON only, and the policy also blocks PHONE_NUMBER.
func TestGuardTypeWithoutDetectorFailsClosed(t *testing.T) {
	pol := strings.Replace(guardPolicy(""), "    PERSON:      { action: mask }", "    PERSON:      { action: mask }\n    PHONE_NUMBER: { action: block }", 1)
	h := newHarness(t, pol)
	f := &fakeGuard{names: []string{"Alice"}}
	h.startGuard(f)
	calls := h.up.calls
	resp, body := h.post("/v1/messages", h.keyA, messages("Call Alice at +1 415 555 0100", false))
	if resp.StatusCode != 503 || !strings.Contains(body, "no detector for PHONE_NUMBER") || h.up.calls != calls || f.askedCount() != 0 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if e := h.event(resp.Header.Get("X-KyGate-Request-Id")); e.Guard != "unavailable" || e.Outcome != "refused" {
		t.Fatalf("event %+v", e)
	}
}

// Two positions whose keys join to the same path ({"a":{"b":..}} and
// {"a.b":..}): the Guard's findings land on the text they were found in.
func TestGuardFindingsLandOnTheirOwnSegment(t *testing.T) {
	h := newHarness(t, guardPolicy(""))
	h.startGuard(&fakeGuard{names: []string{"Alice"}})
	body := map[string]any{"model": "claude-opus-5-5", "max_tokens": 10, "messages": []any{
		map[string]any{"role": "user", "content": "look it up"},
		map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "t1", "name": "find",
			"input": map[string]any{"a": map[string]any{"b": "Alice"}, "a.b": "Hello there friend"}}}},
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": "done"}}},
	}}
	if resp, out := h.post("/v1/messages", h.keyA, body); resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, out)
	}
	input := h.up.lastBody()["messages"].([]any)[1].(map[string]any)["content"].([]any)[0].(map[string]any)["input"].(map[string]any)
	if input["a"].(map[string]any)["b"] != "[PERSON_1]" || input["a.b"] != "Hello there friend" {
		t.Fatalf("the model saw %v", input)
	}
}

// An answer without the threat score asked for is not a clean segment: it is
// a Guard that did not do the work (fail closed).
func TestGuardMissingThreatScoreFailsClosed(t *testing.T) {
	h := newHarness(t, threatPolicy("{ action: block }"))
	h.startGuard(&fakeGuard{injections: attacks, noScores: true})
	calls := h.up.calls
	resp, body := h.post("/v1/messages", h.keyA, messages("Hello there", false))
	if resp.StatusCode != 503 || !strings.Contains(body, "no PROMPT_INJECTION score") || h.up.calls != calls {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

// detection: model — a list never stands in for a model.
func TestDetectionModelRequiresAModel(t *testing.T) {
	pol := strings.Replace(guardPolicy(""), "    PERSON:      { action: mask }", "    PERSON:      { action: mask, detection: model }", 1)
	t.Run("a Guard with only a list is refused", func(t *testing.T) {
		h := newHarness(t, pol)
		f := &fakeGuard{names: []string{"Alice"}, level: "list"}
		h.startGuard(f)
		calls := h.up.calls
		resp, body := h.post("/v1/messages", h.keyA, messages("Write to Alice.", false))
		if resp.StatusCode != 503 || !strings.Contains(body, "no model for PERSON") || h.up.calls != calls || f.askedCount() != 0 {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
	})
	t.Run("a Guard with a model is used", func(t *testing.T) {
		h := newHarness(t, pol)
		h.startGuard(&fakeGuard{names: []string{"Alice"}, level: "model"})
		resp, body := h.post("/v1/messages", h.keyA, messages("Write to Alice.", false))
		if resp.StatusCode != 200 || lastUserText(h.up.lastBody()) != "Write to [PERSON_1]." {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
	})
	t.Run("a Guard that has not reported its models fails closed", func(t *testing.T) {
		h := newHarness(t, pol)
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := ln.Addr().String()
		ln.Close()
		h.connectGuard(addr)
		if resp, body := h.post("/v1/messages", h.keyA, messages("Write to Alice.", false)); resp.StatusCode != 503 {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
	})
}
