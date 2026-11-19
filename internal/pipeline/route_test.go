package pipeline_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store"
)

// The starter policy runs the router in shadow mode: it records the cheaper
// model it would use and what that would save, and the request still goes to
// the model it names.
func TestRouterShadowRecordsAndChangesNothing(t *testing.T) {
	h := newHarness(t, "")
	resp, body := h.post("/v1/messages", h.keyA, messages("What is the capital of Austria?", false))
	if resp.StatusCode != 200 || resp.Header.Get("X-KyGate-Route") != "shadow; would use claude-sonnet-5-5 (standard tier)" {
		t.Fatalf("%d %q %s", resp.StatusCode, resp.Header.Get("X-KyGate-Route"), body)
	}
	if got := h.up.lastBody()["model"]; got != "claude-opus-5-5" {
		t.Fatalf("shadow mode must not change the model: the provider got %v", got)
	}
	e := h.event(resp.Header.Get("X-KyGate-Request-Id"))
	if e.RouteModel != "claude-sonnet-5-5" || e.RouteSavingUSD <= 0 || e.RouteSavingUSD >= e.CostUSD || e.ModelServed != "claude-opus-5-5" {
		t.Fatalf("event %+v", e)
	}

	// Code stays, with its reason.
	resp, _ = h.post("/v1/messages", h.keyA, messages("Fix this:\n```go\nfunc main() {}\n```", false))
	if e := h.event(resp.Header.Get("X-KyGate-Request-Id")); e.RouteModel != "" || e.RouteReason != "the request contains code" || resp.Header.Get("X-KyGate-Route") != "shadow; stays" {
		t.Fatalf("%+v", e)
	}

	// A cache hit calls no model, so the router does not run.
	resp, _ = h.post("/v1/messages", h.keyA, messages("What is the capital of Austria?", false))
	if resp.Header.Get("X-KyGate-Cache") != "hit" || resp.Header.Get("X-KyGate-Route") != "" {
		t.Fatalf("hit: %q %q", resp.Header.Get("X-KyGate-Cache"), resp.Header.Get("X-KyGate-Route"))
	}

	rows, err := h.db.Routing(context.Background(), store.Range{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)})
	if err != nil || len(rows) != 2 || rows[0].Would != "claude-sonnet-5-5" || rows[0].SavingUSD <= 0 || rows[1].Would != "" {
		t.Fatalf("%v %+v", err, rows)
	}
}

// The next turn of a conversation keeps the first turn's decision.
func TestRouterDecisionSticksToTheConversation(t *testing.T) {
	h := newHarness(t, "")
	first := messages("Name three rivers in France.", false)
	resp, _ := h.post("/v1/messages", h.keyA, first)
	if resp.Header.Get("X-KyGate-Route") == "shadow; stays" {
		t.Fatal("the first turn should move")
	}
	next := messages("", false)
	next["messages"] = []any{
		map[string]any{"role": "user", "content": "Name three rivers in France."},
		map[string]any{"role": "assistant", "content": "The Seine, the Loire, the Rhône."},
		map[string]any{"role": "user", "content": "Now write a long Go program that sorts them:\n```go\npackage main\n```"},
	}
	resp, _ = h.post("/v1/messages", h.keyA, next)
	if e := h.event(resp.Header.Get("X-KyGate-Request-Id")); e.RouteModel != "claude-sonnet-5-5" {
		t.Fatalf("decide once per conversation: %+v", e)
	}
}

// A policy without routing: has no router; mode auto is shadow until
// enforcement ships.
func TestRouterOffAndAuto(t *testing.T) {
	off := strings.Replace(string(policy.Starter()), "routing:\n  mode: shadow\n", "", 1)
	h := newHarness(t, off)
	resp, _ := h.post("/v1/messages", h.keyA, messages("What is the capital of Austria?", false))
	if resp.Header.Get("X-KyGate-Route") != "" || h.event(resp.Header.Get("X-KyGate-Request-Id")).RouteReason != "" {
		t.Fatal("no routing section, no router")
	}
	p, err := policy.Parse([]byte(strings.Replace(string(policy.Starter()), "mode: shadow\n", "mode: auto\n  tiers: [economy, standard, frontier]\n  prefer: cheap\n", 1)), "x.yaml")
	if err != nil || !p.RoutingShadow() || !strings.Contains(strings.Join(p.Warnings, "\n"), "routing.prefer") {
		t.Fatalf("%v %+v", err, p)
	}
	if _, err := policy.Parse([]byte(strings.Replace(string(policy.Starter()), "mode: shadow\n", "mode: sometimes\n", 1)), "x.yaml"); err == nil {
		t.Fatal("an unknown mode is an error")
	}
}
