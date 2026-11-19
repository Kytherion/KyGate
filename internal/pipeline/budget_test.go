package pipeline_test

import (
	"strings"
	"testing"

	"github.com/Kytherion/KyGate/internal/policy"
)

// budgetPolicy is the starter policy with budgets and rate limits. An Opus
// request of the harness reserves about $0.02 (1,000 output tokens allowed)
// and costs about $0.001.
func budgetPolicy(section string) string {
	return strings.Replace(string(policy.Starter()), "\naudit:", "\n"+section+"\naudit:", 1)
}

// Past a hard limit the request is refused before any model call, and a cache
// hit still answers: it costs nothing.
func TestBudgetHardLimit(t *testing.T) {
	h := newHarness(t, budgetPolicy("budgets:\n  keys:\n    bob: { daily_usd: { hard: 0.01 } }\n"))
	resp, _ := h.post("/v1/messages", h.keyA, messages("What is the capital of Austria?", false))
	if resp.StatusCode != 200 {
		t.Fatalf("alice has no budget: %d", resp.StatusCode)
	}
	calls := h.up.calls
	resp, body := h.post("/v1/messages", h.keyB, messages("And of Hungary?", false))
	if resp.StatusCode != 429 || resp.Header.Get("X-KyGate-Budget") != "hard:key:daily" || resp.Header.Get("Retry-After") == "" || h.up.calls != calls || !strings.Contains(body, "this key's daily budget") {
		t.Fatalf("%d %q %s", resp.StatusCode, resp.Header.Get("X-KyGate-Budget"), body)
	}
	if e := h.event(resp.Header.Get("X-KyGate-Request-Id")); e.Outcome != "over_budget" || e.Budget != "hard:key:daily" {
		t.Fatalf("%+v", e)
	}
	// The same question alice asked: a hit, served to bob at no cost.
	if resp, _ := h.post("/v1/messages", h.keyB, messages("What is the capital of Austria?", false)); resp.StatusCode != 200 || resp.Header.Get("X-KyGate-Cache") != "hit" {
		t.Fatalf("a hit is served past the budget: %d %q", resp.StatusCode, resp.Header.Get("X-KyGate-Cache"))
	}
}

// Past a soft limit, a new conversation goes one tier down within the
// provider, and says so. The answer is not cached under the requested model.
func TestBudgetSoftLimitGoesOneTierDown(t *testing.T) {
	h := newHarness(t, budgetPolicy("budgets:\n  per_key: { monthly_usd: { soft: 0.01, hard: 10 } }\n"))
	resp, _ := h.post("/v1/messages", h.keyA, messages("Write a long essay with code examples:\n```go\nfunc main() {}\n```", false))
	if resp.StatusCode != 200 || h.up.lastBody()["model"] != "claude-sonnet-5-5" {
		t.Fatalf("past the soft limit, every new conversation goes one tier down: %d %v", resp.StatusCode, h.up.lastBody()["model"])
	}
	if r := resp.Header.Get("X-KyGate-Route"); !strings.HasPrefix(r, "budget; claude-sonnet-5-5 instead of claude-opus-5-5") || resp.Header.Get("X-KyGate-Budget") != "soft:key:monthly" {
		t.Fatalf("never silently: %q %q", r, resp.Header.Get("X-KyGate-Budget"))
	}
	e := h.event(resp.Header.Get("X-KyGate-Request-Id"))
	if !e.RouteApplied || e.RouteModel != "claude-sonnet-5-5" || e.ModelServed != "claude-sonnet-5-5" || e.RouteSavingUSD <= 0 || !e.Alert {
		t.Fatalf("%+v", e)
	}
	resp, _ = h.post("/v1/messages", h.keyA, messages("Write a long essay with code examples:\n```go\nfunc main() {}\n```", false))
	if resp.Header.Get("X-KyGate-Cache") != "miss" {
		t.Fatal("a cheaper model's answer is not stored for the requested model")
	}

	// A conversation that started on its model keeps it.
	next := messages("", false)
	next["messages"] = []any{
		map[string]any{"role": "user", "content": "Hello"},
		map[string]any{"role": "assistant", "content": "Hi."},
		map[string]any{"role": "user", "content": "Go on."},
	}
	h.post("/v1/messages", h.keyA, next)
	if h.up.lastBody()["model"] != "claude-opus-5-5" {
		t.Fatalf("a conversation under way keeps its model: %v", h.up.lastBody()["model"])
	}
}

func TestBudgetSoftLimitAlertAndMonitor(t *testing.T) {
	h := newHarness(t, budgetPolicy("budgets:\n  per_key: { monthly_usd: { soft: 0.01 } }\n  at_soft: alert\n"))
	resp, _ := h.post("/v1/messages", h.keyA, messages("Hello there", false))
	if h.up.lastBody()["model"] != "claude-opus-5-5" || resp.Header.Get("X-KyGate-Budget") != "soft:key:monthly" || !h.event(resp.Header.Get("X-KyGate-Request-Id")).Alert {
		t.Fatalf("alert: flagged, unchanged")
	}
	m := newHarness(t, strings.Replace(budgetPolicy("budgets:\n  per_key: { daily_usd: { hard: 0.001 } }\n"), "mode: enforce", "mode: monitor", 1))
	resp, _ = m.post("/v1/messages", m.keyA, messages("Hello there", false))
	if e := m.event(resp.Header.Get("X-KyGate-Request-Id")); resp.StatusCode != 200 || e.Budget != "hard:key:daily" || !e.Alert {
		t.Fatalf("monitor: recorded, not refused: %d %+v", resp.StatusCode, e)
	}
}

func TestRateLimits(t *testing.T) {
	h := newHarness(t, budgetPolicy("rate_limits:\n  per_key: { requests_per_minute: 2 }\n  keys:\n    bob: { tokens_per_minute: 500 }\n"))
	for i := 0; i < 2; i++ {
		if resp, _ := h.post("/v1/messages", h.keyA, messages("Hello "+strings.Repeat("x", i), false)); resp.StatusCode != 200 {
			t.Fatalf("request %d: %d", i, resp.StatusCode)
		}
	}
	resp, body := h.post("/v1/messages", h.keyA, messages("Hello again", false))
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" || !strings.Contains(body, "2 requests per minute") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if e := h.event(resp.Header.Get("X-KyGate-Request-Id")); e.Outcome != "rate_limited" {
		t.Fatalf("%+v", e)
	}
	// bob: no request limit, but 500 tokens a minute, and a request that may
	// use about 1,000 (its max_tokens).
	resp, body = h.post("/v1/messages", h.keyB, messages("Hello from bob", false))
	if resp.StatusCode != 429 || !strings.Contains(body, "500 tokens per minute") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}
