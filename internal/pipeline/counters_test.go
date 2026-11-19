package pipeline_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/limits"
	"github.com/Kytherion/KyGate/internal/policy"
)

// downCounters is a shared counter store that cannot be reached.
type downCounters struct{}

func (downCounters) Add(context.Context, string, float64, time.Time) (float64, error) {
	return 0, errors.New("connection refused")
}
func (downCounters) Get(context.Context, string) (float64, error) {
	return 0, errors.New("connection refused")
}

func hardKeyBudget(extra string) string {
	return strings.Replace(string(policy.Starter()), "routing:\n", "budgets:\n  per_key: { monthly_usd: { hard: 100 } }\n"+extra+"\nrouting:\n", 1)
}

// Architecture §5.4: with the shared counters down, the policy decides
// whether a request with a hard limit goes on (last known figures) or not.
func TestBudgetCountersUnavailable(t *testing.T) {
	h := newHarness(t, hardKeyBudget(""))
	h.g.Budgets = &limits.Budgets{C: limits.NewFallbackCounters(downCounters{})}
	resp, body := h.post("/v1/chat/completions", h.keyA, chat("hello", false))
	if resp.StatusCode != 200 {
		t.Fatalf("last_known, the default: served: %d %s", resp.StatusCode, body)
	}
	if e := h.events()[0]; !e.Alert || !strings.Contains(e.Budget, "approximate") {
		t.Fatalf("and flagged: %+v", e.Budget)
	}

	h = newHarness(t, hardKeyBudget("  on_counters_unavailable: refuse\n"))
	h.g.Budgets = &limits.Budgets{C: limits.NewFallbackCounters(downCounters{})}
	resp, body = h.post("/v1/chat/completions", h.keyA, chat("hello", false))
	if resp.StatusCode != 503 || !strings.Contains(body, "budget_unavailable") || resp.Header.Get("X-KyGate-Budget") != "unavailable" {
		t.Fatalf("refuse: %d %s", resp.StatusCode, body)
	}
	if h.up.calls != 0 {
		t.Fatal("no provider call")
	}

	// No hard limit at all: nothing to protect, served.
	h = newHarness(t, strings.Replace(string(policy.Starter()), "routing:\n", "budgets:\n  on_counters_unavailable: refuse\n\nrouting:\n", 1))
	h.g.Budgets = &limits.Budgets{C: limits.NewFallbackCounters(downCounters{})}
	if resp, body := h.post("/v1/chat/completions", h.keyA, chat("hello", false)); resp.StatusCode != 200 {
		t.Fatalf("no hard limit: %d %s", resp.StatusCode, body)
	}
}
