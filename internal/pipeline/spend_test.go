package pipeline_test

import (
	"context"
	"testing"
	"time"
)

// Spend is counted with no budget in the policy, so that a budget added later
// starts from the real figures.
func TestSpendIsCountedWithoutABudget(t *testing.T) {
	h := newHarness(t, "")
	resp, _ := h.post("/v1/messages", h.keyA, messages("Hello there", false))
	if resp.StatusCode != 200 || resp.Header.Get("X-KyGate-Budget") != "" {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("X-KyGate-Budget"))
	}
	e := h.event(resp.Header.Get("X-KyGate-Request-Id"))
	org, _ := h.g.Budgets.Spent(context.Background(), "org", time.Now())
	if e.CostUSD <= 0 || org < e.CostUSD*0.999 || org > e.CostUSD*1.001 {
		t.Fatalf("spent %v, counted %v", e.CostUSD, org)
	}
}
