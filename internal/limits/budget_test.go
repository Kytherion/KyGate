package limits

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store"
)

var ctx = context.Background()

func keyBudget(soft, hard float64) policy.Budgets {
	return policy.Budgets{PerKey: policy.BudgetSet{Monthly: policy.Limit{Soft: soft, Hard: hard}}, AtSoft: "cheaper_tier", AtHard: "reject"}
}

// Parallel requests cannot all pass a check that sees the same unspent
// budget: each reserves before the next one checks.
func TestReservationStopsParallelOvershoot(t *testing.T) {
	b := &Budgets{C: NewMemoryCounters()}
	bp := keyBudget(0, 1.00)
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := b.Reserve(ctx, bp, Who{KeyID: "k1", KeyName: "alice"}, 0.30, time.Now(), true)
			if err == nil && c.State != Hard {
				mu.Lock()
				passed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if passed != 3 {
		t.Fatalf("%d requests of $0.30 passed a $1.00 limit; want 3", passed)
	}
}

func TestSettleReplacesTheEstimate(t *testing.T) {
	b := &Budgets{C: NewMemoryCounters()}
	bp := keyBudget(0.5, 1.0)
	now := time.Now()
	c, _ := b.Reserve(ctx, bp, Who{KeyID: "k1", KeyName: "alice"}, 0.40, now, true)
	if c.State != OK {
		t.Fatalf("%+v", c)
	}
	b.Settle(ctx, c, 0.05)
	b.Settle(ctx, c, 0.05) // once only
	m, d := b.Spent(ctx, "key:k1", now)
	if m < 0.0499 || m > 0.0501 || d < 0.0499 || d > 0.0501 {
		t.Fatalf("monthly %v daily %v", m, d)
	}
	if org, _ := b.Spent(ctx, "org", now); org < 0.0499 || org > 0.0501 {
		t.Fatalf("org %v", org)
	}
	// 0.05 spent + 0.50 > soft 0.5: soft; + 0.96 > hard 1.0: hard.
	if c, _ := b.Reserve(ctx, bp, Who{KeyID: "k1", KeyName: "alice"}, 0.50, now, true); c.State != Soft || c.Label() != "soft:key:monthly" {
		t.Fatalf("%+v", c)
	}
	if c, _ := b.Reserve(ctx, bp, Who{KeyID: "k1", KeyName: "alice"}, 0.50, now, true); c.State != Hard {
		t.Fatalf("%+v", c)
	}
}

func TestMonitorModeCountsAndDoesNotStop(t *testing.T) {
	b := &Budgets{C: NewMemoryCounters()}
	c, _ := b.Reserve(ctx, keyBudget(0, 0.10), Who{KeyID: "k1", KeyName: "alice"}, 0.50, time.Now(), false)
	if c.State != Hard || c.res == nil {
		t.Fatalf("monitor: recorded as hard, and reserved: %+v", c)
	}
}

func TestNamedKeyAndOrgAndDaily(t *testing.T) {
	b := &Budgets{C: NewMemoryCounters()}
	bp := policy.Budgets{
		Org:    policy.BudgetSet{Daily: policy.Limit{Hard: 0.30}},
		PerKey: policy.BudgetSet{Monthly: policy.Limit{Hard: 100}},
		Keys:   map[string]policy.BudgetSet{"build-bot": {Daily: policy.Limit{Hard: 0.05}}},
		AtSoft: "alert", AtHard: "reject",
	}
	if c, _ := b.Reserve(ctx, bp, Who{KeyID: "bot", KeyName: "build-bot"}, 0.10, time.Now(), true); c.State != Hard || c.Scope != "key" || c.Period != "daily" {
		t.Fatalf("the named key's own budget: %+v", c)
	}
	b.Reserve(ctx, bp, Who{KeyID: "a", KeyName: "alice"}, 0.20, time.Now(), true)
	if c, _ := b.Reserve(ctx, bp, Who{KeyID: "b", KeyName: "bob"}, 0.20, time.Now(), true); c.State != Hard || c.Scope != "org" {
		t.Fatalf("the organization's daily budget is shared: %+v", c)
	}
}

type ledger struct{ store.EventStore }

func (ledger) Spend(_ context.Context, since time.Time) ([]store.SpendRow, error) {
	if time.Since(since) > 48*time.Hour { // the month
		return []store.SpendRow{{KeyID: "k1", CostUSD: 7}, {KeyID: "k2", CostUSD: 3}}, nil
	}
	return []store.SpendRow{{KeyID: "k1", CostUSD: 1}}, nil
}

func TestRebuildFromTheLedger(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	b := &Budgets{C: NewMemoryCounters()}
	// Spend uses the window start; the fake ledger tells month from day by age.
	if err := b.Rebuild(ctx, ledger{}, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	m, d := b.Spent(ctx, "key:k1", time.Now())
	org, _ := b.Spent(ctx, "org", time.Now())
	if time.Now().UTC().Day() > 2 && (m != 7 || d != 1 || org != 10) {
		t.Fatalf("k1 month %v day %v, org %v", m, d, org)
	}
	_ = now
}

func TestRateBuckets(t *testing.T) {
	r := NewRates()
	now := time.Now()
	for i := 0; i < 3; i++ {
		if ok, _ := r.Request("k", 3, now, false); !ok {
			t.Fatalf("request %d", i)
		}
	}
	ok, wait := r.Request("k", 3, now, false)
	if ok || wait < time.Second || wait > 21*time.Second {
		t.Fatalf("the fourth request in the same instant waits about 20 s: %v %v", ok, wait)
	}
	if ok, _ := r.Request("k", 3, now.Add(21*time.Second), false); !ok {
		t.Fatal("the bucket refills")
	}
	if ok, _ := r.Request("other", 3, now, false); !ok {
		t.Fatal("keys have their own buckets")
	}
	if ok, _ := r.Request("k", 3, now.Add(21*time.Second), true); !ok {
		t.Fatal("monitor mode counts and lets the request go")
	}
	if ok, _ := r.Tokens("k", 1000, 800, now, false); !ok {
		t.Fatal("tokens")
	}
	r.AdjustTokens("k", 1000, 500, now) // 1,300 used in all
	if ok, _ := r.Tokens("k", 1000, 100, now, false); ok {
		t.Fatal("the correction counts")
	}
}

// AC-3: a person's budget counts across every key they use.
func TestPerUserBudget(t *testing.T) {
	b := &Budgets{C: NewMemoryCounters()}
	bp := policy.Budgets{PerUser: policy.BudgetSet{Daily: policy.Limit{Hard: 1}}}
	ctx := context.Background()
	now := time.Now()
	c1, _ := b.Reserve(ctx, bp, Who{KeyID: "key_a", KeyName: "a", User: "u_1"}, 0.6, now, true)
	b.Settle(ctx, c1, 0.6)
	c2, _ := b.Reserve(ctx, bp, Who{KeyID: "key_b", KeyName: "b", User: "u_1"}, 0.6, now, true)
	if c2.State != Hard || c2.Scope != "user" || !strings.Contains(c2.Describe(), "this person's") {
		t.Fatalf("the second key hits the same person's budget: %+v", c2)
	}
	if c3, _ := b.Reserve(ctx, bp, Who{KeyID: "key_b", KeyName: "b", User: "u_2"}, 0.6, now, true); c3.State != OK {
		t.Fatalf("another person: %+v", c3)
	}
	if c4, _ := b.Reserve(ctx, bp, Who{KeyID: "key_b", KeyName: "b"}, 0.6, now, true); c4.State != OK {
		t.Fatalf("no person named: no person's budget: %+v", c4)
	}
}
