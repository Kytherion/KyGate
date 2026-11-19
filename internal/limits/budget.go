package limits

// Budgets with reserve and settle (OP-5; architecture §4.7).
// Before a call the gateway reserves an estimate: the input size plus the
// largest answer the request allows, priced at the model it names. After the
// call it settles with the cost of the usage the provider reported. Without
// reservation, parallel requests would each pass a check that sees the same
// unspent budget. Cache hits cost nothing and are never counted.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store"
)

// Budget states.
const (
	OK   = "ok"
	Soft = "soft" // past a soft limit: the router prefers a cheaper tier
	Hard = "hard" // past a hard limit: refused
)

// Budgets checks and counts spend.
type Budgets struct {
	C store.Counters
}

// Check is the result of a reservation.
type Check struct {
	State  string  // ok | soft | hard
	Scope  string  // org | key: the budget that set the state
	Period string  // monthly | daily
	Spent  float64 // spend of that budget before this request, reservations included
	Limit  float64 // the limit that was passed
	Resets time.Time
	// Approximate is true when the shared counters could not be reached and
	// the figures are this process's last known ones (architecture §5.4).
	// HardLimits says whether any budget of the request has a hard limit.
	Approximate bool
	HardLimits  bool

	res *Reservation
}

// Label names the budget for events and headers, such as "soft:key:monthly".
func (c Check) Label() string {
	if c.State == OK || c.State == "" {
		return ""
	}
	return c.State + ":" + c.Scope + ":" + c.Period
}

// Describe says it in a sentence, for messages.
func (c Check) Describe() string {
	who := map[string]string{"org": "the organization's", "team": "this team's", "project": "this project's", "key": "this key's", "user": "this person's"}[c.Scope]
	return fmt.Sprintf("%s %s budget: $%.2f spent of a %s limit of $%.2f; it resets %s",
		who, c.Period, c.Spent, c.State, c.Limit, c.Resets.Format("2006-01-02 15:04 UTC"))
}

// Who is the caller of a request, for its budgets.
type Who struct {
	KeyID, KeyName    string
	TeamID, ProjectID string
	User              string // the person's pseudonym, when a user token named one (AC-3)
}

// Reservation is what a request reserved, settled after the call.
type Reservation struct {
	keys    []string
	expires []time.Time
	amount  float64
	once    sync.Once
}

type window struct {
	period string
	id     string
	resets time.Time
}

func windows(now time.Time) []window {
	now = now.UTC()
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	return []window{
		{"monthly", "m:" + month.Format("2006-01"), month.AddDate(0, 1, 0)},
		{"daily", "d:" + day.Format("2006-01-02"), day.AddDate(0, 0, 1)},
	}
}

// CounterKey names the spend counter of a scope ("org" or a key ID) in a window.
func CounterKey(scope, windowID string) string { return "spend:" + scope + ":" + windowID }

// Reserve checks the budgets of an organization and a key, and reserves the
// estimate on every counter. Each counter is added to first and checked on the
// value the addition returns, one atomic step per counter, so parallel
// requests never see the same unspent budget. A request past a hard limit
// gives its reservation back when the policy enforces; in monitor mode it
// keeps it, and is only recorded.
func (b *Budgets) Reserve(ctx context.Context, bp policy.Budgets, who Who, estimate float64, now time.Time, enforce bool) (Check, error) {
	type scope struct {
		name, id string
		set      policy.BudgetSet
	}
	scopes := []scope{{"org", "org", bp.Org}}
	if who.TeamID != "" {
		scopes = append(scopes, scope{"team", "team:" + who.TeamID, bp.Team})
	}
	if who.ProjectID != "" {
		scopes = append(scopes, scope{"project", "project:" + who.ProjectID, bp.Project})
	}
	scopes = append(scopes, scope{"key", "key:" + who.KeyID, bp.ForKey(who.KeyName)})
	if who.User != "" {
		// A person's budget counts across every key they use.
		scopes = append(scopes, scope{"user", "user:" + who.User, bp.PerUser})
	}
	best := Check{State: OK}
	rank := map[string]int{OK: 0, Soft: 1, Hard: 2}
	res := &Reservation{amount: estimate}
	approx, hard := false, false
	for _, w := range windows(now) {
		for _, s := range scopes {
			key := CounterKey(s.id, w.id)
			expires := w.resets.Add(24 * time.Hour)
			total, err := b.C.Add(ctx, key, estimate, expires)
			if errors.Is(err, ErrApproximate) {
				approx, err = true, nil
			}
			if err != nil {
				b.release(ctx, res)
				return Check{State: OK}, err
			}
			res.keys = append(res.keys, key)
			res.expires = append(res.expires, expires)
			l := s.set.Monthly
			if w.period == "daily" {
				l = s.set.Daily
			}
			hard = hard || l.Hard > 0
			state, limit := OK, 0.0
			switch {
			case l.Hard > 0 && total > l.Hard:
				state, limit = Hard, l.Hard
			case l.Soft > 0 && total > l.Soft:
				state, limit = Soft, l.Soft
			}
			if rank[state] > rank[best.State] {
				best = Check{State: state, Scope: s.name, Period: w.period, Spent: total - estimate, Limit: limit, Resets: w.resets}
			}
		}
	}
	best.Approximate, best.HardLimits = approx, hard
	if best.State == Hard && enforce {
		b.release(ctx, res)
		return best, nil
	}
	best.res = res
	return best, nil
}

// release gives a reservation back.
func (b *Budgets) release(ctx context.Context, r *Reservation) {
	for i, k := range r.keys {
		b.C.Add(ctx, k, -r.amount, r.expires[i])
	}
}

// Settle replaces a reservation with the real cost. It runs once.
func (b *Budgets) Settle(ctx context.Context, c Check, actual float64) {
	r := c.res
	if r == nil {
		return
	}
	r.once.Do(func() {
		for i, k := range r.keys {
			b.C.Add(ctx, k, actual-r.amount, r.expires[i])
		}
	})
}

// Rebuild sets the counters from the event ledger: this month's and today's
// spend per key, per team and project (by where each key is now), and in all.
// It runs at start, before any request. place may be nil.
func (b *Budgets) Rebuild(ctx context.Context, ev store.EventStore, now time.Time, place func(keyID string) (teamID, projectID string)) error {
	for _, w := range windows(now) {
		// With counters shared by several gateways, only the first process
		// to start in a window rebuilds it; the others would count twice.
		if n, err := b.C.Add(ctx, "rebuilt:"+w.id, 1, w.resets.Add(24*time.Hour)); err != nil {
			return err
		} else if n > 1 {
			continue
		}
		start := w.resets.AddDate(0, -1, 0)
		if w.period == "daily" {
			start = w.resets.AddDate(0, 0, -1)
		}
		rows, err := ev.Spend(ctx, start)
		if err != nil {
			return err
		}
		total := 0.0
		for _, r := range rows {
			total += r.CostUSD
			if r.KeyID != "" {
				if _, err := b.C.Add(ctx, CounterKey("key:"+r.KeyID, w.id), r.CostUSD, w.resets.Add(24*time.Hour)); err != nil {
					return err
				}
				if r.User != "" {
					b.C.Add(ctx, CounterKey("user:"+r.User, w.id), r.CostUSD, w.resets.Add(24*time.Hour))
				}
				if place != nil {
					team, project := place(r.KeyID)
					if team != "" {
						b.C.Add(ctx, CounterKey("team:"+team, w.id), r.CostUSD, w.resets.Add(24*time.Hour))
					}
					if project != "" {
						b.C.Add(ctx, CounterKey("project:"+project, w.id), r.CostUSD, w.resets.Add(24*time.Hour))
					}
				}
			}
		}
		if _, err := b.C.Add(ctx, CounterKey("org", w.id), total, w.resets.Add(24*time.Hour)); err != nil {
			return err
		}
	}
	return nil
}

// Spent returns the spend of a scope ("org", or "key:"+ID) this month and today.
func (b *Budgets) Spent(ctx context.Context, scope string, now time.Time) (monthly, daily float64) {
	ws := windows(now)
	monthly, _ = b.C.Get(ctx, CounterKey(scope, ws[0].id))
	daily, _ = b.C.Get(ctx, CounterKey(scope, ws[1].id))
	return monthly, daily
}

// MemoryCounters is the Solo driver of store.Counters.
type MemoryCounters struct {
	mu sync.Mutex
	m  map[string]memCounter
}

type memCounter struct {
	v       float64
	expires time.Time
}

// NewMemoryCounters returns empty counters.
func NewMemoryCounters() *MemoryCounters { return &MemoryCounters{m: map[string]memCounter{}} }

// Add implements store.Counters.
func (c *MemoryCounters) Add(_ context.Context, key string, delta float64, expires time.Time) (float64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if len(c.m) > 10000 {
		for k, v := range c.m {
			if now.After(v.expires) {
				delete(c.m, k)
			}
		}
	}
	x := c.m[key]
	if now.After(x.expires) && !x.expires.IsZero() {
		x = memCounter{}
	}
	x.v += delta
	if x.v < 0 {
		x.v = 0 // a settlement below its reservation never makes spend negative
	}
	x.expires = expires
	c.m[key] = x
	return x.v, nil
}

// Get implements store.Counters.
func (c *MemoryCounters) Get(_ context.Context, key string) (float64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	x := c.m[key]
	if !x.expires.IsZero() && time.Now().After(x.expires) {
		return 0, nil
	}
	return x.v, nil
}

// Release gives back what a check reserved, when the request does not go on.
func (b *Budgets) Release(ctx context.Context, c Check) {
	if c.res != nil {
		c.res.once.Do(func() { b.release(ctx, c.res) })
	}
}
