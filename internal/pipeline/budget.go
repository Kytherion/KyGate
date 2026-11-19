package pipeline

// Budgets and rate limits on the request path (OP-5). Requests per
// minute are counted at stage 3, for every request. Tokens per minute and the
// budgets are checked after the caches, because a cache hit calls no model
// and costs nothing: a key past its budget is still answered from the cache.

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/Kytherion/KyGate/internal/limits"
	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/router"
)

// DefaultOutputEstimate is the answer size reserved when a request sets no
// maximum.
const DefaultOutputEstimate = 1024

func retryAfter(w interface{ Set(string, string) }, d time.Duration) {
	s := int(d.Seconds())
	if s < 1 {
		s = 1
	}
	w.Set("Retry-After", strconv.Itoa(s))
}

// rateRequest counts the request against the key's requests per minute. It
// reports whether the request may go on.
func (g *Gateway) rateRequest(sc *serveCtx) bool {
	if g.Rates == nil {
		return true
	}
	rl := sc.pol.RateLimits.ForKey(sc.caller.KeyName)
	ok, wait := g.Rates.Request(sc.caller.KeyID, rl.RequestsPerMinute, time.Now(), sc.pol.Mode != policy.Enforce)
	if ok {
		return true
	}
	retryAfter(sc.w.Header(), wait)
	sc.fail(429, "rate_limited", "rate_limit_exceeded", fmt.Sprintf("KyGate: this key is over its limit of %d requests per minute. Retry in %s. (request %s)", rl.RequestsPerMinute, wait, sc.ev.ID))
	return false
}

// userLimitKey is a person's entry in the rate limiter; key IDs start with
// key_, so the two never meet.
func userLimitKey(user string) string { return "user:" + user }

// rateUser counts the request against the person's requests per minute,
// across every key they use (AC-3).
func (g *Gateway) rateUser(sc *serveCtx) bool {
	if g.Rates == nil || sc.caller.User == "" {
		return true
	}
	rl := sc.pol.RateLimits.PerUser
	ok, wait := g.Rates.Request(userLimitKey(sc.caller.User), rl.RequestsPerMinute, time.Now(), sc.pol.Mode != policy.Enforce)
	if ok {
		return true
	}
	retryAfter(sc.w.Header(), wait)
	sc.fail(429, "rate_limited", "rate_limit_exceeded", fmt.Sprintf("KyGate: this person is over their limit of %d requests per minute. Retry in %s. (request %s)", rl.RequestsPerMinute, wait, sc.ev.ID))
	return false
}

// estimate returns the tokens and the cost to reserve: the input size plus
// the largest answer the request allows, priced at the model it names.
func (g *Gateway) estimate(sc *serveCtx, f router.Features, hosting string) (int, float64) {
	out := f.MaxOutputTokens
	if out == 0 {
		out = DefaultOutputEstimate
	}
	cost, _ := g.Catalog.Cost(sc.req.Model, hosting, router.Usage{Input: int64(f.PromptTokens), Output: int64(out)})
	return f.PromptTokens + out, cost
}

// budgetStage checks tokens per minute and the budgets before the upstream
// call, and applies the budget's soft-limit choice. It reports whether the
// request may go on; target may be changed to a cheaper model.
func (g *Gateway) budgetStage(sc *serveCtx, target *router.Target, conversation string) bool {
	pol, ev := sc.pol, sc.ev
	enforce := pol.Mode == policy.Enforce
	f := router.FeaturesOf(sc.req, target.Hosting == "local", pol.Route.Tiers)
	tokens, cost := g.estimate(sc, f, target.Hosting)
	now := time.Now()

	if g.Rates != nil {
		rl := pol.RateLimits.ForKey(sc.caller.KeyName)
		if ok, wait := g.Rates.Tokens(sc.caller.KeyID, rl.TokensPerMinute, tokens, now, !enforce); !ok {
			retryAfter(sc.w.Header(), wait)
			sc.fail(429, "rate_limited", "rate_limit_exceeded", fmt.Sprintf("KyGate: this key is over its limit of %d tokens per minute (this request may use about %d). Retry in %s. (request %s)", rl.TokensPerMinute, tokens, wait, ev.ID))
			return false
		}
		sc.tokenEstimate, sc.tokenLimit = tokens, rl.TokensPerMinute
		if u := sc.caller.User; u != "" {
			ul := pol.RateLimits.PerUser.TokensPerMinute
			if ok, wait := g.Rates.Tokens(userLimitKey(u), ul, tokens, now, !enforce); !ok {
				retryAfter(sc.w.Header(), wait)
				sc.fail(429, "rate_limited", "rate_limit_exceeded", fmt.Sprintf("KyGate: this person is over their limit of %d tokens per minute (this request may use about %d). Retry in %s. (request %s)", ul, tokens, wait, ev.ID))
				return false
			}
			sc.userTokenLimit = ul
		}
	}

	// Spend is always counted, budget or not, so that a budget added later
	// starts from the real figures.
	if g.Budgets == nil {
		return true
	}
	who := limits.Who{KeyID: sc.caller.KeyID, KeyName: sc.caller.KeyName, TeamID: sc.caller.TeamID, ProjectID: sc.caller.ProjectID, User: sc.caller.User}
	chk, err := g.Budgets.Reserve(context.Background(), pol.Budget, who, cost, now, enforce)
	if err != nil {
		// The counters are an optimization of the ledger: a failure lets the
		// request go, recorded (architecture §5.4).
		g.Logf("budget: %v", err)
		return true
	}
	sc.budget = chk
	ev.Budget = chk.Label()
	if chk.Approximate {
		// The shared counters are down: the figures are this gateway's last
		// known ones (architecture §5.4).
		g.Metrics.Add("kygate_budget_approximate_total", 1)
		ev.Alert = true
		if chk.HardLimits && pol.Budget.OnCountersUnavailable == "refuse" && enforce {
			g.Budgets.Release(context.Background(), chk)
			sc.w.Header().Set("X-KyGate-Budget", "unavailable")
			sc.fail(503, "refused", "budget_unavailable", "KyGate refused this request: its budget has a hard limit, the shared budget counters cannot be reached, and the policy refuses until they are back (budgets.on_counters_unavailable: refuse). (request "+ev.ID+")")
			return false
		}
		if ev.Budget == "" {
			ev.Budget = "approximate"
		} else {
			ev.Budget += ":approximate"
		}
	}
	switch chk.State {
	case limits.Hard:
		ev.Alert = true
		if !enforce {
			return true
		}
		sc.w.Header().Set("X-KyGate-Budget", chk.Label())
		retryAfter(sc.w.Header(), time.Until(chk.Resets))
		sc.fail(429, "over_budget", "budget_exceeded", "KyGate refused this request: it would pass "+chk.Describe()+". (request "+ev.ID+")")
		return false
	case limits.Soft:
		ev.Alert = true
		sc.w.Header().Set("X-KyGate-Budget", chk.Label())
		if pol.Budget.AtSoft != "cheaper_tier" || !enforce || g.Router == nil {
			return true
		}
		d := g.Router.Downgrade(f, conversation, "past the soft limit of "+chk.Describe())
		if !d.Moves() {
			ev.RouteReason = "budget: stays: " + d.Reason
			return true
		}
		// Never silently: the headers name the model and the reason.
		target.UpstreamModel = d.Model
		sc.downgraded = true
		ev.RouteModel, ev.RouteApplied = d.Model, true
		ev.RouteReason = "budget: " + d.Reason
		sc.w.Header().Set("X-KyGate-Route", fmt.Sprintf("budget; %s instead of %s (%s tier): past a soft limit", d.Model, sc.req.Model, d.Tier))
	}
	return true
}

// settleLimits replaces the reservations with the real usage, once the answer
// is known. It runs when the event is written.
func (g *Gateway) settleLimits(sc *serveCtx) {
	if g.Budgets != nil {
		g.Budgets.Settle(context.Background(), sc.budget, sc.ev.CostUSD)
	}
	if g.Rates != nil && sc.tokenEstimate > 0 {
		used := int(sc.ev.InputTokens + sc.ev.CachedTokens + sc.ev.CacheWrite + sc.ev.OutputTokens)
		g.Rates.AdjustTokens(sc.caller.KeyID, sc.tokenLimit, used-sc.tokenEstimate, time.Now())
		if sc.caller.User != "" {
			g.Rates.AdjustTokens(userLimitKey(sc.caller.User), sc.userTokenLimit, used-sc.tokenEstimate, time.Now())
		}
	}
}
