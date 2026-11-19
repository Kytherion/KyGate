package policy

// Budgets and rate limits (OP-5). Budgets are in US dollars per
// calendar month and day (UTC), for the organization, for every virtual key,
// and for named keys. Past a soft limit the router prefers a cheaper tier;
// past a hard limit the request is refused (architecture §3.5, §4.7).
//
//	budgets:
//	  org:     { monthly_usd: { soft: 800, hard: 1000 }, daily_usd: { hard: 60 } }
//	  per_key: { monthly_usd: { soft: 50, hard: 100 } }
//	  per_user: { monthly_usd: { hard: 20 } }   # each person named by a user token (AC-3)
//	  keys:
//	    build-bot: { daily_usd: { hard: 5 } }
//	  at_soft: cheaper_tier   # cheaper_tier | alert
//	  at_hard: reject
//	rate_limits:
//	  per_key: { requests_per_minute: 60, tokens_per_minute: 200000 }
//	  per_user: { requests_per_minute: 20 }
//	  keys:
//	    build-bot: { requests_per_minute: 10 }
//
// The design's shorthand, monthly_usd and daily_usd directly under budgets:,
// is the organization's budget.

import (
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// Limit is a soft and a hard limit in US dollars; 0 means none.
type Limit struct {
	Soft float64 `yaml:"soft" json:"soft,omitempty"`
	Hard float64 `yaml:"hard" json:"hard,omitempty"`
}

// BudgetSet is a monthly and a daily limit.
type BudgetSet struct {
	Monthly Limit `yaml:"monthly_usd" json:"monthly_usd"`
	Daily   Limit `yaml:"daily_usd" json:"daily_usd"`
}

func (b BudgetSet) empty() bool { return b == BudgetSet{} }

// Budgets is the parsed budgets section.
type Budgets struct {
	Org BudgetSet `json:"org"`
	// Team and Project are the caller's team's and project's own budgets,
	// from their policy files (AC-4).
	Team    BudgetSet            `json:"team"`
	Project BudgetSet            `json:"project"`
	PerKey  BudgetSet            `json:"per_key"`
	PerUser BudgetSet            `json:"per_user"` // each person, across keys (AC-3)
	Keys    map[string]BudgetSet `json:"keys,omitempty"`
	AtSoft  string               `json:"at_soft"` // cheaper_tier | alert
	AtHard  string               `json:"at_hard"` // reject
	// OnCountersUnavailable: when the shared counters (Team, Valkey) cannot
	// be reached, last_known goes on from this gateway's last known figures,
	// approximately (the default, architecture §5.4); refuse refuses every
	// request that has a hard limit until they are back.
	OnCountersUnavailable string `json:"on_counters_unavailable"`
}

// On reports whether any budget is set.
func (b Budgets) On() bool {
	return !b.Org.empty() || !b.Team.empty() || !b.Project.empty() || !b.PerKey.empty() || !b.PerUser.empty() || len(b.Keys) > 0
}

// ForKey returns the budget of a key: its own when named, else the default.
func (b Budgets) ForKey(name string) BudgetSet {
	if s, ok := b.Keys[name]; ok {
		return s
	}
	return b.PerKey
}

// RateLimit is a per-minute limit of one key; 0 means none.
type RateLimit struct {
	RequestsPerMinute int `yaml:"requests_per_minute" json:"requests_per_minute,omitempty"`
	TokensPerMinute   int `yaml:"tokens_per_minute" json:"tokens_per_minute,omitempty"`
}

// RateLimits is the parsed rate_limits section.
type RateLimits struct {
	PerKey  RateLimit            `yaml:"per_key" json:"per_key"`
	PerUser RateLimit            `yaml:"per_user" json:"per_user"` // each person, across keys (AC-3)
	Keys    map[string]RateLimit `yaml:"keys" json:"keys,omitempty"`
}

// ForKey returns the rate limit of a key: its own when named, else the default.
func (r RateLimits) ForKey(name string) RateLimit {
	if l, ok := r.Keys[name]; ok {
		return l
	}
	return r.PerKey
}

func (l Limit) check(where string) error {
	if l.Soft < 0 || l.Hard < 0 {
		return fmt.Errorf("%s: limits are positive amounts in US dollars", where)
	}
	if l.Soft > 0 && l.Hard > 0 && l.Soft > l.Hard {
		return fmt.Errorf("%s: the soft limit (%g) is above the hard limit (%g)", where, l.Soft, l.Hard)
	}
	return nil
}

func (b BudgetSet) check(where string) error {
	if err := b.Monthly.check(where + ".monthly_usd"); err != nil {
		return err
	}
	return b.Daily.check(where + ".daily_usd")
}

// parseBudgets reads budgets: loosely, so that the design's example loads.
func (p *Policy) parseBudgets() error {
	p.Budget = Budgets{AtSoft: "cheaper_tier", AtHard: "reject", OnCountersUnavailable: "last_known"}
	if p.Budgets.Kind == 0 {
		return nil
	}
	var raw map[string]yaml.Node
	if err := p.Budgets.Decode(&raw); err != nil {
		return fmt.Errorf("budgets: %v", err)
	}
	names := make([]string, 0, len(raw))
	for k := range raw {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		n := raw[k]
		var err error
		switch k {
		case "org":
			err = n.Decode(&p.Budget.Org)
		case "per_key":
			err = n.Decode(&p.Budget.PerKey)
		case "per_user":
			err = n.Decode(&p.Budget.PerUser)
		case "team":
			err = n.Decode(&p.Budget.Team)
		case "project":
			err = n.Decode(&p.Budget.Project)
		case "keys":
			err = n.Decode(&p.Budget.Keys)
		case "monthly_usd":
			// The design's shorthand: the organization's budget. at_soft and
			// at_hard may sit inside it, as in the design's example.
			var m struct {
				Limit  `yaml:",inline"`
				AtSoft string `yaml:"at_soft"`
				AtHard string `yaml:"at_hard"`
			}
			if err = n.Decode(&m); err == nil {
				p.Budget.Org.Monthly = m.Limit
				if m.AtSoft != "" {
					p.Budget.AtSoft = m.AtSoft
				}
				if m.AtHard != "" {
					p.Budget.AtHard = m.AtHard
				}
			}
		case "daily_usd":
			err = n.Decode(&p.Budget.Org.Daily)
		case "at_soft":
			err = n.Decode(&p.Budget.AtSoft)
		case "at_hard":
			err = n.Decode(&p.Budget.AtHard)
		case "on_counters_unavailable":
			err = n.Decode(&p.Budget.OnCountersUnavailable)
		default:
			p.Warnings = append(p.Warnings, fmt.Sprintf("budgets.%s: accepted, and ignored until the slice that ships it", k))
		}
		if err != nil {
			return fmt.Errorf("budgets.%s: %v", k, err)
		}
	}
	switch p.Budget.OnCountersUnavailable {
	case "last_known", "refuse":
	default:
		return fmt.Errorf("budgets.on_counters_unavailable must be last_known or refuse, not %q", p.Budget.OnCountersUnavailable)
	}
	switch p.Budget.AtSoft {
	case "cheaper_tier", "alert":
	default:
		return fmt.Errorf("budgets.at_soft must be cheaper_tier or alert, not %q", p.Budget.AtSoft)
	}
	switch p.Budget.AtHard {
	case "reject":
	case "local":
		p.Warnings = append(p.Warnings, "budgets.at_hard: local arrives with the router's local tier; requests past a hard limit are refused")
		p.Budget.AtHard = "reject"
	default:
		return fmt.Errorf("budgets.at_hard must be reject, not %q", p.Budget.AtHard)
	}
	if err := p.Budget.Org.check("budgets.org"); err != nil {
		return err
	}
	if err := p.Budget.Team.check("budgets.team"); err != nil {
		return err
	}
	if err := p.Budget.Project.check("budgets.project"); err != nil {
		return err
	}
	if err := p.Budget.PerKey.check("budgets.per_key"); err != nil {
		return err
	}
	if err := p.Budget.PerUser.check("budgets.per_user"); err != nil {
		return err
	}
	for name, s := range p.Budget.Keys {
		if err := s.check("budgets.keys." + name); err != nil {
			return err
		}
	}
	return nil
}

func (p *Policy) checkRateLimits() error {
	for name, l := range p.RateLimits.Keys {
		if l.RequestsPerMinute < 0 || l.TokensPerMinute < 0 {
			return fmt.Errorf("rate_limits.keys.%s: limits are positive numbers", name)
		}
	}
	if p.RateLimits.PerKey.RequestsPerMinute < 0 || p.RateLimits.PerKey.TokensPerMinute < 0 {
		return fmt.Errorf("rate_limits.per_key: limits are positive numbers")
	}
	if p.RateLimits.PerUser.RequestsPerMinute < 0 || p.RateLimits.PerUser.TokensPerMinute < 0 {
		return fmt.Errorf("rate_limits.per_user: limits are positive numbers")
	}
	return nil
}
