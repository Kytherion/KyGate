package router

// The routing decision (OP-4). It answers: what is the cheapest
// target that is allowed and able to answer this request? It runs in
// shadow mode only: the decision is recorded with the money it would have
// saved, and the request still goes to the model it names (architecture §3.5,
// §4.6).
//
// The rules are cautious, by the owner's choice:
//   - one tier down at most (frontier -> standard -> economy);
//   - the same provider (no translation between API families);
//   - only when a conversation starts, and the decision sticks to it;
//   - only for short plain prompts: no code, no tools, no images or files, no
//     structured output, no extended reasoning, and a short context.

import (
	"strings"
	"sync"
)

// Tiers, cheapest first. "local" is not reached yet.
var tierOrder = []string{"local", "economy", "standard", "frontier"}

func tierRank(t string) int {
	for i, x := range tierOrder {
		if x == t {
			return i
		}
	}
	return -1
}

// Features describe a request for the router: shapes and sizes, never text.
type Features struct {
	Family          string // openai | anthropic
	Model           string // the model the request names
	PromptTokens    int    // an estimate of the whole prompt
	LastUserTokens  int    // an estimate of the last user message
	UserTurns       int
	AssistantTurns  int
	Code            bool // a code block or code-like text
	Tools           bool // the request declares tools
	Unreadable      bool // images, files, audio
	Structured      bool // a structured-output request (JSON schema, JSON mode)
	Reasoning       bool // extended thinking or a reasoning effort above the default
	Local           bool // the request goes to a local model server
	MaxOutputTokens int  // what the request allows the answer, 0 when unset
	// Tiers the policy lets the router use; all when empty.
	Tiers []string
}

// Limits of the cautious rules.
const (
	MaxEasyLastTokens   = 400  // the last user message
	MaxEasyPromptTokens = 2000 // the whole prompt
	MaxEasyOutputTokens = 4096 // what the request asks the answer to be able to reach
)

// Decision is what the router would do.
type Decision struct {
	Requested     string `json:"requested"`
	RequestedTier string `json:"requested_tier,omitempty"`
	Model         string `json:"model,omitempty"` // the cheaper model, or "" to stay
	Tier          string `json:"tier,omitempty"`
	Reason        string `json:"reason"` // why it moves, or why it stays
	Sticky        bool   `json:"sticky,omitempty"`
}

// Moves reports whether the decision changes the model.
func (d Decision) Moves() bool { return d.Model != "" && d.Model != d.Requested }

// Router decides, and remembers each conversation's decision.
type Router struct {
	Catalog *Catalog
	mu      sync.Mutex
	convs   map[string]Decision
	order   []string
	budget  map[string]Decision // conversations that started past a soft limit
	border  []string
}

const maxConversations = 100000

// NewRouter returns a router over a catalog.
func NewRouter(c *Catalog) *Router {
	return &Router{Catalog: c, convs: map[string]Decision{}, budget: map[string]Decision{}}
}

// Decide returns the routing decision for a request. conversation identifies
// the conversation (empty when unknown): a conversation keeps the decision of
// its first turn.
func (r *Router) Decide(f Features, conversation string) Decision {
	if conversation != "" {
		r.mu.Lock()
		d, ok := r.convs[conversation]
		r.mu.Unlock()
		if ok && d.Requested == f.Model {
			d.Sticky = true
			return d
		}
	}
	d := r.decide(f)
	if conversation != "" && f.AssistantTurns == 0 {
		r.mu.Lock()
		if _, ok := r.convs[conversation]; !ok {
			r.convs[conversation] = d
			r.order = append(r.order, conversation)
			if len(r.order) > maxConversations {
				delete(r.convs, r.order[0])
				r.order = r.order[1:]
			}
		}
		r.mu.Unlock()
	}
	return d
}

func (r *Router) decide(f Features) Decision {
	d := Decision{Requested: f.Model}
	stay := func(reason string) Decision { d.Reason = reason; return d }
	m := r.Catalog.Lookup(f.Model)
	if m == nil {
		return stay("the model is not in the catalog")
	}
	d.RequestedTier = m.Tier
	switch {
	case f.Local:
		return stay("the request goes to a local model")
	case f.AssistantTurns > 0:
		return stay("the conversation started before the router saw it")
	case f.Tools:
		return stay("the request declares tools")
	case f.Unreadable:
		return stay("the request carries images, files, or audio")
	case f.Structured:
		return stay("the request asks for structured output")
	case f.Reasoning:
		return stay("the request asks for extended reasoning")
	case f.Code:
		return stay("the request contains code")
	case f.LastUserTokens > MaxEasyLastTokens:
		return stay("the last message is long")
	case f.PromptTokens > MaxEasyPromptTokens:
		return stay("the context is long")
	case f.MaxOutputTokens > MaxEasyOutputTokens:
		return stay("the request allows a long answer")
	}
	rank := tierRank(m.Tier)
	if rank <= tierRank("economy") {
		return stay("the model is already in the cheapest tier")
	}
	target := tierOrder[rank-1]
	if len(f.Tiers) > 0 && !contains(f.Tiers, target) {
		return stay("the policy does not let the router use the " + target + " tier")
	}
	best := r.cheapest(m.Family, target, f.PromptTokens+f.MaxOutputTokens, m)
	if best == nil {
		return stay("no cheaper model of this provider in the " + target + " tier")
	}
	d.Model, d.Tier = best.ID, best.Tier
	d.Reason = "a short plain prompt at the start of a conversation: one tier down"
	return d
}

// Downgrade is the budget's choice past a soft limit (architecture §3.5, step
// 2): one tier down within the provider, for every conversation that starts
// there, whatever its difficulty. The hard constraints still hold: the model
// must be in the catalog and hold the request, a request with reasoning
// settings stays (a cheaper model may not take them), and a conversation that
// started on its model keeps it. A conversation that starts cheaper stays
// cheaper.
func (r *Router) Downgrade(f Features, conversation string, why string) Decision {
	if conversation != "" {
		r.mu.Lock()
		d, ok := r.budget[conversation]
		r.mu.Unlock()
		if ok && d.Requested == f.Model {
			d.Sticky = true
			return d
		}
	}
	d := Decision{Requested: f.Model}
	stay := func(reason string) Decision { d.Reason = reason; return d }
	m := r.Catalog.Lookup(f.Model)
	switch {
	case m == nil:
		return stay("the model is not in the catalog")
	case f.Local:
		return stay("the request goes to a local model")
	case f.AssistantTurns > 0:
		return stay("the conversation started on its model")
	case f.Reasoning:
		return stay("the request asks for extended reasoning, which a cheaper model may not take")
	}
	d.RequestedTier = m.Tier
	rank := tierRank(m.Tier)
	if rank <= tierRank("economy") {
		return stay("the model is already in the cheapest tier")
	}
	target := tierOrder[rank-1]
	if len(f.Tiers) > 0 && !contains(f.Tiers, target) {
		return stay("the policy does not let the router use the " + target + " tier")
	}
	best := r.cheapest(m.Family, target, f.PromptTokens+f.MaxOutputTokens, m)
	if best == nil {
		return stay("no cheaper model of this provider in the " + target + " tier holds the request")
	}
	d.Model, d.Tier, d.Reason = best.ID, best.Tier, why
	if conversation != "" {
		r.mu.Lock()
		if _, ok := r.budget[conversation]; !ok {
			r.budget[conversation] = d
			r.border = append(r.border, conversation)
			if len(r.border) > maxConversations {
				delete(r.budget, r.border[0])
				r.border = r.border[1:]
			}
		}
		r.mu.Unlock()
	}
	return d
}

// cheapest returns the cheapest model of a family in a tier that can hold the
// request and costs less than the requested one. Ties keep catalog order.
func (r *Router) cheapest(family, tier string, need int, than *Model) *Model {
	var best *Model
	cost := func(m *Model) float64 { return m.Price.Input + m.Price.Output }
	for _, m := range r.Catalog.InOrder() {
		m := m
		if m.Family != family || m.Tier != tier || (m.Kind != "" && m.Kind != "chat") || cost(&m) == 0 || cost(&m) >= cost(than) {
			continue
		}
		if m.Context > 0 && m.Context < need {
			continue
		}
		if best == nil || cost(&m) < cost(best) {
			best = &m
		}
	}
	return best
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// EstimateTokens estimates the tokens of a text: about four characters each.
func EstimateTokens(s string) int { return (len(s) + 3) / 4 }

// LooksLikeCode reports whether a text holds code: a fenced block, or several
// lines that end like code.
func LooksLikeCode(s string) bool {
	if strings.Contains(s, "```") {
		return true
	}
	n := 0
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasSuffix(t, ";") || strings.HasSuffix(t, "{") || strings.HasSuffix(t, "}") || strings.HasPrefix(t, "def ") ||
			strings.HasPrefix(t, "func ") || strings.HasPrefix(t, "import ") || strings.HasPrefix(t, "#include") || strings.HasPrefix(t, "SELECT ") {
			n++
		}
	}
	return n >= 2
}
