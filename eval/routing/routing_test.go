// Package routing is the routing quality gate (OP-4). The router
// runs in shadow mode with cautious rules, so the gate is about the rules: a
// request that needs the requested model must never be called easy, and
// short plain questions should be. Requests are parsed by the same ingress
// code as live traffic.
//
// The rules see shapes, not meaning: a short question that is hard ("prove
// that...") is called easy. Those are listed apart, as a known limit that the
// shadow figures and a quality check must settle before any enforcement.
package routing

import (
	"strings"
	"testing"

	"github.com/Kytherion/KyGate/internal/ingress"
	"github.com/Kytherion/KyGate/internal/router"
)

type sample struct {
	name string
	body map[string]any
	kind string // easy: should move one tier down; hard: must stay; limit: easy for the rules, hard in truth
}

func anth(content any, extra ...any) map[string]any {
	b := map[string]any{"model": "claude-opus-5-5", "max_tokens": 1024, "messages": []any{map[string]any{"role": "user", "content": content}}}
	for i := 0; i+1 < len(extra); i += 2 {
		b[extra[i].(string)] = extra[i+1]
	}
	return b
}

func oai(content string, extra ...any) map[string]any {
	b := map[string]any{"model": "gpt-5", "messages": []any{map[string]any{"role": "user", "content": content}}}
	for i := 0; i+1 < len(extra); i += 2 {
		b[extra[i].(string)] = extra[i+1]
	}
	return b
}

var long = strings.Repeat("The quarterly report covers revenue, costs, hiring, and the roadmap in detail. ", 200)

var corpus = []sample{
	// Easy: short plain questions and tasks.
	{"capital", anth("What is the capital of Austria?"), "easy"},
	{"translate", anth("Translate 'good morning, how are you?' into French."), "easy"},
	{"email", anth("Write a two-line polite reply declining a meeting on Friday."), "easy"},
	{"definition", oai("What does HTTP status 404 mean?"), "easy"},
	{"summary short", oai("Summarize in one sentence: the meeting moved from Monday to Tuesday because the room was booked."), "easy"},
	{"french", anth("Quelle est la différence entre un bail et un contrat de location ?"), "easy"},
	{"list", oai("Give me five name ideas for a bakery."), "easy"},
	{"rewrite", anth("Rewrite more politely: send me the file now."), "easy"},
	// Hard: the rules must keep these on the requested model.
	{"code block", anth("Why does this panic?\n```go\nvar m map[string]int\nm[\"a\"] = 1\n```"), "hard"},
	{"code lines", oai("Refactor:\nfunc add(a, b int) int {\n  return a + b;\n}"), "hard"},
	{"tools", anth("What's the weather in Paris?", "tools", []any{map[string]any{"name": "weather", "input_schema": map[string]any{"type": "object"}}}), "hard"},
	{"openai tools", oai("Book a table for two.", "tools", []any{map[string]any{"type": "function", "function": map[string]any{"name": "book"}}}), "hard"},
	{"image", anth([]any{map[string]any{"type": "image", "source": map[string]any{"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}}, map[string]any{"type": "text", "text": "What is in this picture?"}}), "hard"},
	{"long document", anth("Summarize this report:\n" + long), "hard"},
	{"json schema", oai("Extract the name and age from: Alice, 31.", "response_format", map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "p", "schema": map[string]any{"type": "object"}}}), "hard"},
	{"thinking", anth("Plan a three-day trip to Rome.", "thinking", map[string]any{"type": "enabled", "budget_tokens": 4000}), "hard"},
	{"reasoning effort", oai("Plan a three-day trip to Rome.", "reasoning_effort", "high"), "hard"},
	{"long answer", anth("Write a story about a lighthouse.", "max_tokens", 32000), "hard"},
	{"later turn", map[string]any{"model": "claude-opus-5-5", "max_tokens": 1024, "messages": []any{
		map[string]any{"role": "user", "content": "Let's design a database schema for a shop."},
		map[string]any{"role": "assistant", "content": "Sure. Which entities do you need?"},
		map[string]any{"role": "user", "content": "Customers and orders."},
	}}, "hard"},
	{"already economy", map[string]any{"model": "claude-haiku-5-5", "max_tokens": 100, "messages": []any{map[string]any{"role": "user", "content": "Hi"}}}, "hard"},
	// Known limit: short, plain, and hard.
	{"proof", anth("Prove that the square root of 2 is irrational."), "limit"},
	{"riddle", oai("A bat and a ball cost 1.10 in total; the bat costs 1.00 more than the ball. How much is the ball?"), "limit"},
}

func TestRoutingRules(t *testing.T) {
	cat, err := router.LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	r := router.NewRouter(cat)
	var easyMoved, easy, hardMoved, limitMoved int
	for _, s := range corpus {
		fam, ep := ingress.Anthropic, ingress.Messages
		if strings.HasPrefix(s.body["model"].(string), "gpt") {
			fam, ep = ingress.OpenAI, ingress.Chat
		}
		req, err := ingress.Parse(fam, ep, s.body)
		if err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		d := r.Decide(router.FeaturesOf(req, false, nil), "")
		switch s.kind {
		case "easy":
			easy++
			if d.Moves() {
				easyMoved++
			} else {
				t.Logf("easy, stays: %s (%s)", s.name, d.Reason)
			}
		case "hard":
			if d.Moves() {
				hardMoved++
				t.Errorf("hard, called easy: %s -> %s", s.name, d.Model)
			}
		case "limit":
			if d.Moves() {
				limitMoved++
			}
		}
	}
	t.Logf("easy requests moved: %d/%d; hard requests moved: %d; known limit (short and hard) moved: %d", easyMoved, easy, hardMoved, limitMoved)
	// Floors: no hard request is ever called easy; most easy ones are.
	if hardMoved != 0 {
		t.Errorf("hard requests called easy: %d (floor 0)", hardMoved)
	}
	if easyMoved*10 < easy*8 {
		t.Errorf("easy requests moved: %d/%d (floor 80%%)", easyMoved, easy)
	}
}
