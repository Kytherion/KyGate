package router

import (
	"strings"
	"testing"
)

func newTestRouter(t *testing.T) *Router {
	c, err := LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	return NewRouter(c)
}

func easy(family, model string) Features {
	return Features{Family: family, Model: model, PromptTokens: 40, LastUserTokens: 20, UserTurns: 1}
}

func TestOneTierDownWithinTheProvider(t *testing.T) {
	r := newTestRouter(t)
	for model, want := range map[string]string{
		"claude-opus-5-5":   "claude-sonnet-5-5", // frontier -> standard, the cheapest; ties keep catalog order
		"claude-sonnet-5-5": "claude-haiku-5-5",  // standard -> economy
		"claude-haiku-5-5":  "",                  // already the cheapest tier
		"gpt-5":             "o4-mini",           // frontier -> standard, the cheapest
		"gpt-4o":            "gpt-5-nano",        // standard -> economy
		"gpt-4o-mini":       "",
		"o3":                "o4-mini",
		"my-own-model":      "", // not in the catalog
	} {
		fam := "openai"
		if strings.HasPrefix(model, "claude") {
			fam = "anthropic"
		}
		d := r.Decide(easy(fam, model), "")
		if d.Model != want {
			t.Errorf("%s: would use %q (%s), want %q", model, d.Model, d.Reason, want)
		}
		if d.Model != "" && tierRank(d.Tier) != tierRank(d.RequestedTier)-1 {
			t.Errorf("%s: %s -> %s is not one tier down", model, d.RequestedTier, d.Tier)
		}
	}
}

func TestCautiousRulesStay(t *testing.T) {
	r := newTestRouter(t)
	for name, change := range map[string]func(*Features){
		"code":                 func(f *Features) { f.Code = true },
		"tools":                func(f *Features) { f.Tools = true },
		"images":               func(f *Features) { f.Unreadable = true },
		"structured output":    func(f *Features) { f.Structured = true },
		"extended reasoning":   func(f *Features) { f.Reasoning = true },
		"a long last message":  func(f *Features) { f.LastUserTokens = MaxEasyLastTokens + 1 },
		"a long context":       func(f *Features) { f.PromptTokens = MaxEasyPromptTokens + 1 },
		"a long answer":        func(f *Features) { f.MaxOutputTokens = MaxEasyOutputTokens + 1 },
		"a later turn":         func(f *Features) { f.AssistantTurns = 1; f.UserTurns = 2 },
		"a local model server": func(f *Features) { f.Local = true },
	} {
		f := easy("anthropic", "claude-opus-5-5")
		change(&f)
		if d := r.Decide(f, ""); d.Moves() || d.Reason == "" {
			t.Errorf("%s: %+v", name, d)
		}
	}
}

// A conversation keeps the decision of its first turn, both ways.
func TestDecisionSticksToTheConversation(t *testing.T) {
	r := newTestRouter(t)
	first := r.Decide(easy("anthropic", "claude-opus-5-5"), "conv-1")
	later := easy("anthropic", "claude-opus-5-5")
	later.AssistantTurns, later.UserTurns, later.Code = 1, 2, true
	if d := r.Decide(later, "conv-1"); d.Model != first.Model || !d.Sticky {
		t.Fatalf("first %+v, later %+v", first, d)
	}
	stay := r.Decide(Features{Family: "anthropic", Model: "claude-opus-5-5", Code: true, UserTurns: 1}, "conv-2")
	if d := r.Decide(easy("anthropic", "claude-opus-5-5"), "conv-2"); d.Moves() || stay.Moves() || !d.Sticky {
		t.Fatalf("a conversation that started on its model stays there: %+v", d)
	}
}

func TestLooksLikeCode(t *testing.T) {
	for s, want := range map[string]bool{
		"```go\nfmt.Println()\n```":                true,
		"int x = 1;\nreturn x;":                    true,
		"What is the capital of France?":           false,
		"Write a haiku; about the sea.\nThank you": false,
	} {
		if LooksLikeCode(s) != want {
			t.Errorf("%q", s)
		}
	}
}
