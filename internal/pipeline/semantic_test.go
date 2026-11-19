package pipeline_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/provider"
	"github.com/Kytherion/KyGate/internal/store"
)

// semanticPolicy is the starter policy with the semantic cache on, in the
// given mode, against the stand-in embeddings endpoint.
func semanticPolicy(mode string, minSim string) string {
	p := string(policy.Starter())
	p = strings.Replace(p, "    enabled: false\n    mode: shadow", "    enabled: true\n    mode: "+mode, 1)
	p = strings.Replace(p, "min_similarity: 0.95", "min_similarity: "+minSim, 1)
	return p
}

func newSemanticHarness(t *testing.T, mode, minSim string) *harness {
	t.Helper()
	h := newHarness(t, semanticPolicy(mode, minSim))
	if !h.holder.Current().SemanticEnabled() {
		t.Fatal("the semantic cache must be on")
	}
	h.addEmbeddings(h.upURL)
	return h
}

// addEmbeddings connects the stand-in embeddings server through
// KYGATE_LOCAL_OLLAMA, the way 'kygate serve' reads it, so the connection gets
// the name the starter policy uses.
func (h *harness) addEmbeddings(url string) {
	env, warnings := provider.FromEnv([]string{"KYGATE_LOCAL_OLLAMA=" + url + "/v1"}, nil)
	if len(env) != 1 {
		h.t.Fatalf("KYGATE_LOCAL_OLLAMA gave no connection: %v", warnings)
	}
	h.g.Registry.Replace(append(h.g.Registry.All(), env...))
}

// waitAdmitted waits for the background write of n semantic entries.
func (h *harness) waitAdmitted(n int64) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.g.Semantic.Stats(context.Background()).Entries >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("semantic entries: %+v", h.g.Semantic.Stats(context.Background()))
}

// event returns the event of one request. The handler may still be finishing
// after the client has its answer (a shadow comparison), so it waits a little.
func (h *harness) event(id string) store.Event {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, e := range h.events() {
			if e.ID == id {
				return e
			}
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("no event %s", id)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The goal of the semantic cache: an almost identical question, even
// days later and after a restart, is answered from the cache, and the
// response says so.
func TestSemanticCacheServesALookAlikeQuestion(t *testing.T) {
	h := newSemanticHarness(t, "serve", "0.80")
	resp, _ := h.post("/v1/chat/completions", h.keyA, chat("What is the capital of France?", false))
	if resp.Header.Get("X-KyGate-Cache") != "miss" {
		t.Fatalf("first ask: %q", resp.Header.Get("X-KyGate-Cache"))
	}
	h.waitAdmitted(1)
	h.restartCache()
	h.waitAdmitted(1) // the entry is in cache.db

	calls := h.up.calls
	resp, body := h.post("/v1/chat/completions", h.keyA, chat("what's the capital of france", false))
	if resp.Header.Get("X-KyGate-Cache") != "hit" || resp.Header.Get("X-KyGate-Cache-Kind") != "semantic" {
		t.Fatalf("a look-alike question must be a semantic hit, got %q %q: %s", resp.Header.Get("X-KyGate-Cache"), resp.Header.Get("X-KyGate-Cache-Kind"), body)
	}
	if h.up.calls != calls {
		t.Fatal("a semantic hit called the model")
	}
	if !strings.Contains(body, "You said: What is the capital of France?") {
		t.Fatalf("the stored answer must be served: %s", body)
	}
	hit := h.event(resp.Header.Get("X-KyGate-Request-Id"))
	if hit.Semantic != "hit" || hit.Cache != "hit" || hit.CostAvoidedUSD <= 0 || hit.Similarity < 0.8 || !strings.Contains(hit.CacheReason, "semantic") {
		t.Fatalf("event %+v", hit)
	}

	// Streamed, the same hit is replayed as a stream.
	resp, body = h.post("/v1/chat/completions", h.keyA, chat("WHAT is the capital of France", true))
	if resp.Header.Get("X-KyGate-Cache-Kind") != "semantic" || streamText(t, body, false) != "You said: What is the capital of France?" {
		t.Fatalf("streamed semantic hit: %q %q", resp.Header.Get("X-KyGate-Cache-Kind"), streamText(t, body, false))
	}

	// The file holds sealed entries only.
	h.g.Cache.Close()
	raw := readCacheFiles(t, h.dir)
	for _, s := range []string{"capital", "France", "You said"} {
		if strings.Contains(raw, s) {
			t.Fatalf("cache.db holds %q in readable form", s)
		}
	}
}

// The hard checks stop a match the embedding alone would allow.
func TestSemanticCacheHardChecks(t *testing.T) {
	h := newSemanticHarness(t, "serve", "0.80")
	h.post("/v1/messages", h.keyA, messages("What was the population of Lyon in 2020?", false))
	h.waitAdmitted(1)
	for _, q := range []string{
		"What was the population of Lyon in 2021?",     // numbers
		"What was not the population of Lyon in 2020?", // negation
		"What was the population of Paris in 2020?",    // words
	} {
		resp, _ := h.post("/v1/messages", h.keyA, messages(q, false))
		if resp.Header.Get("X-KyGate-Cache") == "hit" {
			t.Fatalf("%q must not reuse the stored answer", q)
		}
	}
	if st := h.g.Semantic.Stats(context.Background()); st.Hits != 0 {
		t.Fatalf("stats %+v", st)
	}
}

// The scope is one virtual key, the conversation before the last message must
// be identical, and a request with a finding or a tool is not eligible.
func TestSemanticCacheIsNarrow(t *testing.T) {
	h := newSemanticHarness(t, "serve", "0.80")
	h.post("/v1/chat/completions", h.keyA, chat("How do I sort a list in Python?", false))
	h.waitAdmitted(1)

	// Another key.
	if resp, _ := h.post("/v1/chat/completions", h.keyB, chat("how do I sort a list in python", false)); resp.Header.Get("X-KyGate-Cache") == "hit" {
		t.Fatal("the semantic scope is the key")
	}
	// Another system prompt.
	other := chat("how do I sort a list in python", false)
	other["messages"].([]any)[0].(map[string]any)["content"] = "You are a poet."
	if resp, _ := h.post("/v1/chat/completions", h.keyA, other); resp.Header.Get("X-KyGate-Cache") == "hit" {
		t.Fatal("everything before the last message must match")
	}
	// A finding: not eligible.
	resp, _ := h.post("/v1/chat/completions", h.keyA, chat("How do I sort a list in Python? card "+cardA, false))
	if e := h.event(resp.Header.Get("X-KyGate-Request-Id")); e.Semantic != "" {
		t.Fatalf("a request with a finding is not eligible: %+v", e)
	}
	// Tools: not eligible.
	withTools := chat("how do I sort a list in python", false)
	withTools["tools"] = []any{map[string]any{"type": "function", "function": map[string]any{"name": "run"}}}
	resp, _ = h.post("/v1/chat/completions", h.keyA, withTools)
	if e := h.event(resp.Header.Get("X-KyGate-Request-Id")); e.Semantic != "" {
		t.Fatalf("a request with tools is not eligible: %+v", e)
	}
	// The same key and context: a hit. (The exact text above is now in the
	// exact cache, which is shared across the organization, so use another.)
	if resp, _ := h.post("/v1/chat/completions", h.keyA, chat("How do I sort a list in Python", false)); resp.Header.Get("X-KyGate-Cache-Kind") != "semantic" {
		t.Fatalf("want a semantic hit, got %q", resp.Header.Get("X-KyGate-Cache"))
	}
}

// Shadow mode changes nothing: the model answers, and the event records the
// hit it would have served and whether the answers agreed.
func TestSemanticShadowMode(t *testing.T) {
	h := newSemanticHarness(t, "shadow", "0.95")
	h.post("/v1/chat/completions", h.keyA, chat("What is the capital of France?", false))
	h.waitAdmitted(1)
	calls := h.up.calls
	resp, body := h.post("/v1/chat/completions", h.keyA, chat("what is the capital of france", false))
	if resp.Header.Get("X-KyGate-Cache") != "miss" || h.up.calls != calls+1 {
		t.Fatalf("shadow mode must call the model: %q", resp.Header.Get("X-KyGate-Cache"))
	}
	if !strings.Contains(body, "You said: what is the capital of france") {
		t.Fatalf("shadow mode must return the real answer: %s", body)
	}
	e := h.event(resp.Header.Get("X-KyGate-Request-Id"))
	if e.Semantic != "would_hit" || e.SemanticCheck != "agree" || e.CostAvoidedUSD != 0 {
		t.Fatalf("event %+v", e)
	}
	tot, err := h.db.Totals(context.Background(), store.Range{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if tot.SemanticWouldHit != 1 || tot.SemanticAgree != 1 || tot.SemanticWouldUSD <= 0 || tot.SemanticLookups != 2 {
		t.Fatalf("totals %+v", tot)
	}
}

// The semantic cache fails open: with the embeddings server down, requests
// are served and the error is recorded.
func TestSemanticCacheFailsOpen(t *testing.T) {
	h := newHarness(t, semanticPolicy("serve", "0.80"))
	down := httptest.NewServer(nil)
	down.Close()
	h.addEmbeddings(down.URL)
	resp, body := h.post("/v1/chat/completions", h.keyA, chat("What is the capital of France?", false))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if e := h.event(resp.Header.Get("X-KyGate-Request-Id")); e.Semantic != "error" || e.Outcome != "ok" {
		t.Fatalf("event %+v", e)
	}
}
