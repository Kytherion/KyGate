package pipeline_test

import (
	"encoding/json"
	"strings"
	"testing"
)

var longSystem = strings.Repeat("You are the support assistant of a shop. Answer politely, cite the order number. ", 60) // ~1,300 tokens

func anthropicWith(system any, msgs ...any) map[string]any {
	return map[string]any{"model": "claude-opus-5-5", "max_tokens": 200, "system": system, "messages": msgs}
}

func user(text string) map[string]any { return map[string]any{"role": "user", "content": text} }

func marked(v any) bool {
	b, _ := json.Marshal(v)
	return strings.Contains(string(b), `"cache_control":{"type":"ephemeral"}`)
}

// The starter policy marks the end of the system prompt and of the latest
// message, when the prompt is long enough and the client placed no marker.
func TestProviderCacheMarkers(t *testing.T) {
	h := newHarness(t, "")
	resp, _ := h.post("/v1/messages", h.keyA, anthropicWith(longSystem, user("Where is my order?")))
	if resp.Header.Get("X-KyGate-Prompt-Cache") != "marked system,conversation" {
		t.Fatalf("%q", resp.Header.Get("X-KyGate-Prompt-Cache"))
	}
	sent := h.up.lastBody()
	sys, _ := sent["system"].([]any)
	if len(sys) != 1 || !marked(sys[0]) || sys[0].(map[string]any)["text"] != longSystem {
		t.Fatalf("system %v", sent["system"])
	}
	msgs := sent["messages"].([]any)
	if !marked(msgs[len(msgs)-1]) {
		t.Fatalf("latest message %v", msgs[len(msgs)-1])
	}
	// The fingerprint is the request's own: the same request is a cache hit.
	if resp, _ := h.post("/v1/messages", h.keyA, anthropicWith(longSystem, user("Where is my order?"))); resp.Header.Get("X-KyGate-Cache") != "hit" {
		t.Fatalf("%q", resp.Header.Get("X-KyGate-Cache"))
	}
}

func TestProviderCacheMarkersLeaveOthersAlone(t *testing.T) {
	h := newHarness(t, "")
	// The client's own markers: untouched.
	own := anthropicWith([]any{map[string]any{"type": "text", "text": longSystem, "cache_control": map[string]any{"type": "ephemeral", "ttl": "1h"}}}, user("Hi"))
	resp, _ := h.post("/v1/messages", h.keyA, own)
	if resp.Header.Get("X-KyGate-Prompt-Cache") != "" || marked(h.up.lastBody()["messages"]) {
		t.Fatal("a request with its own markers is left alone")
	}
	// A short prompt: nothing worth caching.
	resp, _ = h.post("/v1/messages", h.keyA, anthropicWith("Be brief.", user("Hi")))
	if resp.Header.Get("X-KyGate-Prompt-Cache") != "" || marked(h.up.lastBody()) {
		t.Fatal("a short prompt is not marked")
	}
	// OpenAI caches by itself.
	h.post("/v1/chat/completions", h.keyA, map[string]any{"model": "gpt-4o", "messages": []any{map[string]any{"role": "system", "content": longSystem}, user("Hi")}})
	if marked(h.up.lastBody()) {
		t.Fatal("OpenAI requests are not marked")
	}
	// A reasoning block is never marked: the marker goes on the block before it.
	think := anthropicWith(longSystem, user("Plan it."), map[string]any{"role": "assistant", "content": []any{
		map[string]any{"type": "text", "text": "Here is the plan."},
		map[string]any{"type": "thinking", "thinking": "...", "signature": "sig"},
	}})
	h.post("/v1/messages", h.keyA, think)
	last := h.up.lastBody()["messages"].([]any)[1].(map[string]any)["content"].([]any)
	if !marked(last[0]) || marked(last[1]) {
		t.Fatalf("%v", last)
	}
}

func TestProviderCacheMarkersInstructionsOnlyAndOff(t *testing.T) {
	h := newHarness(t, strings.Replace(budgetPolicy(""), "provider_markers: conversation", "provider_markers: instructions", 1))
	resp, _ := h.post("/v1/messages", h.keyA, anthropicWith(longSystem, user("Where is my order?")))
	if resp.Header.Get("X-KyGate-Prompt-Cache") != "marked system" || marked(h.up.lastBody()["messages"]) {
		t.Fatalf("%q", resp.Header.Get("X-KyGate-Prompt-Cache"))
	}
	off := newHarness(t, strings.Replace(budgetPolicy(""), "  provider_markers: conversation\n", "", 1))
	off.post("/v1/messages", off.keyA, anthropicWith(longSystem, user("Where is my order?")))
	if marked(off.up.lastBody()) {
		t.Fatal("a policy that does not name provider_markers marks nothing")
	}
}
