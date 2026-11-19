// Package standin is a stand-in model provider for load tests. It speaks the
// OpenAI chat completions and Anthropic messages APIs, with and without
// streaming, and answers with the last user text it received followed by
// filler words, so a load test can check that every caller got its own
// values back. It never calls a real provider and needs no key.
package standin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Provider is the stand-in. The zero value answers at once, with a short answer.
type Provider struct {
	FirstByte time.Duration // waited before the answer starts, like a model's time to first token
	Chunks    int           // pieces of a streamed answer; 20 when zero
	ChunkGap  time.Duration // waited between pieces of a streamed answer
	Filler    int           // words added after the echo; 40 when zero

	calls atomic.Int64
}

// Calls is the number of model calls answered.
func (p *Provider) Calls() int64 { return p.calls.Load() }

func (p *Provider) chunks() int {
	if p.Chunks <= 0 {
		return 20
	}
	return p.Chunks
}

func (p *Provider) answer(body map[string]any) string {
	n := p.Filler
	if n <= 0 {
		n = 40
	}
	var b strings.Builder
	b.WriteString("You said: ")
	b.WriteString(lastUserText(body))
	b.WriteString(" .")
	for i := 0; i < n; i++ {
		b.WriteString(" ")
		b.WriteString(filler[i%len(filler)])
	}
	return b.String()
}

var filler = strings.Fields("the answer goes on with plain words so that the stream has a realistic length and every piece carries some text")

// ServeHTTP answers /v1/chat/completions and /v1/messages.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(400)
		return
	}
	p.calls.Add(1)
	if p.FirstByte > 0 {
		select {
		case <-time.After(p.FirstByte):
		case <-r.Context().Done():
			return
		}
	}
	stream, _ := body["stream"].(bool)
	model, _ := body["model"].(string)
	text := p.answer(body)
	in := tokens(body)
	switch r.URL.Path {
	case "/v1/chat/completions":
		if !stream {
			json.NewEncoder(w).Encode(map[string]any{
				"id": "chatcmpl-load", "object": "chat.completion", "created": 1, "model": model,
				"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": text}, "finish_reason": "stop"}},
				"usage":   map[string]any{"prompt_tokens": in, "completion_tokens": len(text) / 4, "total_tokens": in + len(text)/4},
			})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		send := func(v any) bool {
			b, _ := json.Marshal(v)
			if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
				return false
			}
			w.(http.Flusher).Flush()
			return true
		}
		send(map[string]any{"id": "c1", "object": "chat.completion.chunk", "model": model, "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant", "content": ""}}}})
		for _, piece := range split(text, p.chunks()) {
			if !p.wait(r) || !send(map[string]any{"id": "c1", "object": "chat.completion.chunk", "model": model, "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": piece}, "finish_reason": nil}}}) {
				return
			}
		}
		send(map[string]any{"id": "c1", "object": "chat.completion.chunk", "model": model, "choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}}})
		send(map[string]any{"id": "c1", "object": "chat.completion.chunk", "model": model, "choices": []any{}, "usage": map[string]any{"prompt_tokens": in, "completion_tokens": len(text) / 4}})
		fmt.Fprint(w, "data: [DONE]\n\n")
	case "/v1/messages":
		if !stream {
			json.NewEncoder(w).Encode(map[string]any{
				"id": "msg_load", "type": "message", "role": "assistant", "model": model,
				"content":     []any{map[string]any{"type": "text", "text": text}},
				"stop_reason": "end_turn", "stop_sequence": nil,
				"usage": map[string]any{"input_tokens": in, "output_tokens": len(text) / 4},
			})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		send := func(ev string, v any) bool {
			b, _ := json.Marshal(v)
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev, b); err != nil {
				return false
			}
			w.(http.Flusher).Flush()
			return true
		}
		send("message_start", map[string]any{"type": "message_start", "message": map[string]any{"id": "msg_load", "type": "message", "role": "assistant", "model": model, "content": []any{}, "stop_reason": nil, "usage": map[string]any{"input_tokens": in, "output_tokens": 1}}})
		send("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}})
		for _, piece := range split(text, p.chunks()) {
			if !p.wait(r) || !send("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": piece}}) {
				return
			}
		}
		send("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
		send("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": map[string]any{"output_tokens": len(text) / 4}})
		send("message_stop", map[string]any{"type": "message_stop"})
	default:
		w.WriteHeader(404)
	}
}

func (p *Provider) wait(r *http.Request) bool {
	if p.ChunkGap <= 0 {
		return true
	}
	select {
	case <-time.After(p.ChunkGap):
		return true
	case <-r.Context().Done():
		return false
	}
}

// split cuts s into n pieces of about the same length (fewer when s is short).
func split(s string, n int) []string {
	if n > len(s) {
		n = len(s)
	}
	if n <= 1 {
		return []string{s}
	}
	out := make([]string, 0, n)
	size := (len(s) + n - 1) / n
	for i := 0; i < len(s); i += size {
		end := i + size
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}

func tokens(body map[string]any) int {
	b, _ := json.Marshal(body["messages"])
	return len(b)/4 + 1
}

func lastUserText(body map[string]any) string {
	msgs, _ := body["messages"].([]any)
	for i := len(msgs) - 1; i >= 0; i-- {
		m, _ := msgs[i].(map[string]any)
		if m["role"] != "user" {
			continue
		}
		switch c := m["content"].(type) {
		case string:
			return c
		case []any:
			for _, b := range c {
				if bm, ok := b.(map[string]any); ok && bm["type"] == "text" {
					s, _ := bm["text"].(string)
					return s
				}
			}
		}
	}
	return ""
}
