package pipeline

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Kytherion/KyGate/internal/ingress"
	"github.com/Kytherion/KyGate/internal/mask"
	"github.com/Kytherion/KyGate/internal/router"
)

// num reads a JSON number decoded with UseNumber, or a float64.
func num(v any) int64 {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			f, _ := n.Float64()
			return int64(f)
		}
		return i
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func arr(v any) []any {
	a, _ := v.([]any)
	return a
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// usageOf normalizes the usage block of a response.
func usageOf(family ingress.Family, u map[string]any) router.Usage {
	if u == nil {
		return router.Usage{}
	}
	if family == ingress.Anthropic {
		return router.Usage{
			Input:       num(u["input_tokens"]),
			CachedInput: num(u["cache_read_input_tokens"]),
			CacheWrite:  num(u["cache_creation_input_tokens"]),
			Output:      num(u["output_tokens"]),
		}
	}
	prompt := num(u["prompt_tokens"])
	cached := num(obj(u["prompt_tokens_details"])["cached_tokens"])
	return router.Usage{Input: prompt - cached, CachedInput: cached, Output: num(u["completion_tokens"])}
}

// clean reports whether an answer is a clean completion, the only kind that
// may enter the cache: no error, no truncation, no refusal (architecture §3.4).
func clean(family ingress.Family, endpoint ingress.Endpoint, body map[string]any) bool {
	switch endpoint {
	case ingress.Embeddings:
		return len(arr(body["data"])) > 0
	case ingress.CountTokens:
		return false
	}
	if family == ingress.Anthropic {
		switch str(body["stop_reason"]) {
		case "end_turn", "tool_use", "stop_sequence":
			return str(body["type"]) == "message"
		}
		return false
	}
	choices := arr(body["choices"])
	if len(choices) == 0 {
		return false
	}
	for _, c := range choices {
		cm := obj(c)
		switch str(cm["finish_reason"]) {
		case "stop", "tool_calls", "function_call":
		default:
			return false
		}
		if r := obj(cm["message"])["refusal"]; r != nil && str(r) != "" {
			return false
		}
	}
	return true
}

// rehydrate puts real values back into a non-streamed answer, in place.
func rehydrate(family ingress.Family, body map[string]any, vm *mask.ValueMap) {
	if vm == nil || vm.Len() == 0 {
		return
	}
	plain := func(s string) string { return vm.Rehydrate(s, false) }
	if family == ingress.Anthropic {
		for _, b := range arr(body["content"]) {
			bm := obj(b)
			switch str(bm["type"]) {
			case "text":
				bm["text"] = plain(str(bm["text"]))
			case toolUse, serverToolUse, mcpToolUse:
				// As in a stream, whose input_json_delta events are put back
				// for every kind of tool use.
				if in, ok := bm["input"]; ok {
					bm["input"] = mapStrings(in, plain)
				}
			}
		}
		return
	}
	for _, c := range arr(body["choices"]) {
		msg := obj(obj(c)["message"])
		if msg == nil {
			continue
		}
		if s, ok := msg["content"].(string); ok {
			msg["content"] = plain(s)
		}
		if s, ok := msg["refusal"].(string); ok {
			msg["refusal"] = plain(s)
		}
		for _, tc := range arr(msg["tool_calls"]) {
			if fn := obj(obj(tc)["function"]); fn != nil {
				if s, ok := fn["arguments"].(string); ok {
					fn["arguments"] = vm.Rehydrate(s, true)
				}
			}
			if cu := obj(obj(tc)["custom"]); cu != nil {
				if s, ok := cu["input"].(string); ok {
					cu["input"] = plain(s)
				}
			}
		}
	}
}

// The Anthropic content blocks whose input the model writes.
const (
	toolUse       = "tool_use"
	serverToolUse = "server_tool_use"
	mcpToolUse    = "mcp_tool_use"
)

// mapStrings replaces every string inside v, at every depth, lists inside
// lists included, with f of it. Maps and lists change in place; the result is
// v, or f(v) for a string.
func mapStrings(v any, f func(string) string) any {
	switch t := v.(type) {
	case string:
		return f(t)
	case map[string]any:
		for k, e := range t {
			t[k] = mapStrings(e, f)
		}
	case []any:
		for i, e := range t {
			t[i] = mapStrings(e, f)
		}
	}
	return v
}

// writeError answers in the caller's wire format.
func writeError(w http.ResponseWriter, family ingress.Family, status int, kind, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", "")
	var body any
	if family == ingress.Anthropic {
		body = map[string]any{"type": "error", "error": map[string]any{"type": anthropicType(status, kind), "message": msg}}
	} else {
		body = map[string]any{"error": map[string]any{"message": msg, "type": openaiType(status, kind), "param": nil, "code": kind}}
	}
	b := ingress.Marshal(body)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	w.Write(b)
}

func anthropicType(status int, kind string) string {
	switch status {
	case 400, 413:
		return "invalid_request_error"
	case 401:
		return "authentication_error"
	case 403:
		return "permission_error"
	case 404:
		return "not_found_error"
	case 429:
		return "rate_limit_error"
	case 503, 529:
		return "overloaded_error"
	}
	return "api_error"
}

func openaiType(status int, kind string) string {
	switch status {
	case 400, 413, 404:
		return "invalid_request_error"
	case 401:
		return "authentication_error"
	case 403:
		return "permission_error"
	case 429:
		return "rate_limit_exceeded"
	}
	return "api_error"
}
