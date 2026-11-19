package pipeline

// Provider prompt-cache markers (OP-2). Anthropic bills the
// repeated beginning of a prompt at about a tenth of the input price, but
// only up to a marker (cache_control) that the request places; writing that
// beginning costs about a quarter more, once. For a request that carries no
// marker of its own, KyGate adds them, by policy:
//
//   - instructions: at the end of the tools and of the system prompt, which
//     every request with the same instructions repeats;
//   - conversation: those, and at the end of the latest message, so that the
//     next turn of the conversation reads everything before it from the cache.
//
// A marker is placed only after a prefix long enough to be cached (about
// 1,024 tokens). The markers are deterministic, so the prefix stays
// byte-identical turn after turn. They are added after the cache stage: the
// fingerprint is the request's own. Reasoning blocks are never marked.
// OpenAI caches long prefixes by itself and needs nothing.

import (
	"encoding/json"

	"github.com/Kytherion/KyGate/internal/ingress"
)

// minCacheTokens is the shortest prefix worth marking.
const minCacheTokens = 1024

// addCacheMarkers marks the request, and returns where it put markers.
func (g *Gateway) addCacheMarkers(sc *serveCtx) []string {
	mode := sc.pol.Cache.ProviderMarkers
	req := sc.req
	if mode == "" || mode == "off" || req.Family != ingress.Anthropic || req.Endpoint != ingress.Messages {
		return nil
	}
	b := req.Body
	if hasCacheControl(b) {
		return nil // the client places its own markers
	}
	marker := func() map[string]any { return map[string]any{"type": "ephemeral"} }
	var placed []string
	prefix := 0

	if tools, ok := b["tools"].([]any); ok && len(tools) > 0 {
		prefix += tokensOf(tools)
		if prefix >= minCacheTokens {
			if t, ok := tools[len(tools)-1].(map[string]any); ok {
				t["cache_control"] = marker()
				placed = append(placed, "tools")
			}
		}
	}
	switch sys := b["system"].(type) {
	case string:
		prefix += (len(sys) + 3) / 4
		if sys != "" && prefix >= minCacheTokens {
			b["system"] = []any{map[string]any{"type": "text", "text": sys, "cache_control": marker()}}
			placed = append(placed, "system")
		}
	case []any:
		prefix += tokensOf(sys)
		if len(sys) > 0 && prefix >= minCacheTokens {
			if blk, ok := sys[len(sys)-1].(map[string]any); ok {
				blk["cache_control"] = marker()
				placed = append(placed, "system")
			}
		}
	}
	if mode != "conversation" {
		return placed
	}
	msgs, _ := b["messages"].([]any)
	if len(msgs) == 0 {
		return placed
	}
	prefix += tokensOf(msgs)
	if prefix < minCacheTokens {
		return placed
	}
	last, ok := msgs[len(msgs)-1].(map[string]any)
	if !ok {
		return placed
	}
	switch c := last["content"].(type) {
	case string:
		if c != "" {
			last["content"] = []any{map[string]any{"type": "text", "text": c, "cache_control": marker()}}
			placed = append(placed, "conversation")
		}
	case []any:
		for i := len(c) - 1; i >= 0; i-- {
			blk, ok := c[i].(map[string]any)
			if !ok {
				continue
			}
			switch blk["type"] {
			case "thinking", "redacted_thinking":
				continue // reasoning blocks pass through untouched
			}
			blk["cache_control"] = marker()
			placed = append(placed, "conversation")
			break
		}
	}
	return placed
}

// hasCacheControl reports whether the client placed any marker.
func hasCacheControl(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		if _, ok := t["cache_control"]; ok {
			return true
		}
		for _, e := range t {
			if hasCacheControl(e) {
				return true
			}
		}
	case []any:
		for _, e := range t {
			if hasCacheControl(e) {
				return true
			}
		}
	}
	return false
}

// tokensOf estimates the tokens of a part of the request: about four
// characters each, from its JSON.
func tokensOf(v any) int {
	b, _ := json.Marshal(v)
	return (len(b) + 3) / 4
}
