package pipeline_test

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/provider"
)

// useUpstream points both connections at handler instead of the stand-in provider.
func (h *harness) useUpstream(handler http.HandlerFunc) {
	h.t.Helper()
	srv := httptest.NewServer(handler)
	h.t.Cleanup(srv.Close)
	h.g.Registry.Replace([]*provider.Connection{
		provider.NewConnection("openai", provider.OpenAI, srv.URL, "sk-openai-1", "env"),
		provider.NewConnection("anthropic", provider.Anthropic, srv.URL, "sk-ant-1", "env"),
	})
}

func upstreamText(h *harness) string {
	b, _ := json.Marshal(h.up.lastBody())
	return string(b)
}

const testSecret = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"

// Every field that reaches the model is inspected, not only the messages'
// text: a predicted output, a call in the deprecated function form, tool and
// schema definitions, metadata (goal G4).
func TestEveryFieldThatReachesTheModelIsInspected(t *testing.T) {
	h := newHarness(t, "") // the starter policy: SECRET block, CREDIT_CARD mask
	body := map[string]any{"model": "gpt-4o-mini",
		"messages": []any{
			map[string]any{"role": "user", "content": "Update the file"},
			map[string]any{"role": "assistant", "content": nil, "function_call": map[string]any{"name": "pay", "arguments": `{"card":"` + cardA + `"}`}},
			map[string]any{"role": "function", "name": "pay", "content": "ok"},
			map[string]any{"role": "user", "content": "thanks"},
		},
		"prediction": map[string]any{"type": "content", "content": "card = \"" + cardA + "\""},
		"metadata":   map[string]any{"note": "card " + cardA},
		"tools": []any{map[string]any{"type": "function", "function": map[string]any{"name": "lookup", "description": "Look a customer up",
			"parameters": map[string]any{"type": "object", "properties": map[string]any{
				"name": map[string]any{"type": "string", "description": "the customer, such as the one with card " + cardA}}}}}},
	}
	resp, out := h.post("/v1/chat/completions", h.keyA, body)
	up := upstreamText(h)
	if resp.StatusCode != 200 || strings.Contains(up, cardA) || strings.Count(up, "[CREDIT_CARD_1]") != 4 || resp.Header.Get("X-KyGate-Masked") != "4" {
		t.Fatalf("%d masked %q: %s\n%s", resp.StatusCode, resp.Header.Get("X-KyGate-Masked"), up, out)
	}
	// A secret in a tool's description is blocked like one in a message.
	body = map[string]any{"model": "gpt-4o-mini", "messages": []any{map[string]any{"role": "user", "content": "hi"}},
		"tools": []any{map[string]any{"type": "function", "function": map[string]any{"name": "lookup", "description": "Authenticate with " + testSecret}}}}
	calls := h.up.calls
	if resp, out := h.post("/v1/chat/completions", h.keyA, body); resp.StatusCode != 403 || resp.Header.Get("X-KyGate-Blocked") != "SECRET" || h.up.calls != calls {
		t.Fatalf("%d %q %s", resp.StatusCode, resp.Header.Get("X-KyGate-Blocked"), out)
	}
	// Anthropic: tool definitions, metadata, and stop sequences. A remote MCP
	// server's own credential goes to the provider on purpose.
	body = map[string]any{"model": "claude-opus-5-5", "max_tokens": 10, "messages": []any{map[string]any{"role": "user", "content": "hi"}},
		"tools":          []any{map[string]any{"name": "lookup", "description": "the card " + cardA, "input_schema": map[string]any{"type": "object"}}},
		"metadata":       map[string]any{"user_id": "card " + cardA},
		"stop_sequences": []any{cardA},
		"mcp_servers":    []any{map[string]any{"type": "url", "url": "https://mcp.example.com/sse", "name": "docs", "authorization_token": testSecret}},
	}
	resp, out = h.post("/v1/messages", h.keyA, body)
	up = upstreamText(h)
	if resp.StatusCode != 200 || strings.Contains(up, cardA) || strings.Count(up, "[CREDIT_CARD_1]") != 3 || !strings.Contains(up, testSecret) {
		t.Fatalf("%d: %s\n%s", resp.StatusCode, up, out)
	}
}

// A participant's name cannot take a placeholder (the provider checks it
// against a pattern): a value the policy masks there refuses the request.
func TestNameCannotTakeAPlaceholder(t *testing.T) {
	h := newHarness(t, "")
	calls := h.up.calls
	resp, body := h.post("/v1/chat/completions", h.keyA, map[string]any{"model": "gpt-4o-mini", "messages": []any{
		map[string]any{"role": "user", "name": "4111111111111111", "content": "hello"}}})
	if resp.StatusCode != 403 || resp.Header.Get("X-KyGate-Blocked") != "CREDIT_CARD" || !strings.Contains(body, "messages.0.name") || h.up.calls != calls {
		t.Fatalf("%d %q %s", resp.StatusCode, resp.Header.Get("X-KyGate-Blocked"), body)
	}
	if resp, _ := h.post("/v1/chat/completions", h.keyA, map[string]any{"model": "gpt-4o-mini", "messages": []any{
		map[string]any{"role": "user", "name": "alice_martin", "content": "hello"}}}); resp.StatusCode != 200 {
		t.Fatalf("a name with nothing to mask goes through: %d", resp.StatusCode)
	}
}

// Text that already has the shape of a placeholder of a masked type is
// masked as a literal: the model can tell it from the value, the caller gets
// it back as written, and the masking is the same at every turn.
func TestPlaceholderShapedTextIsKeptApartFromValues(t *testing.T) {
	h := newHarness(t, "")
	text := "Fill [CREDIT_CARD_1] with card " + cardA
	resp, body := h.post("/v1/chat/completions", h.keyA, chat(text, false))
	first := lastUserText(h.up.lastBody())
	if first != "Fill [LITERAL_1] with card [CREDIT_CARD_1]" || resp.Header.Get("X-KyGate-Masked") != "1" {
		t.Fatalf("the model saw %q (masked %q)", first, resp.Header.Get("X-KyGate-Masked"))
	}
	if !strings.Contains(body, "You said: "+text) {
		t.Fatalf("the caller must get both back as written: %s", body)
	}
	// The next turn resends the answer: the first turn is masked as before.
	turn2 := map[string]any{"model": "gpt-4o-mini", "messages": []any{
		map[string]any{"role": "system", "content": "You write payment reminders."},
		map[string]any{"role": "user", "content": text},
		map[string]any{"role": "assistant", "content": "You said: " + text},
		map[string]any{"role": "user", "content": "Again"},
	}}
	h.post("/v1/chat/completions", h.keyA, turn2)
	msgs := h.up.lastBody()["messages"].([]any)
	if msgs[1].(map[string]any)["content"] != first || msgs[2].(map[string]any)["content"] != "You said: "+first {
		t.Fatalf("earlier turns changed: %v", msgs)
	}
	// A type the policy does not mask is left as it is.
	h.post("/v1/chat/completions", h.keyA, chat("Step [STEP_1], then [EMAIL_1]", false))
	if got := lastUserText(h.up.lastBody()); got != "Step [STEP_1], then [EMAIL_1]" {
		t.Fatalf("%q", got)
	}
}

// Headers that change an answer are part of the fingerprint: an answer made
// with one beta feature is never served to a request with another.
func TestAnswerChangingHeadersAreInTheFingerprint(t *testing.T) {
	h := newHarness(t, "")
	get := func(hdr ...string) string {
		resp, _ := h.post("/v1/messages", h.keyA, messages("beta check", false), hdr...)
		return resp.Header.Get("X-KyGate-Cache")
	}
	for i, c := range []struct {
		hdr  []string
		want string
	}{
		{nil, "miss"},
		{nil, "hit"},
		{[]string{"Anthropic-Beta", "feature-a,feature-b"}, "miss"},
		{[]string{"Anthropic-Beta", "feature-b, feature-a"}, "hit"}, // the same flags, in another order
		{[]string{"Anthropic-Version", "2023-06-01"}, "hit"},        // the default version, named
		{[]string{"Anthropic-Version", "2099-01-01"}, "miss"},
	} {
		if got := get(c.hdr...); got != c.want {
			t.Fatalf("request %d %v: %q, want %q", i, c.hdr, got, c.want)
		}
	}
}

// cache.exact.scope: project shares entries within a project; a key in no
// project shares the organization's.
func TestCacheScopeProject(t *testing.T) {
	pol := strings.Replace(string(policy.Starter()), "    scope: org  ", "    scope: project", 1)
	if pol == string(policy.Starter()) {
		t.Fatal("the starter policy's exact-cache scope line changed")
	}
	h := newHarness(t, pol)
	placeB(t, h, nil) // bob in project ledger; alice in none
	for i, c := range []struct {
		key, want string
	}{{h.keyA, "miss"}, {h.keyB, "miss"}, {h.keyB, "hit"}, {h.keyA, "hit"}} {
		if resp, _ := h.post("/v1/chat/completions", c.key, chat("scope check", false)); resp.Header.Get("X-KyGate-Cache") != c.want {
			t.Fatalf("request %d: %q, want %q", i, resp.Header.Get("X-KyGate-Cache"), c.want)
		}
	}
}

// The key is checked before the body is read: an unknown key gets 401
// whatever it sends.
func TestUnknownKeyIsRefusedBeforeTheBody(t *testing.T) {
	h := newHarness(t, "")
	req, _ := http.NewRequest("POST", h.gw.URL+"/v1/chat/completions", strings.NewReader("{not json"))
	req.Header.Set("Authorization", "Bearer kg-unknown")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("%d", resp.StatusCode)
	}
}

// A provider that cannot be reached: the caller gets a plain message, the
// event keeps the details.
func TestUnreachableProviderDetailsStayInTheEvent(t *testing.T) {
	h := newHarness(t, "")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	h.g.Registry.Replace([]*provider.Connection{provider.NewConnection("anthropic", provider.Anthropic, "http://"+addr, "sk-ant-1", "env")})
	resp, body := h.post("/v1/messages", h.keyA, messages("hello", false))
	if resp.StatusCode != 502 || strings.Contains(body, addr) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if e := h.event(resp.Header.Get("X-KyGate-Request-Id")); !strings.Contains(e.Reason, addr) {
		t.Fatalf("the event keeps the details: %q", e.Reason)
	}
}
