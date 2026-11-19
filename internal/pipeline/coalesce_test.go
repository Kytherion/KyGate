package pipeline_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// Identical requests that arrive together share one model call; each caller
// gets its own values back.
func TestCoalescingSharesOneCall(t *testing.T) {
	h := newHarness(t, "")
	h.up.delay = 300 * time.Millisecond
	type result struct {
		cache, body string
		card        string
	}
	cards := []string{cardA, cardB, cardA, cardB, cardA}
	keys := []string{h.keyA, h.keyB, h.keyA, h.keyB, h.keyA}
	out := make([]result, len(cards))
	var wg sync.WaitGroup
	for i := range cards {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 20 * time.Millisecond) // the first leads
			resp, body := h.post("/v1/chat/completions", keys[i], chat("Charge card "+cards[i]+" again", false))
			out[i] = result{resp.Header.Get("X-KyGate-Cache"), body, cards[i]}
		}(i)
	}
	wg.Wait()
	if h.up.calls != 1 {
		t.Fatalf("five identical masked requests made %d model calls", h.up.calls)
	}
	coalesced := 0
	for i, r := range out {
		if !strings.Contains(r.body, "You said: Charge card "+r.card+" again") {
			t.Fatalf("request %d did not get its own card back: %s", i, r.body)
		}
		if r.cache == "coalesced" {
			coalesced++
		}
	}
	if coalesced != 4 || out[0].cache != "miss" {
		t.Fatalf("%+v", out)
	}
	for _, e := range h.events() {
		if e.Cache == "coalesced" && (e.CostUSD != 0 || e.CostAvoidedUSD <= 0) {
			t.Fatalf("a follower avoided the cost: %+v", e)
		}
	}
	// Later, the same request is a plain cache hit.
	if resp, _ := h.post("/v1/chat/completions", h.keyA, chat("Charge card "+cardA+" again", false)); resp.Header.Get("X-KyGate-Cache") != "hit" {
		t.Fatalf("%q", resp.Header.Get("X-KyGate-Cache"))
	}
}

// A follower of a stream gets the whole answer; streamed and plain requests do
// not share a call (their answers differ in form).
func TestCoalescingStreams(t *testing.T) {
	h := newHarness(t, "")
	h.up.delay = 300 * time.Millisecond
	var wg sync.WaitGroup
	texts := make([]string, 3)
	caches := make([]string, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 30 * time.Millisecond)
			stream := i < 2
			resp, body := h.post("/v1/messages", h.keyA, messages("Tell me about rivers", stream))
			caches[i] = resp.Header.Get("X-KyGate-Cache")
			if stream {
				texts[i] = streamText(t, body, true)
			} else {
				texts[i] = body
			}
		}(i)
	}
	wg.Wait()
	if h.up.calls != 2 || caches[1] != "coalesced" || caches[2] != "miss" {
		t.Fatalf("calls %d, caches %v", h.up.calls, caches)
	}
	if texts[0] != "You said: Tell me about rivers" || texts[1] != texts[0] || !strings.Contains(texts[2], "You said: Tell me about rivers") {
		t.Fatalf("%q", texts)
	}
}

// The call is detached from the leader's connection: when the leader leaves,
// its follower still gets the answer.
func TestCoalescingSurvivesTheLeaderLeaving(t *testing.T) {
	h := newHarness(t, "")
	h.up.delay = 400 * time.Millisecond
	body, _ := json.Marshal(messages("Explain tides briefly", false))
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "POST", h.gw.URL+"/v1/messages", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+h.keyA)
		req.Header.Set("Content-Type", "application/json")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	time.Sleep(30 * time.Millisecond)
	resp, out := h.post("/v1/messages", h.keyA, messages("Explain tides briefly", false))
	if resp.StatusCode != 200 || resp.Header.Get("X-KyGate-Cache") != "coalesced" || !strings.Contains(out, "You said: Explain tides briefly") || h.up.calls != 1 {
		t.Fatalf("%d %q calls %d %s", resp.StatusCode, resp.Header.Get("X-KyGate-Cache"), h.up.calls, out)
	}
}

// A leader refused before its call (here, by its budget) lets its followers
// call on their own.
func TestCoalescingLeaderRefused(t *testing.T) {
	h := newHarness(t, budgetPolicy("budgets:\n  keys:\n    bob: { daily_usd: { hard: 0.001 } }\n"))
	h.up.delay = 200 * time.Millisecond
	var wg sync.WaitGroup
	var bob, alice int
	wg.Add(2)
	go func() {
		defer wg.Done()
		resp, _ := h.post("/v1/messages", h.keyB, messages("What is a fjord?", false))
		bob = resp.StatusCode
	}()
	go func() {
		defer wg.Done()
		time.Sleep(20 * time.Millisecond)
		resp, _ := h.post("/v1/messages", h.keyA, messages("What is a fjord?", false))
		alice = resp.StatusCode
	}()
	wg.Wait()
	if bob != 429 || alice != 200 || h.up.calls != 1 {
		t.Fatalf("bob %d alice %d calls %d", bob, alice, h.up.calls)
	}
}
