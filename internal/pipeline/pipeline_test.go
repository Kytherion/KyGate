package pipeline_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/Kytherion/KyGate/internal/cache"
	"github.com/Kytherion/KyGate/internal/control"
	"github.com/Kytherion/KyGate/internal/events"
	"github.com/Kytherion/KyGate/internal/identity"
	"github.com/Kytherion/KyGate/internal/limits"
	"github.com/Kytherion/KyGate/internal/pipeline"
	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/provider"
	"github.com/Kytherion/KyGate/internal/router"
	"github.com/Kytherion/KyGate/internal/store"
	"github.com/Kytherion/KyGate/internal/store/sqlite"
	"github.com/Kytherion/KyGate/internal/telemetry"
)

// fakeProvider stands in for OpenAI and Anthropic. It answers "You said: "
// followed by the last user text, so a test can see what the model saw and
// whether placeholders came back as real values.
type fakeProvider struct {
	mu         sync.Mutex
	embedCalls int
	bodies     []map[string]any
	keys       []string
	failKeys   map[string]int // key -> status to answer with
	calls      int
	headers    []http.Header // what each model call received
	answer     string        // when set, the answer instead of the echo (it may hold placeholders)
	delay      time.Duration // waited before answering, so that requests overlap
}

func (f *fakeProvider) lastBody() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bodies[len(f.bodies)-1]
}

func (f *fakeProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/embeddings" {
		// A stand-in embeddings model: a bag of lowercased words. It is not
		// counted as a model call.
		var in struct {
			Input []string `json:"input"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.embedCalls++
		f.mu.Unlock()
		data := []any{}
		for i, s := range in.Input {
			data = append(data, map[string]any{"object": "embedding", "index": i, "embedding": bagOfWords(s)})
		}
		json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
		return
	}
	key := r.Header.Get("X-Api-Key")
	if key == "" {
		key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	f.calls++
	f.headers = append(f.headers, r.Header.Clone())
	f.keys = append(f.keys, key)
	f.bodies = append(f.bodies, body)
	fail := f.failKeys[key]
	delay := f.delay
	f.mu.Unlock()
	time.Sleep(delay)
	if fail != 0 {
		w.WriteHeader(fail)
		w.Write([]byte(`{"error":{"message":"rate limited"}}`))
		return
	}
	stream, _ := body["stream"].(bool)
	text := "You said: " + lastUserText(body)
	if f.answer != "" {
		text = f.answer
	}
	model, _ := body["model"].(string)
	switch r.URL.Path {
	case "/v1/chat/completions":
		if !stream {
			json.NewEncoder(w).Encode(map[string]any{
				"id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": model,
				"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": text}, "finish_reason": "stop"}},
				"usage":   map[string]any{"prompt_tokens": 1000, "completion_tokens": 100, "prompt_tokens_details": map[string]any{"cached_tokens": 200}},
			})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		send := func(v any) { b, _ := json.Marshal(v); fmt.Fprintf(w, "data: %s\n\n", b); w.(http.Flusher).Flush() }
		send(map[string]any{"id": "c1", "object": "chat.completion.chunk", "model": model, "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant", "content": ""}}}})
		// Split the answer in three-byte pieces, so placeholders arrive split.
		for i := 0; i < len(text); i += 3 {
			end := i + 3
			if end > len(text) {
				end = len(text)
			}
			send(map[string]any{"id": "c1", "object": "chat.completion.chunk", "model": model, "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": text[i:end]}, "finish_reason": nil}}})
		}
		send(map[string]any{"id": "c1", "object": "chat.completion.chunk", "model": model, "choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}}})
		send(map[string]any{"id": "c1", "object": "chat.completion.chunk", "model": model, "choices": []any{}, "usage": map[string]any{"prompt_tokens": 50, "completion_tokens": 5}})
		fmt.Fprint(w, "data: [DONE]\n\n")
	case "/v1/messages":
		if !stream {
			json.NewEncoder(w).Encode(map[string]any{
				"id": "msg_1", "type": "message", "role": "assistant", "model": model,
				"content":     []any{map[string]any{"type": "text", "text": text}},
				"stop_reason": "end_turn", "stop_sequence": nil,
				"usage": map[string]any{"input_tokens": 100, "output_tokens": 20, "cache_read_input_tokens": 1000, "cache_creation_input_tokens": 0},
			})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		send := func(ev string, v any) {
			b, _ := json.Marshal(v)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev, b)
			w.(http.Flusher).Flush()
		}
		send("message_start", map[string]any{"type": "message_start", "message": map[string]any{"id": "msg_2", "type": "message", "role": "assistant", "model": model, "content": []any{}, "stop_reason": nil, "usage": map[string]any{"input_tokens": 10, "output_tokens": 1}}})
		send("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}})
		for i := 0; i < len(text); i += 4 {
			end := i + 4
			if end > len(text) {
				end = len(text)
			}
			send("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": text[i:end]}})
		}
		send("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
		send("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": map[string]any{"output_tokens": 7}})
		send("message_stop", map[string]any{"type": "message_stop"})
	default:
		w.WriteHeader(404)
	}
}

func bagOfWords(s string) []float32 {
	v := make([]float32, 256)
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		h := fnv.New32a()
		h.Write([]byte(w))
		v[h.Sum32()%256]++
	}
	return v
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
					return bm["text"].(string)
				}
			}
		}
	}
	return ""
}

type harness struct {
	t       *testing.T
	gw      *httptest.Server
	up      *fakeProvider
	db      *sqlite.DB
	spool   *events.Spool
	keyA    string
	keyB    string
	polPath string
	holder  *policy.Holder
	keys    *identity.Resolver
	g       *pipeline.Gateway
	dir     string
	upURL   string
}

// openCache wires the exact cache as 'kygate serve' does: in memory, and in
// cache.db when the policy keeps it on disk.
func openCache(t *testing.T, dir string, p *policy.Policy) *cache.Exact {
	t.Helper()
	c := cache.New(int64(p.Cache.Exact.MaxSizeMB) << 20)
	c.UseDisk(func() (store.CacheStore, error) { return sqlite.OpenCache(filepath.Join(dir, control.CacheFile)) }, t.Logf)
	if err := c.Configure(cache.Settings{MaxMemoryBytes: int64(p.Cache.Exact.MaxSizeMB) << 20, Persist: p.CachePersist(),
		MaxDiskBytes: int64(p.Cache.Exact.MaxDiskMB) << 20}); err != nil {
		t.Logf("cache file unavailable: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// restartCache stands for a restart of KyGate: the in-process cache is lost,
// pending writes are flushed, and the cache file is opened again.
func (h *harness) restartCache() {
	h.t.Helper()
	h.g.Cache.Close()
	h.g.Cache = openCache(h.t, h.dir, h.holder.Current())
	h.g.Semantic = cache.NewSemantic(h.g.Cache.SemanticStore, h.t.Logf)
}

func newHarness(t *testing.T, policyYAML string, extraKeys ...string) *harness {
	t.Helper()
	dir := t.TempDir()
	db, err := sqlite.Open(filepath.Join(dir, "kygate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	polPath := filepath.Join(dir, "policy.yaml")
	ctx := context.Background()
	setup, err := control.Setup(ctx, db, dir, polPath)
	if err != nil {
		t.Fatal(err)
	}
	if policyYAML != "" {
		os.WriteFile(polPath, []byte(policyYAML), 0o600)
	}
	holder, err := policy.NewHolder(polPath)
	if err != nil {
		t.Fatal(err)
	}
	keyB, _, err := identity.CreateKey(ctx, db, "bob", setup.OrgID)
	if err != nil {
		t.Fatal(err)
	}
	up := &fakeProvider{failKeys: map[string]int{}}
	upSrv := httptest.NewServer(up)
	t.Cleanup(upSrv.Close)

	reg := provider.NewRegistry()
	conns := []*provider.Connection{
		provider.NewConnection("openai", provider.OpenAI, upSrv.URL, "sk-openai-1", "env"),
		provider.NewConnection("anthropic", provider.Anthropic, upSrv.URL, "sk-ant-1", "env"),
	}
	for i, k := range extraKeys {
		conns = append(conns, provider.NewConnection(fmt.Sprintf("anthropic-%d", i+2), provider.Anthropic, upSrv.URL, k, "env"))
	}
	reg.Replace(conns)
	keys := identity.NewResolver()
	ks, _ := db.ListKeys(ctx)
	keys.Load(ks)
	catalog, err := router.LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	spool, err := events.OpenSpool(filepath.Join(dir, "spool"), 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { spool.Close() })
	gw := &pipeline.Gateway{
		Policies: holder, Keys: keys, Registry: reg, Client: provider.NewClient(reg), Catalog: catalog,
		Cache: openCache(t, dir, holder.Current()), Spool: spool, Limit: limits.NewConcurrency(64), MasterKey: setup.MasterKey,
		Metrics: telemetry.New(), Logf: t.Logf, NearMiss: cache.NewNearMiss(), Router: router.NewRouter(catalog),
		Budgets: &limits.Budgets{C: limits.NewMemoryCounters()}, Rates: limits.NewRates(), Flights: cache.NewFlights(),
	}
	gw.Semantic = cache.NewSemantic(gw.Cache.SemanticStore, t.Logf)
	srv := httptest.NewServer(gw.Handler())
	t.Cleanup(srv.Close)
	return &harness{t: t, gw: srv, up: up, db: db, spool: spool, keyA: setup.VirtualKey, keyB: keyB, polPath: polPath, holder: holder, keys: keys, g: gw, dir: dir, upURL: upSrv.URL}
}

func (h *harness) post(path, key string, body any, hdr ...string) (*http.Response, string) {
	h.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", h.gw.URL+path, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	if strings.HasPrefix(path, "/v1/messages") {
		req.Header.Set("X-Api-Key", key)
		req.Header.Set("Anthropic-Version", "2023-06-01")
	} else {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, string(out)
}

func (h *harness) events() []store.Event {
	h.t.Helper()
	if err := h.spool.Deliver(context.Background(), h.db); err != nil {
		h.t.Fatal(err)
	}
	evs, err := h.db.ListEvents(context.Background(), store.EventFilter{Range: store.Range{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)}, Limit: 500})
	if err != nil {
		h.t.Fatal(err)
	}
	return evs
}

func chat(text string, stream bool) map[string]any {
	return map[string]any{"model": "gpt-4o-mini", "stream": stream, "messages": []any{
		map[string]any{"role": "system", "content": "You write payment reminders."},
		map[string]any{"role": "user", "content": text},
	}}
}

func messages(text string, stream bool) map[string]any {
	return map[string]any{"model": "claude-opus-5-5", "max_tokens": 1000, "stream": stream, "system": "You write payment reminders.",
		"messages": []any{map[string]any{"role": "user", "content": text}}}
}

// streamText concatenates the text deltas of an SSE body.
func streamText(t *testing.T, body string, anthropic bool) string {
	var b strings.Builder
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") || line == "data: [DONE]" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line[6:]), &m); err != nil {
			t.Fatalf("bad event %q", line)
		}
		if anthropic {
			if d, ok := m["delta"].(map[string]any); ok && d["type"] == "text_delta" {
				b.WriteString(d["text"].(string))
			}
			continue
		}
		for _, c := range m["choices"].([]any) {
			if d, ok := c.(map[string]any)["delta"].(map[string]any); ok {
				if s, ok := d["content"].(string); ok {
					b.WriteString(s)
				}
			}
		}
	}
	return b.String()
}

const cardA = "4111 1111 1111 1111"
const cardB = "5555 5555 5555 4444"

// The design's central example: masking makes the cache shareable.
func TestMaskingMakesTheCacheShareable(t *testing.T) {
	h := newHarness(t, "")
	resp, body := h.post("/v1/chat/completions", h.keyA, chat("Charge card "+cardA+" again", false))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if got := lastUserText(h.up.lastBody()); got != "Charge card [CREDIT_CARD_1] again" {
		t.Fatalf("the model saw %q", got)
	}
	if !strings.Contains(body, "You said: Charge card "+cardA+" again") {
		t.Fatalf("answer not rehydrated: %s", body)
	}
	if resp.Header.Get("X-KyGate-Cache") != "miss" {
		t.Fatalf("cache header %q", resp.Header.Get("X-KyGate-Cache"))
	}

	// User B, a different card: same masked request, served from the cache
	// with B's own value, and no model call.
	calls := h.up.calls
	resp, body = h.post("/v1/chat/completions", h.keyB, chat("Charge card "+cardB+" again", false))
	if resp.Header.Get("X-KyGate-Cache") != "hit" {
		t.Fatalf("want a cache hit, got %q", resp.Header.Get("X-KyGate-Cache"))
	}
	if h.up.calls != calls {
		t.Fatal("a cache hit called the model")
	}
	if !strings.Contains(body, cardB) || strings.Contains(body, cardA) {
		t.Fatalf("B must get B's card and never A's: %s", body)
	}

	// The same hit, streamed: the cache serves either form.
	resp, body = h.post("/v1/chat/completions", h.keyB, chat("Charge card "+cardB+" again", true), "X-Test", "1")
	_ = resp
	evs := h.events()
	if len(evs) != 3 {
		t.Fatalf("want 3 events, got %d", len(evs))
	}
	var hit *store.Event
	for i := range evs {
		if evs[i].Cache == "hit" {
			hit = &evs[i]
		}
		for _, f := range evs[i].Findings {
			if f.Type == "CREDIT_CARD" && f.Action != "mask" {
				t.Fatalf("finding %+v", f)
			}
		}
	}
	if hit == nil || hit.CostAvoidedUSD <= 0 {
		t.Fatalf("a hit must record the cost it avoided: %+v", hit)
	}
}

func TestStreamingRehydratesSplitPlaceholders(t *testing.T) {
	h := newHarness(t, "")
	_, body := h.post("/v1/chat/completions", h.keyA, chat("card "+cardA+" and IBAN GB82WEST12345698765432", true))
	got := streamText(t, body, false)
	want := "You said: card " + cardA + " and IBAN GB82WEST12345698765432"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if strings.Contains(body, `"usage"`) {
		t.Fatal("the client did not ask for usage, so the usage chunk must not reach it")
	}
	evs := h.events()
	if evs[0].InputTokens != 50 || evs[0].OutputTokens != 5 || evs[0].CostUSD <= 0 {
		t.Fatalf("usage from the stream not recorded: %+v", evs[0])
	}

	_, body = h.post("/v1/messages", h.keyA, messages("card "+cardA+" please", true))
	if got := streamText(t, body, true); got != "You said: card "+cardA+" please" {
		t.Fatalf("anthropic stream got %q", got)
	}
	if !strings.Contains(body, "event: message_stop") {
		t.Fatal("anthropic stream must end with message_stop")
	}
}

func TestStreamedAnswerIsCachedAndReplayed(t *testing.T) {
	h := newHarness(t, "")
	_, first := h.post("/v1/messages", h.keyA, messages("Remind "+cardA, true))
	resp, second := h.post("/v1/messages", h.keyB, messages("Remind "+cardB, true))
	if resp.Header.Get("X-KyGate-Cache") != "hit" {
		t.Fatalf("want hit, got %q", resp.Header.Get("X-KyGate-Cache"))
	}
	if streamText(t, first, true) != "You said: Remind "+cardA || streamText(t, second, true) != "You said: Remind "+cardB {
		t.Fatalf("replay wrong:\n%s\n%s", streamText(t, first, true), streamText(t, second, true))
	}
	// The starter policy switches the regenerate rule off: a quick repeat by
	// the same key is answered from the cache too.
	resp, _ = h.post("/v1/messages", h.keyB, messages("Remind "+cardB, false))
	if resp.Header.Get("X-KyGate-Cache") != "hit" || resp.Header.Get("X-KyGate-Cache-Kind") != "exact" {
		t.Fatalf("with repeat_window: 0s a quick repeat is a hit, got %q %q", resp.Header.Get("X-KyGate-Cache"), resp.Header.Get("X-KyGate-Cache-Kind"))
	}
}

// With a repeat window, the same key repeating a request within it gets a
// fresh answer: usually a "regenerate" click.
func TestRepeatWindowBypassesTheCache(t *testing.T) {
	pol := strings.Replace(string(policy.Starter()), "repeat_window: 0s", "repeat_window: 30s", 1)
	h := newHarness(t, pol)
	h.post("/v1/messages", h.keyA, messages("Remind "+cardA, false))
	if resp, _ := h.post("/v1/messages", h.keyA, messages("Remind "+cardA, false)); resp.Header.Get("X-KyGate-Cache") != "bypass" {
		t.Fatalf("a quick repeat by the same key must bypass the cache, got %q", resp.Header.Get("X-KyGate-Cache"))
	}
	if resp, _ := h.post("/v1/messages", h.keyB, messages("Remind "+cardB, false)); resp.Header.Get("X-KyGate-Cache") != "hit" {
		t.Fatalf("another key is not repeating, got %q", resp.Header.Get("X-KyGate-Cache"))
	}
}

// Editing a comment or a TTL keeps every stored answer; changing a data rule
// starts a new cache.
func TestPolicyEditKeepsTheCache(t *testing.T) {
	h := newHarness(t, "")
	h.post("/v1/chat/completions", h.keyA, chat("Charge card "+cardA+" again", false))
	reload := func(old, new string) {
		b, _ := os.ReadFile(h.polPath)
		if !strings.Contains(string(b), old) {
			t.Fatalf("starter policy lacks %q", old)
		}
		os.WriteFile(h.polPath, []byte(strings.Replace(string(b), old, new, 1)), 0o600)
		hd, err := policy.NewHolder(h.polPath)
		if err != nil {
			t.Fatal(err)
		}
		h.g.Policies = hd
	}
	reload("# KyGate starter policy", "# My edited policy")
	reload("ttl: 30d", "ttl: 60d")
	if resp, _ := h.post("/v1/chat/completions", h.keyB, chat("Charge card "+cardB+" again", false)); resp.Header.Get("X-KyGate-Cache") != "hit" {
		t.Fatalf("a comment and a TTL edit must keep stored answers, got %q", resp.Header.Get("X-KyGate-Cache"))
	}
	reload("EMAIL:       { action: allow }", "EMAIL:       { action: mask }")
	if resp, _ := h.post("/v1/chat/completions", h.keyB, chat("Charge card "+cardB+" again", false)); resp.Header.Get("X-KyGate-Cache") != "miss" {
		t.Fatalf("a changed data rule must start a new cache, got %q", resp.Header.Get("X-KyGate-Cache"))
	}
}

func TestSecretIsBlocked(t *testing.T) {
	h := newHarness(t, "")
	calls := h.up.calls
	resp, body := h.post("/v1/messages", h.keyA, messages("my key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789", false))
	if resp.StatusCode != 403 || !strings.Contains(body, "SECRET") || !strings.Contains(body, `"type":"error"`) {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if h.up.calls != calls {
		t.Fatal("a blocked request reached the provider")
	}
	if evs := h.events(); evs[0].Outcome != "blocked" {
		t.Fatalf("outcome %q", evs[0].Outcome)
	}
}

func TestMonitorModeChangesNothing(t *testing.T) {
	pol := strings.Replace(string(policy.Starter()), "mode: enforce", "mode: monitor", 1)
	h := newHarness(t, pol)
	resp, body := h.post("/v1/chat/completions", h.keyA, chat("key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789 card "+cardA, false))
	if resp.StatusCode != 200 {
		t.Fatalf("monitor mode must not block: %d %s", resp.StatusCode, body)
	}
	if got := lastUserText(h.up.lastBody()); !strings.Contains(got, cardA) {
		t.Fatalf("monitor mode must not mask: %q", got)
	}
	if resp.Header.Get("X-KyGate-Cache") != "bypass" {
		t.Fatal("unmasked protected values must never be cached")
	}
	evs := h.events()
	applied := 0
	for _, f := range evs[0].Findings {
		if f.Applied && (f.Action == "block" || f.Action == "mask") {
			applied++
		}
	}
	if applied != 0 || evs[0].Outcome != "ok" {
		t.Fatalf("monitor mode recorded applied actions: %+v", evs[0])
	}
}

// Principle 4: the provider sees a stable conversation, turn after turn.
func TestMaskingIsStableAcrossTurns(t *testing.T) {
	h := newHarness(t, "")
	turn1 := []any{
		map[string]any{"role": "user", "content": "Pay " + cardA},
	}
	turn2 := append(append([]any{}, turn1...),
		map[string]any{"role": "assistant", "content": "Paid [CREDIT_CARD_1]."},
		map[string]any{"role": "user", "content": "Now also pay " + cardB + " and " + cardA},
	)
	h.post("/v1/messages", h.keyA, map[string]any{"model": "claude-opus-5-5", "max_tokens": 10, "messages": turn1})
	first := h.up.lastBody()["messages"].([]any)[0]
	h.post("/v1/messages", h.keyA, map[string]any{"model": "claude-opus-5-5", "max_tokens": 10, "messages": turn2})
	second := h.up.lastBody()["messages"].([]any)
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second[0])
	if string(a) != string(b) {
		t.Fatalf("turn 1 changed between requests:\n%s\n%s", a, b)
	}
	if got := second[2].(map[string]any)["content"]; got != "Now also pay [CREDIT_CARD_2] and [CREDIT_CARD_1]" {
		t.Fatalf("got %q", got)
	}
}

func TestNextKeyBeforeFirstByte(t *testing.T) {
	h := newHarness(t, "", "sk-ant-2")
	h.up.failKeys["sk-ant-1"] = 429
	for i := 0; i < 4; i++ {
		resp, body := h.post("/v1/messages", h.keyA, messages(fmt.Sprintf("hello %d", i), false), "X-KyGate-Cache", "no-cache")
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: %d %s", i, resp.StatusCode, body)
		}
	}
	for _, e := range h.events() {
		if e.Connection != "anthropic-2" {
			t.Fatalf("served by %q", e.Connection)
		}
	}
}

func TestUnknownKeyAndUnreadableContent(t *testing.T) {
	h := newHarness(t, "")
	resp, _ := h.post("/v1/chat/completions", "kg-not-a-key", chat("hi", false))
	if resp.StatusCode != 401 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	img := map[string]any{"model": "gpt-4o-mini", "messages": []any{map[string]any{"role": "user", "content": []any{
		map[string]any{"type": "text", "text": "what is this"},
		map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64,AAAA"}},
	}}}}
	resp, body := h.post("/v1/chat/completions", h.keyA, img)
	if resp.StatusCode != 403 || !strings.Contains(body, "image") {
		t.Fatalf("the starter policy keeps images local: %d %s", resp.StatusCode, body)
	}
}

func TestRevokedKeyStopsWorking(t *testing.T) {
	h := newHarness(t, "")
	if ok, err := h.db.RevokeKey(context.Background(), "bob"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	ks, _ := h.db.ListKeys(context.Background())
	h.keys.Load(ks) // what the serve command does when the config version changes
	if resp, _ := h.post("/v1/chat/completions", h.keyB, chat("hi", false)); resp.StatusCode != 401 {
		t.Fatalf("a revoked key must be refused, got %d", resp.StatusCode)
	}
	if resp, _ := h.post("/v1/chat/completions", h.keyA, chat("hi", false)); resp.StatusCode != 200 {
		t.Fatalf("other keys keep working, got %d", resp.StatusCode)
	}
}

// The exact cache on disk (OP-1, architecture §4.5): the starter policy keeps
// entries in cache.db, so a stored answer is served after a restart, with the
// caller's own values, and no model call.
func TestCacheSurvivesRestart(t *testing.T) {
	h := newHarness(t, "")
	if !h.holder.Current().CachePersist() {
		t.Fatal("the starter policy must keep the exact cache on disk")
	}
	if resp, body := h.post("/v1/chat/completions", h.keyA, chat("Charge card "+cardA+" again", false)); resp.Header.Get("X-KyGate-Cache") != "miss" {
		t.Fatalf("want a miss: %s", body)
	}
	h.restartCache()

	calls := h.up.calls
	resp, body := h.post("/v1/chat/completions", h.keyB, chat("Charge card "+cardB+" again", false))
	if resp.Header.Get("X-KyGate-Cache") != "hit" {
		t.Fatalf("after a restart, want a hit from the cache file, got %q", resp.Header.Get("X-KyGate-Cache"))
	}
	if h.up.calls != calls {
		t.Fatal("a cache hit called the model")
	}
	if !strings.Contains(body, cardB) || strings.Contains(body, cardA) {
		t.Fatalf("B must get B's card and never A's: %s", body)
	}
	var fromDisk bool
	for _, e := range h.events() {
		if e.Cache == "hit" && e.CacheReason == "served from the cache file" && e.CostAvoidedUSD > 0 {
			fromDisk = true
		}
	}
	if !fromDisk {
		t.Fatal("a hit from the cache file must be recorded as such, with the cost it avoided")
	}

	// Invariants 3 and 5: the file holds sealed placeholder text, never a
	// real value, and no readable answer text.
	h.g.Cache.Close()
	raw := readCacheFiles(t, h.dir)
	for _, s := range []string{cardA, cardB, "4111111111111111", "You said", "CREDIT_CARD_1", "Charge card"} {
		if strings.Contains(raw, s) {
			t.Fatalf("cache.db holds %q in readable form", s)
		}
	}
}

// The upgrade rule: a policy file that does not name cache.exact.persist keeps
// the cache in memory only, and no cache file is written.
func TestPolicyWithoutPersistKeepsCacheInMemory(t *testing.T) {
	pol := strings.Replace(string(policy.Starter()), "    persist: true\n", "", 1)
	h := newHarness(t, pol)
	if h.holder.Current().CachePersist() {
		t.Fatal("persist must be off when the policy does not name it")
	}
	h.post("/v1/chat/completions", h.keyA, chat("hello there", false))
	h.restartCache()
	if resp, _ := h.post("/v1/chat/completions", h.keyB, chat("hello there", false)); resp.Header.Get("X-KyGate-Cache") != "miss" {
		t.Fatalf("a memory-only cache is empty after a restart, got %q", resp.Header.Get("X-KyGate-Cache"))
	}
	if _, err := os.Stat(filepath.Join(h.dir, control.CacheFile)); !os.IsNotExist(err) {
		t.Fatalf("no cache file may be written while persist is off: %v", err)
	}
	if st := h.g.Cache.Stats(); st.Disk.State != "off" {
		t.Fatalf("disk state %q", st.Disk.State)
	}
}

// Optimization fails open: a damaged cache file never stops KyGate; the cache
// runs in memory only.
func TestDamagedCacheFileFailsOpen(t *testing.T) {
	h := newHarness(t, "")
	h.g.Cache.Close()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		os.Remove(filepath.Join(h.dir, control.CacheFile+suffix))
	}
	if err := os.WriteFile(filepath.Join(h.dir, control.CacheFile), []byte(strings.Repeat("not a database ", 1000)), 0o600); err != nil {
		t.Fatal(err)
	}
	h.g.Cache = openCache(t, h.dir, h.holder.Current())
	if st := h.g.Cache.Stats(); st.Disk.State != "unavailable" || st.Disk.Error == "" {
		t.Fatalf("a damaged file must be reported as unavailable: %+v", st.Disk)
	}
	if resp, body := h.post("/v1/chat/completions", h.keyA, chat("still serving", false)); resp.StatusCode != 200 || resp.Header.Get("X-KyGate-Cache") != "miss" {
		t.Fatalf("status %d, cache %q: %s", resp.StatusCode, resp.Header.Get("X-KyGate-Cache"), body)
	}
	if resp, _ := h.post("/v1/chat/completions", h.keyB, chat("still serving", false)); resp.Header.Get("X-KyGate-Cache") != "hit" {
		t.Fatalf("the in-process cache must keep serving, got %q", resp.Header.Get("X-KyGate-Cache"))
	}
}

// readCacheFiles returns the bytes of cache.db and its write-ahead log.
func readCacheFiles(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(filepath.Join(dir, control.CacheFile+suffix))
		if err != nil && suffix == "" {
			t.Fatal(err)
		}
		b.Write(data)
	}
	return b.String()
}
