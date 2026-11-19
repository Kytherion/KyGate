// Package run sends load to a KyGate gateway and measures it: latency, time to
// first byte, requests per second, errors, and cache hits. Every answer is
// checked: a caller whose answer misses its own card number, carries a
// placeholder, or carries someone else's value counts as an error, so the
// numbers are only reported for traffic that was served correctly.
//
// It is used by the gates in eval/load and by the kyload command, which loads
// a real deployment.
package run

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptrace"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config describes one load run.
type Config struct {
	URL         string // the gateway's model API, such as http://127.0.0.1:4000
	Key         string // a virtual key
	API         string // openai | anthropic
	Model       string
	Concurrency int           // requests in flight
	Requests    int           // how many to send; 0 means until Duration
	Duration    time.Duration // how long to send, when Requests is 0
	Repeat      float64       // share of requests that repeat an earlier prompt (exact-cache hits)
	Stream      float64       // share of requests that ask for a streamed answer
	Sensitive   float64       // share of requests that carry a card number to mask and put back
	Pool        int           // distinct prompts that repeated requests draw from; 20 when zero
	Ramp        time.Duration // the workers start spread over this time, so connections do not all arrive at once
	Seed        int64
	Client      *http.Client // nil: a client sized for Concurrency
}

// Summary is the distribution of one measure.
type Summary struct {
	N                  int
	P50, P95, P99, Max time.Duration
}

func (s Summary) String() string {
	if s.N == 0 {
		return "n=0"
	}
	return fmt.Sprintf("n=%d p50=%s p95=%s p99=%s max=%s", s.N, ms(s.P50), ms(s.P95), ms(s.P99), ms(s.Max))
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000) }

// Result is what a run measured.
type Result struct {
	Requests int
	Errors   int            // transport errors, error statuses, and wrong answers
	Wrong    int            // answers served with a missing, foreign, or unreplaced value
	ByStatus map[int]int    // HTTP status counts
	Samples  map[string]int // a few error messages, counted
	Hits     int            // answers marked X-KyGate-Cache: hit
	Elapsed  time.Duration
	RPS      float64

	Latency     Summary // whole request, every answer
	TTFB        Summary // time to the first byte of the answer, every answer
	HitTTFB     Summary // cache hits only
	MissLatency Summary // non-streamed answers that called the model
	StreamTotal Summary // streamed answers, to the last byte
}

type sample struct {
	total, ttfb time.Duration
	hit, stream bool
}

// Run sends the load and waits for every request to finish.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1
	}
	if cfg.Pool <= 0 {
		cfg.Pool = 20
	}
	if cfg.API == "" {
		cfg.API = "openai"
	}
	if cfg.API != "openai" && cfg.API != "anthropic" {
		return nil, fmt.Errorf("api must be openai or anthropic, not %q", cfg.API)
	}
	if cfg.Requests <= 0 && cfg.Duration <= 0 {
		return nil, fmt.Errorf("set a number of requests or a duration")
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Transport: &http.Transport{
			MaxIdleConns: cfg.Concurrency * 2, MaxIdleConnsPerHost: cfg.Concurrency * 2, IdleConnTimeout: 90 * time.Second,
			DisableCompression: true,
		}}
	}
	run := &runner{cfg: cfg, client: client, res: &Result{ByStatus: map[int]int{}, Samples: map[string]int{}}}

	// Prime the pool: each repeated prompt is sent once first, unmeasured,
	// so that later repeats can be served from the exact cache.
	if cfg.Repeat > 0 {
		for i := 0; i < cfg.Pool; i++ {
			job := run.job(rand.New(rand.NewSource(cfg.Seed+int64(i))), i, false, true, i)
			if _, err := run.do(ctx, job); err != nil {
				return nil, fmt.Errorf("priming the cache: %w", err)
			}
		}
	}

	var issued atomic.Int64
	deadline := time.Time{}
	if cfg.Requests <= 0 {
		deadline = time.Now().Add(cfg.Duration)
	}
	samples := make([][]sample, cfg.Concurrency)
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < cfg.Concurrency; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(cfg.Seed + 1000003*int64(w+1)))
			if cfg.Ramp > 0 {
				select {
				case <-time.After(cfg.Ramp * time.Duration(w) / time.Duration(cfg.Concurrency)):
				case <-ctx.Done():
					return
				}
			}
			for ctx.Err() == nil {
				n := issued.Add(1)
				if cfg.Requests > 0 && n > int64(cfg.Requests) {
					return
				}
				if !deadline.IsZero() && time.Now().After(deadline) {
					return
				}
				template := -1
				if rng.Float64() < cfg.Repeat {
					template = rng.Intn(cfg.Pool)
				}
				job := run.job(rng, template, rng.Float64() < cfg.Stream, rng.Float64() < cfg.Sensitive, int(n))
				s, err := run.do(ctx, job)
				if err != nil {
					run.fail(err.Error())
					continue
				}
				samples[w] = append(samples[w], s)
			}
		}(w)
	}
	wg.Wait()
	res := run.res
	res.Elapsed = time.Since(start)

	var all, ttfb, hit, miss, stream []time.Duration
	for _, ws := range samples {
		for _, s := range ws {
			all = append(all, s.total)
			ttfb = append(ttfb, s.ttfb)
			if s.stream {
				stream = append(stream, s.total)
			}
			switch {
			case s.hit:
				res.Hits++
				hit = append(hit, s.ttfb)
			case !s.stream:
				miss = append(miss, s.total)
			}
		}
	}
	res.Requests = len(all) + res.Errors
	if res.Elapsed > 0 {
		res.RPS = float64(res.Requests) / res.Elapsed.Seconds()
	}
	res.Latency, res.TTFB, res.HitTTFB, res.MissLatency, res.StreamTotal = summarize(all), summarize(ttfb), summarize(hit), summarize(miss), summarize(stream)
	return res, nil
}

type runner struct {
	cfg    Config
	client *http.Client
	mu     sync.Mutex
	res    *Result
}

func (r *runner) fail(msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.res.Errors++
	if len(msg) > 160 {
		msg = msg[:160]
	}
	if len(r.res.Samples) < 20 || r.res.Samples[msg] > 0 {
		r.res.Samples[msg]++
	}
}

type job struct {
	body   []byte
	stream bool
	card   string // the value the answer must carry back, or ""
	echo   string // text the answer must carry
}

// job builds one request. A repeated request (template >= 0) takes its prompt
// from the pool, so its masked form is the same as the primed one's; its card
// number is its own, so the answer it gets from the cache must carry that
// number and no other. Other requests are unique.
func (r *runner) job(rng *rand.Rand, template int, stream, sensitive bool, n int) job {
	var prompt string
	if template >= 0 {
		prompt = fmt.Sprintf("Write a short payment reminder, template %d.", template)
		// Primed prompts carry a card, so repeats must too: the masked form
		// is what the cache keys on.
		sensitive = true
	} else {
		// Words between the numbers, so they never read as a card number.
		prompt = fmt.Sprintf("Write a short payment reminder for invoice %d, batch %d.", n, rng.Intn(1000000))
	}
	card := ""
	if sensitive {
		card = cardNumber(rng)
		prompt += " The card is " + card + "."
	}
	var body map[string]any
	if r.cfg.API == "anthropic" {
		body = map[string]any{"model": r.cfg.Model, "max_tokens": 256, "stream": stream, "system": "You write payment reminders.",
			"messages": []any{map[string]any{"role": "user", "content": prompt}}}
	} else {
		body = map[string]any{"model": r.cfg.Model, "stream": stream, "messages": []any{
			map[string]any{"role": "system", "content": "You write payment reminders."},
			map[string]any{"role": "user", "content": prompt},
		}}
	}
	b, _ := json.Marshal(body)
	return job{body: b, stream: stream, card: card, echo: strings.SplitN(prompt, ".", 2)[0]}
}

func (r *runner) do(ctx context.Context, j job) (sample, error) {
	path := "/v1/chat/completions"
	if r.cfg.API == "anthropic" {
		path = "/v1/messages"
	}
	var first time.Time
	trace := &httptrace.ClientTrace{GotFirstResponseByte: func() { first = time.Now() }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "POST", strings.TrimRight(r.cfg.URL, "/")+path, bytes.NewReader(j.body))
	if err != nil {
		return sample{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if r.cfg.API == "anthropic" {
		req.Header.Set("X-Api-Key", r.cfg.Key)
		req.Header.Set("Anthropic-Version", "2023-06-01")
	} else {
		req.Header.Set("Authorization", "Bearer "+r.cfg.Key)
	}
	start := time.Now()
	resp, err := r.client.Do(req)
	if err != nil {
		return sample{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	total := time.Since(start)
	r.mu.Lock()
	r.res.ByStatus[resp.StatusCode]++
	r.mu.Unlock()
	if err != nil {
		return sample{}, fmt.Errorf("reading the answer: %w", err)
	}
	if resp.StatusCode != 200 {
		return sample{}, fmt.Errorf("status %d: %s", resp.StatusCode, firstLine(body))
	}
	var text string
	if j.stream {
		text = streamText(body, r.cfg.API == "anthropic")
	} else {
		text = wholeText(body, r.cfg.API == "anthropic")
	}
	if msg := check(text, j); msg != "" {
		r.mu.Lock()
		r.res.Wrong++
		r.mu.Unlock()
		return sample{}, fmt.Errorf("wrong answer: %s", msg)
	}
	if first.IsZero() {
		first = time.Now()
	}
	return sample{total: total, ttfb: first.Sub(start), hit: resp.Header.Get("X-KyGate-Cache") == "hit", stream: j.stream}, nil
}

// check reports what is wrong with an answer, or "". The stand-in provider
// echoes the user text, so the answer must carry the caller's own prompt and
// card number, with no placeholder left in it.
func check(text string, j job) string {
	if text == "" {
		return "empty answer"
	}
	if strings.Contains(text, "[CREDIT_CARD_") {
		return "a placeholder was not replaced"
	}
	if j.card != "" && !strings.Contains(text, j.card) {
		return "the answer does not carry the caller's own card number"
	}
	if !strings.Contains(text, j.echo) {
		return "the answer is not the answer to this prompt"
	}
	return ""
}

func wholeText(body []byte, anthropic bool) string {
	if anthropic {
		var m struct {
			Content []struct {
				Type, Text string
			} `json:"content"`
		}
		json.Unmarshal(body, &m)
		var b strings.Builder
		for _, c := range m.Content {
			b.WriteString(c.Text)
		}
		return b.String()
	}
	var m struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	json.Unmarshal(body, &m)
	if len(m.Choices) == 0 {
		return ""
	}
	return m.Choices[0].Message.Content
}

func streamText(body []byte, anthropic bool) string {
	var b strings.Builder
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") || line == "data: [DONE]" {
			continue
		}
		data := []byte(strings.TrimPrefix(line, "data: "))
		if anthropic {
			var ev struct {
				Type  string `json:"type"`
				Delta struct {
					Type, Text string
				} `json:"delta"`
			}
			if json.Unmarshal(data, &ev) == nil && ev.Type == "content_block_delta" {
				b.WriteString(ev.Delta.Text)
			}
			continue
		}
		var ev struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal(data, &ev) == nil && len(ev.Choices) > 0 {
			b.WriteString(ev.Choices[0].Delta.Content)
		}
	}
	return b.String()
}

func firstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// cardNumber returns a synthetic 16-digit Visa-style number that passes the
// Luhn check, so the fast detectors mask it. It is not a real card.
func cardNumber(rng *rand.Rand) string {
	d := make([]int, 16)
	d[0] = 4
	for i := 1; i < 15; i++ {
		d[i] = rng.Intn(10)
	}
	sum := 0
	for i := 0; i < 15; i++ {
		v := d[14-i]
		if i%2 == 0 {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
	}
	d[15] = (10 - sum%10) % 10
	var b strings.Builder
	for i, v := range d {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteByte(byte('0' + v))
	}
	return b.String()
}

func summarize(ds []time.Duration) Summary {
	if len(ds) == 0 {
		return Summary{}
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	at := func(p float64) time.Duration {
		i := int(p*float64(len(ds))+0.5) - 1
		if i < 0 {
			i = 0
		}
		if i >= len(ds) {
			i = len(ds) - 1
		}
		return ds[i]
	}
	return Summary{N: len(ds), P50: at(0.50), P95: at(0.95), P99: at(0.99), Max: ds[len(ds)-1]}
}
