// Load gates: the latency targets of architecture.md §5.5 and the cost of
// an open stream, measured on a gateway in this process with the starter
// policy (masking, output inspection, the exact cache on disk, the router in
// shadow mode, the audit spool) against a stand-in provider that answers at
// once. Every answer is checked: each caller must get its own card number back.
//
// The gates are loose enough for a shared CI machine; each test logs what it
// measured. Measured numbers for docs come from kyload against the real
// binary (eval/load/README.md).
package load_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/eval/load/run"
	"github.com/Kytherion/KyGate/eval/load/standin"
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

// Gates. The targets are architecture.md §5.5's; CI machines are shared and
// noisy, so a gate fails only well past its target.
const (
	targetOverheadP95 = 5 * time.Millisecond  // gateway stages without ML
	targetHitTTFBP95  = 15 * time.Millisecond // exact-cache hit, to first byte
	ciSlack           = 4                     // a gate fails beyond target x ciSlack
	maxBytesPerStream = 192 << 10             // memory of one open stream in the gateway: about 128 KB measured
	minRPS            = 300                   // mixed traffic, one process, instant provider
)

type gateway struct {
	url   string
	key   string
	db    *sqlite.DB
	spool *events.Spool
}

func newGateway(t *testing.T, up http.Handler) *gateway {
	t.Helper()
	dir := t.TempDir()
	db, err := sqlite.Open(filepath.Join(dir, "kygate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	polPath := filepath.Join(dir, "policy.yaml")
	ctx := context.Background()
	setup, err := control.Setup(ctx, db, dir, polPath) // writes the starter policy
	if err != nil {
		t.Fatal(err)
	}
	holder, err := policy.NewHolder(polPath)
	if err != nil {
		t.Fatal(err)
	}
	upSrv := httptest.NewServer(up)
	t.Cleanup(upSrv.Close)
	reg := provider.NewRegistry()
	reg.Replace([]*provider.Connection{
		provider.NewConnection("openai", provider.OpenAI, upSrv.URL, "sk-standin", "env"),
		provider.NewConnection("anthropic", provider.Anthropic, upSrv.URL, "sk-ant-standin", "env"),
	})
	keys := identity.NewResolver()
	ks, _ := db.ListKeys(ctx)
	keys.Load(ks)
	catalog, err := router.LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	spool, err := events.OpenSpool(filepath.Join(dir, "spool"), 256<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { spool.Close() })
	p := holder.Current()
	c := cache.New(int64(p.Cache.Exact.MaxSizeMB) << 20)
	c.UseDisk(func() (store.CacheStore, error) { return sqlite.OpenCache(filepath.Join(dir, control.CacheFile)) }, t.Logf)
	if err := c.Configure(cache.Settings{MaxMemoryBytes: int64(p.Cache.Exact.MaxSizeMB) << 20, Persist: p.CachePersist(),
		MaxDiskBytes: int64(p.Cache.Exact.MaxDiskMB) << 20}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	gw := &pipeline.Gateway{
		Policies: holder, Keys: keys, Registry: reg, Client: provider.NewClient(reg), Catalog: catalog,
		Cache: c, Spool: spool, Limit: limits.NewConcurrency(1024), MasterKey: setup.MasterKey,
		Metrics: telemetry.New(), Logf: func(string, ...any) {}, NearMiss: cache.NewNearMiss(), Router: router.NewRouter(catalog),
		Budgets: &limits.Budgets{C: limits.NewMemoryCounters()}, Rates: limits.NewRates(), Flights: cache.NewFlights(),
	}
	gw.Semantic = cache.NewSemantic(c.SemanticStore, t.Logf)
	srv := httptest.NewServer(gw.Handler())
	t.Cleanup(srv.Close)
	return &gateway{url: srv.URL, key: setup.VirtualKey, db: db, spool: spool}
}

// client is the test's client. A refused connect is tried again: Windows keeps
// a short accept queue (about 200), and while the whole suite runs in
// parallel, 1,000 streams opening within a second can overflow it. A refused
// connect never reached the gateway, so retrying it hides no gateway error.
func client(n int) *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var err error
		for try := 0; try < 5; try++ {
			var c net.Conn
			if c, err = d.DialContext(ctx, network, addr); err == nil {
				return c, nil
			}
			if !strings.Contains(err.Error(), "refused") {
				return nil, err
			}
			time.Sleep(time.Duration(50*(try+1)) * time.Millisecond)
		}
		return nil, err
	}
	return &http.Client{Transport: &http.Transport{DialContext: dial, MaxIdleConns: 2 * n, MaxIdleConnsPerHost: 2 * n, DisableCompression: true}}
}

func mustRun(t *testing.T, cfg run.Config) *run.Result {
	t.Helper()
	res, err := run.Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Errors > 0 {
		t.Fatalf("%d of %d requests failed (%d wrong answers): %v", res.Errors, res.Requests, res.Wrong, res.Samples)
	}
	return res
}

// overheads reads the last events and returns KyGate's own time for each
// non-streamed model call: every stage but the upstream call.
func (g *gateway) overheads(t *testing.T) []time.Duration {
	t.Helper()
	ctx := context.Background()
	if err := g.spool.Deliver(ctx, g.db); err != nil {
		t.Fatal(err)
	}
	evs, err := g.db.ListEvents(ctx, store.EventFilter{Range: store.Range{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)}, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	var out []time.Duration
	for _, e := range evs {
		if e.Stream || e.Cache == "hit" || e.Outcome != "ok" {
			continue
		}
		us := 0
		for name, v := range e.Stages {
			if name != "upstream" {
				us += v
			}
		}
		out = append(out, time.Duration(us)*time.Microsecond)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func p95(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	return ds[(len(ds)*95+99)/100-1]
}

// TestGatewayOverhead: KyGate's own time on a model call, masking a card
// number on the way out and putting it back on the way in.
func TestGatewayOverhead(t *testing.T) {
	g := newGateway(t, &standin.Provider{})
	res := mustRun(t, run.Config{URL: g.url, Key: g.key, Model: "gpt-4o-mini", Concurrency: 8, Requests: 600, Sensitive: 1, Seed: 1, Client: client(8)})
	ov := g.overheads(t)
	if len(ov) < 400 {
		t.Fatalf("only %d events with stage timings", len(ov))
	}
	got := p95(ov)
	t.Logf("gateway overhead p95 %s (median %s) over %d model calls; client latency %s", got, ov[len(ov)/2], len(ov), res.MissLatency)
	if got > targetOverheadP95*ciSlack {
		t.Errorf("gateway overhead p95 %s, target %s (gate %s)", got, targetOverheadP95, targetOverheadP95*ciSlack)
	}
}

// TestCacheHitTimeToFirstByte: a repeated request answered from the exact
// cache, each caller with its own card number put back.
func TestCacheHitTimeToFirstByte(t *testing.T) {
	g := newGateway(t, &standin.Provider{FirstByte: 50 * time.Millisecond})
	res := mustRun(t, run.Config{URL: g.url, Key: g.key, API: "anthropic", Model: "claude-sonnet-5-5", Concurrency: 8, Requests: 600, Repeat: 1, Pool: 10, Seed: 2, Client: client(8)})
	if res.Hits < res.Requests*9/10 {
		t.Fatalf("only %d of %d requests were cache hits", res.Hits, res.Requests)
	}
	t.Logf("cache hit time to first byte %s", res.HitTTFB)
	if res.HitTTFB.P95 > targetHitTTFBP95*ciSlack {
		t.Errorf("cache hit time to first byte p95 %s, target %s (gate %s)", res.HitTTFB.P95, targetHitTTFBP95, targetHitTTFBP95*ciSlack)
	}
}

// TestManyOpenStreams holds 1,000 streams open at once through the gateway,
// each rehydrating its own card number, and measures what one open stream
// costs the gateway: the same streams sent straight to the stand-in provider
// are the baseline, so the client's and the provider's share is subtracted.
func TestManyOpenStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("1,000 open streams")
	}
	const streams = 1000
	slow := func() *standin.Provider {
		return &standin.Provider{FirstByte: 100 * time.Millisecond, Chunks: 30, ChunkGap: 50 * time.Millisecond}
	}
	measure := func(url, key string) (heap uint64, goroutines int, res *run.Result) {
		type outcome struct {
			res *run.Result
			err error
		}
		done := make(chan outcome, 1)
		go func() {
			r, err := run.Run(context.Background(), run.Config{URL: url, Key: key, Model: "gpt-4o-mini", Concurrency: streams, Requests: streams,
				Stream: 1, Sensitive: 1, Seed: 3, Client: client(streams), Ramp: 600 * time.Millisecond})
			done <- outcome{r, err}
		}()
		time.Sleep(1200 * time.Millisecond) // every stream is open: the last opened 600 ms in, the first ends after about 1.7 s
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		heap, goroutines = m.HeapInuse+m.StackInuse, runtime.NumGoroutine()
		// KYGATE_LOAD_HEAPPROFILE=FILE writes a heap profile with every stream open.
		if path := os.Getenv("KYGATE_LOAD_HEAPPROFILE"); path != "" && key != "unused" {
			if f, err := os.Create(path); err == nil {
				pprof.WriteHeapProfile(f)
				f.Close()
			}
		}
		o := <-done
		if o.err != nil {
			t.Fatal(o.err)
		}
		return heap, goroutines, o.res
	}
	base := func() (uint64, int) {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapInuse + m.StackInuse, runtime.NumGoroutine()
	}

	// Baseline: client and provider only.
	direct := httptest.NewServer(slow())
	defer direct.Close()
	h0, g0 := base()
	hd, gd, _ := measure(direct.URL, "unused")

	// Through the gateway.
	g := newGateway(t, slow())
	h1, g1 := base()
	hg, gg, res := measure(g.url, g.key)

	perStream := (int64(hg-h1) - int64(hd-h0)) / streams
	goroutinesPerStream := float64((gg-g1)-(gd-g0)) / streams
	t.Logf("%d open streams: gateway memory %d KB per stream, %.1f goroutines per stream; whole stream %s", streams, perStream>>10, goroutinesPerStream, res.StreamTotal)
	if res.Requests != streams || res.Errors != 0 {
		t.Fatalf("%d streams, %d errors: %v", res.Requests, res.Errors, res.Samples)
	}
	if perStream > maxBytesPerStream {
		t.Errorf("an open stream costs the gateway %d KB, gate %d KB", perStream>>10, maxBytesPerStream>>10)
	}
}

// TestMixedThroughput: half repeats, a fifth streamed, half with card
// numbers, both API families' worth of work on one process.
func TestMixedThroughput(t *testing.T) {
	g := newGateway(t, &standin.Provider{})
	res := mustRun(t, run.Config{URL: g.url, Key: g.key, Model: "gpt-4o-mini", Concurrency: 64, Requests: 4000, Repeat: 0.5, Stream: 0.2, Sensitive: 0.5, Seed: 4, Client: client(64)})
	t.Logf("%d requests in %s: %.0f per second, %d cache hits; latency %s", res.Requests, res.Elapsed.Round(time.Millisecond), res.RPS, res.Hits, res.Latency)
	if res.RPS < minRPS {
		t.Errorf("%.0f requests per second, gate %d", res.RPS, minRPS)
	}
}
