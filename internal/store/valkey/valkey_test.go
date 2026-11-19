package valkey

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/Kytherion/KyGate/internal/cache"
	"github.com/Kytherion/KyGate/internal/limits"
	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store"
)

var ctx = context.Background()

func server(t *testing.T) (*miniredis.Miniredis, string) {
	m := miniredis.RunT(t)
	return m, "redis://" + m.Addr()
}

func TestCounters(t *testing.T) {
	m, url := server(t)
	c, err := OpenCounters(url)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	exp := time.Now().Add(time.Hour)
	if v, err := c.Add(ctx, "spend:org:m:2026-11", 0.25, exp); err != nil || v != 0.25 {
		t.Fatal(v, err)
	}
	if v, _ := c.Add(ctx, "spend:org:m:2026-11", 0.5, exp); v != 0.75 {
		t.Fatal(v)
	}
	if v, _ := c.Get(ctx, "spend:org:m:2026-11"); v != 0.75 {
		t.Fatal(v)
	}
	if v, _ := c.Get(ctx, "absent"); v != 0 {
		t.Fatal(v)
	}
	if v, _ := c.Add(ctx, "spend:org:m:2026-11", -5, exp); v != 0 {
		t.Fatalf("spend never goes negative: %v", v)
	}
	if ttl := m.TTL("kygate:n:spend:org:m:2026-11"); ttl <= 0 || ttl > time.Hour {
		t.Fatalf("the counter expires: %v", ttl)
	}
	// Two gateways share one budget: reservations add up across them.
	other, _ := OpenCounters(url)
	defer other.Close()
	b1, b2 := &limits.Budgets{C: c}, &limits.Budgets{C: other}
	_ = b2
	if _, err := b1.C.Add(ctx, "x", 1, exp); err != nil {
		t.Fatal(err)
	}
	if v, _ := other.Get(ctx, "x"); v != 1 {
		t.Fatalf("a second client sees the same counter: %v", v)
	}
}

func TestSharedRatesAcrossGateways(t *testing.T) {
	_, url := server(t)
	a, _ := OpenCounters(url)
	b, _ := OpenCounters(url)
	defer a.Close()
	defer b.Close()
	ra, rb := &limits.SharedRates{C: a}, &limits.SharedRates{C: b}
	now := time.Now()
	passed := 0
	for i := 0; i < 6; i++ {
		r := ra
		if i%2 == 1 {
			r = rb
		}
		if ok, _ := r.Request("key1", 4, now, false); ok {
			passed++
		}
	}
	if passed != 4 {
		t.Fatalf("two gateways enforce one limit of 4 together, not 4 each: %d passed", passed)
	}
	if ok, wait := ra.Request("key1", 4, now, false); ok || wait <= 0 || wait > 61*time.Second {
		t.Fatalf("%v %v", ok, wait)
	}
	if ok, _ := ra.Request("key2", 4, now, false); !ok {
		t.Fatal("keys have their own counters")
	}
}

// Valkey down: each gateway keeps a limit of its own instead of none
// (architecture §5.4), and counts the fallback.
func TestSharedRatesFallBackPerInstance(t *testing.T) {
	m, url := server(t)
	c, _ := OpenCounters(url)
	defer c.Close()
	r := &limits.SharedRates{C: c, Local: limits.NewRates()}
	m.Close()
	now := time.Now()
	passed := 0
	for i := 0; i < 6; i++ {
		if ok, _ := r.Request("key1", 4, now, false); ok {
			passed++
		}
	}
	if passed != 4 || r.Fallbacks.Load() != 6 {
		t.Fatalf("with the counters down, the local limit applies: %d passed, %d fallbacks", passed, r.Fallbacks.Load())
	}
}

func TestCache(t *testing.T) {
	m, url := server(t)
	c, err := OpenCache(url)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	now := time.Now()
	err = c.PutEntries(ctx, []store.CacheRecord{
		{Key: "fp1", OrgID: "o", Sealed: []byte{0, 1, 2, 255}, Expires: now.Add(time.Hour)},
		{Key: "fp2", OrgID: "o", Sealed: []byte{7}, Expires: now.Add(-time.Second)}, // already expired: not stored
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.GetEntry(ctx, "fp1")
	if err != nil || string(r.Sealed) != string([]byte{0, 1, 2, 255}) || r.OrgID != "o" || r.Expires.UnixMilli() != now.Add(time.Hour).UnixMilli() {
		t.Fatalf("binary entries survive: %v %v", r, err)
	}
	if _, err := c.GetEntry(ctx, "fp2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	m.FastForward(2 * time.Hour)
	if _, err := c.GetEntry(ctx, "fp1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("entries expire with their TTL")
	}
	c.PutEntries(ctx, []store.CacheRecord{{Key: "fp3", Sealed: []byte{1}, Expires: time.Now().Add(time.Hour)}})
	if s, err := c.Stats(ctx); err != nil || s.Entries != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	c.DeleteEntries(ctx, []string{"fp3"})
	if _, err := c.GetEntry(ctx, "fp3"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
}

// Two gateways share the exact cache: what one stores, the other serves. The
// entry carries its organization and expiry, which the cache checks.
func TestExactCacheSharedByTwoGateways(t *testing.T) {
	_, url := server(t)
	open := func() *cache.Exact {
		e := cache.New(1 << 20)
		e.UseDisk(func() (store.CacheStore, error) { return OpenCache(url) }, t.Logf)
		if err := e.Configure(cache.Settings{MaxMemoryBytes: 1 << 20, Persist: true}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { e.Close() })
		return e
	}
	a, b := open(), open()
	key := []byte("0123456789abcdef0123456789abcdef")
	if err := a.Put(key, "org1", "fp", &cache.Entry{Family: "openai", Body: []byte(`{"x":1}`), Created: time.Now()}, time.Hour); err != nil {
		t.Fatal(err)
	}
	var got *cache.Entry
	for i := 0; i < 50 && got == nil; i++ {
		time.Sleep(20 * time.Millisecond) // the writer flushes in the background
		got, _ = b.Get(ctx, key, "org1", "fp")
	}
	if got == nil || string(got.Body) != `{"x":1}` || got.Tier != cache.TierDisk {
		t.Fatalf("the second gateway serves the first one's entry: %+v", got)
	}
	if e, ok := b.Get(ctx, key, "org2", "fp"); ok {
		t.Fatalf("another organization's entry is never served: %+v", e)
	}
}

// GV-4: purges by label and of everything; label sets expire with their
// longest-lived entry.
func TestCachePurge(t *testing.T) {
	m, url := server(t)
	c, err := OpenCache(url)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	now := time.Now()
	err = c.PutEntries(ctx, []store.CacheRecord{
		{Key: "fp1", OrgID: "o", Sealed: []byte{1}, Expires: now.Add(time.Hour), Labels: []string{"keyA"}},
		{Key: "fp2", OrgID: "o", Sealed: []byte{2}, Expires: now.Add(3 * time.Hour), Labels: []string{"keyA", "tagX"}},
		{Key: "fp3", OrgID: "o", Sealed: []byte{3}, Expires: now.Add(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ttl := m.TTL("kygate:l:keyA"); ttl < 2*time.Hour {
		t.Fatalf("a label lives as long as its longest-lived entry: %v", ttl)
	}
	if n, err := c.Purge(ctx, "tagX"); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if _, err := c.GetEntry(ctx, "fp2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the tagged entry is gone")
	}
	if _, err := c.GetEntry(ctx, "fp1"); err != nil {
		t.Fatal("the others stay")
	}
	if n, err := c.Purge(ctx, ""); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	if keys := m.Keys(); len(keys) != 0 {
		t.Fatalf("purge all leaves nothing KyGate wrote: %v", keys)
	}
}

// Architecture §5.4: with Valkey down, budgets go on from the last known
// figures, and the spend counted meanwhile reaches Valkey when it is back.
func TestBudgetCountersFallBack(t *testing.T) {
	m, url := server(t)
	c, _ := OpenCounters(url)
	defer c.Close()
	f := limits.NewFallbackCounters(c)
	exp := time.Now().Add(time.Hour)
	if v, err := f.Add(ctx, "spend:key:k:m", 5, exp); err != nil || v != 5 {
		t.Fatal(v, err)
	}
	addr := m.Addr()
	m.Close()
	v, err := f.Add(ctx, "spend:key:k:m", 2, exp)
	if !errors.Is(err, limits.ErrApproximate) || v != 7 || !f.Down() {
		t.Fatalf("goes on from the last known 5: %v %v", v, err)
	}
	// A budget check runs on the approximate figure.
	b := &limits.Budgets{C: f}
	bp := policy.Budgets{PerKey: policy.BudgetSet{Monthly: policy.Limit{Hard: 8}}}
	chk, err := b.Reserve(ctx, bp, limits.Who{KeyID: "k2"}, 9, time.Now(), true)
	if err != nil || !chk.Approximate || !chk.HardLimits || chk.State != limits.Hard {
		t.Fatalf("%+v %v", chk, err)
	}
	// Valkey is back: the 2 counted meanwhile are added.
	m2 := miniredis.NewMiniRedis()
	if err := m2.StartAddr(addr); err != nil {
		t.Skip("could not restart on the same address:", err)
	}
	defer m2.Close()
	m2.Set("kygate:n:spend:key:k:m", "5")
	time.Sleep(2100 * time.Millisecond) // the back-off before the store is tried again
	if v, err := f.Add(ctx, "spend:key:k:m", 1, exp); err != nil || v != 8 {
		t.Fatalf("5 in Valkey, 2 counted during the outage, 1 now: %v %v", v, err)
	}
	if f.Down() {
		t.Fatal("recovered")
	}
}
