// Package cache is the cache quality gate. This file measures the exact cache
// kept on disk (OP-1, architecture §4.5): every stored answer must survive a
// restart, the file must hold no readable text, and a changed master key must
// turn every entry into a miss without an error. semantic_test.go gates the
// semantic cache's false-hit rate.
//
// Every value here is synthetic.
package cache

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/cache"
	"github.com/Kytherion/KyGate/internal/store"
	"github.com/Kytherion/KyGate/internal/store/sqlite"
)

const entries = 500

func open(t *testing.T, path string) *cache.Exact {
	t.Helper()
	e := cache.New(256 << 20)
	e.UseDisk(func() (store.CacheStore, error) { return sqlite.OpenCache(path) }, t.Logf)
	if err := e.Configure(cache.Settings{MaxMemoryBytes: 256 << 20, Persist: true, MaxDiskBytes: 1024 << 20}); err != nil {
		t.Fatal(err)
	}
	return e
}

func orgKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func body(i int) []byte {
	return []byte(fmt.Sprintf(`{"choices":[{"message":{"content":"Synthetic answer %04d for [EMAIL_1] and [CREDIT_CARD_1]"}}]}`, i))
}

func TestExactCacheOnDisk(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.db")

	e := open(t, path)
	for i := 0; i < entries; i++ {
		if err := e.Put(orgKey(1), "org", fmt.Sprintf("fp-%04d", i), &cache.Entry{Model: "m", Body: body(i)}, 24*time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	e.Close()

	// Survival across a restart: every entry, byte for byte.
	e = open(t, path)
	survived := 0
	for i := 0; i < entries; i++ {
		got, ok := e.Get(ctx, orgKey(1), "org", fmt.Sprintf("fp-%04d", i))
		if ok && got.Tier == cache.TierDisk && string(got.Body) == string(body(i)) {
			survived++
		}
	}
	t.Logf("survived a restart: %d of %d", survived, entries)
	if survived != entries {
		t.Fatalf("survival %d/%d, floor %d/%d", survived, entries, entries, entries)
	}
	e.Close()

	// The file holds sealed entries: no answer text, no placeholder.
	var raw strings.Builder
	for _, s := range []string{"", "-wal"} {
		b, _ := os.ReadFile(path + s)
		raw.Write(b)
	}
	for _, s := range []string{"Synthetic answer", "[EMAIL_1]", "CREDIT_CARD", "choices"} {
		if strings.Contains(raw.String(), s) {
			t.Fatalf("cache.db holds %q in readable form", s)
		}
	}

	// A changed master key: every entry is a miss, and the cache keeps working.
	e = open(t, path)
	defer e.Close()
	for i := 0; i < entries; i++ {
		if _, ok := e.Get(ctx, orgKey(2), "org", fmt.Sprintf("fp-%04d", i)); ok {
			t.Fatal("an entry sealed under another key was served")
		}
	}
	if st := e.Stats(); st.Disk.State != "on" {
		t.Fatalf("disk state %q after unreadable entries", st.Disk.State)
	}
}
