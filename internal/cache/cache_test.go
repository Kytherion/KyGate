package cache

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
	"github.com/Kytherion/KyGate/internal/store/sqlite"
)

func newExact(t *testing.T, path string, persist bool) *Exact {
	t.Helper()
	e := New(1 << 20)
	e.UseDisk(func() (store.CacheStore, error) { return sqlite.OpenCache(path) }, t.Logf)
	if err := e.Configure(Settings{MaxMemoryBytes: 1 << 20, Persist: persist, MaxDiskBytes: 64 << 20}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func key(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestEntryIsReadFromDiskAfterRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cache.db")
	e := newExact(t, path, true)
	if err := e.Put(key(1), "org", "fp", &Entry{Model: "m", Body: []byte(`{"x":"[EMAIL_1]"}`)}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, ok := e.Get(ctx, key(1), "org", "fp"); !ok || got.Tier != TierMemory {
		t.Fatalf("want a memory hit, got %v %+v", ok, got)
	}
	e.Close()

	e2 := newExact(t, path, true)
	got, ok := e2.Get(ctx, key(1), "org", "fp")
	if !ok || got.Tier != TierDisk || got.Model != "m" || string(got.Body) != `{"x":"[EMAIL_1]"}` {
		t.Fatalf("want a disk hit, got %v %+v", ok, got)
	}
	// The entry is copied into memory.
	if got, ok := e2.Get(ctx, key(1), "org", "fp"); !ok || got.Tier != TierMemory {
		t.Fatalf("want the entry in memory after a disk hit, got %v %+v", ok, got)
	}
	if _, ok := e2.Get(ctx, key(1), "other-org", "fp"); ok {
		t.Fatal("an entry belongs to one organization")
	}
}

// A changed master key makes the entries unreadable: a miss, never an error.
func TestChangedKeyIsAMiss(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cache.db")
	e := newExact(t, path, true)
	e.Put(key(1), "org", "fp", &Entry{Model: "m"}, time.Hour)
	e.Close()

	e2 := newExact(t, path, true)
	if _, ok := e2.Get(ctx, key(2), "org", "fp"); ok {
		t.Fatal("an entry sealed under another key must be a miss")
	}
	e2.Close()
	// The unreadable entry was removed in the background.
	e3 := newExact(t, path, true)
	if _, ok := e3.Get(ctx, key(1), "org", "fp"); ok {
		t.Fatal("the unreadable entry should have been deleted")
	}
}

func TestExpiredEntryIsAMiss(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cache.db")
	e := newExact(t, path, true)
	e.Put(key(1), "org", "fp", &Entry{}, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if _, ok := e.Get(ctx, key(1), "org", "fp"); ok {
		t.Fatal("an expired entry must be a miss")
	}
}

// Turning persist off at a policy reload stops reads and writes of the file.
func TestPersistOffSkipsTheFile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cache.db")
	e := newExact(t, path, true)
	e.Configure(Settings{MaxMemoryBytes: 1 << 20, Persist: false})
	e.Put(key(1), "org", "fp", &Entry{}, time.Hour)
	if st := e.Stats(); st.Disk.State != "off" {
		t.Fatalf("state %q", st.Disk.State)
	}
	e.Close()
	e2 := newExact(t, path, true)
	if _, ok := e2.Get(ctx, key(1), "org", "fp"); ok {
		t.Fatal("an entry stored while persist was off must not be on disk")
	}
}
