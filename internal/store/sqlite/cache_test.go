package sqlite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
)

func openCache(t *testing.T) (*CacheDB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cache.db")
	c, err := OpenCache(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, path
}

func TestCacheRoundTripAndReopen(t *testing.T) {
	ctx := context.Background()
	c, path := openCache(t)
	exp := time.Now().Add(time.Hour).Truncate(time.Millisecond)
	if err := c.PutEntries(ctx, []store.CacheRecord{{Key: "k1", OrgID: "o1", Sealed: []byte("sealed-1"), Expires: exp}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetEntry(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	c.Close()

	c2, err := OpenCache(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	r, err := c2.GetEntry(ctx, "k1")
	if err != nil || r.OrgID != "o1" || !bytes.Equal(r.Sealed, []byte("sealed-1")) || !r.Expires.Equal(exp) {
		t.Fatalf("after reopen: %+v %v", r, err)
	}
}

func TestCacheTrimRemovesExpiredThenLeastRecentlyUsed(t *testing.T) {
	ctx := context.Background()
	c, _ := openCache(t)
	now := time.Now()
	blob := bytes.Repeat([]byte{7}, 16<<10)
	var recs []store.CacheRecord
	for i := 0; i < 200; i++ {
		recs = append(recs, store.CacheRecord{Key: fmt.Sprintf("k%03d", i), OrgID: "o", Sealed: blob, Expires: now.Add(time.Hour)})
	}
	recs = append(recs, store.CacheRecord{Key: "old", OrgID: "o", Sealed: blob, Expires: now.Add(-time.Second)})
	if err := c.PutEntries(ctx, recs); err != nil {
		t.Fatal(err)
	}
	// k199 is the most recently used entry.
	if err := c.TouchEntries(ctx, []string{"k199"}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	if _, err := c.Trim(ctx, now, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetEntry(ctx, "old"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("an expired entry must be removed")
	}

	limit := int64(1 << 20) // about a third of what is stored
	removed, err := c.Trim(ctx, now, limit)
	if err != nil || removed == 0 {
		t.Fatalf("removed %d, %v", removed, err)
	}
	used, _ := c.usedBytes(ctx)
	if used > limit {
		t.Fatalf("the file holds %d bytes of data, over the limit of %d", used, limit)
	}
	if _, err := c.GetEntry(ctx, "k199"); err != nil {
		t.Fatal("the most recently used entry must stay")
	}
	if _, err := c.GetEntry(ctx, "k000"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the least recently used entry must go first")
	}
}

func TestCacheDamagedFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	os.WriteFile(path, bytes.Repeat([]byte("garbage!"), 1024), 0o600)
	if c, err := OpenCache(path); err == nil {
		c.Close()
		t.Fatal("a damaged file must be reported, so the cache runs in memory only")
	}
}
