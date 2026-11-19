package cache

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
)

// GV-4: a purge by label removes exactly the labelled entries, from memory
// and from the store, including one written just before the purge.
func TestPurgeByLabel(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cache.db")
	e := newExact(t, path, true)
	lk := key(9)
	a, b := Label(lk, LabelKey, "key-a"), Label(lk, LabelTag, "docs-v3")
	if len(a) != store.LabelSize || a == b || Label(lk, LabelTag, "key-a") == a {
		t.Fatal("labels are fixed-size keyed hashes, distinct per kind and value")
	}
	e.Put(key(1), "org", "fp1", &Entry{Model: "m"}, time.Hour, a)
	e.Put(key(1), "org", "fp2", &Entry{Model: "m"}, time.Hour, a, b)
	e.Put(key(1), "org", "fp3", &Entry{Model: "m"}, time.Hour)
	// No wait: the purge must come after these queued writes.
	n, err := e.Purge(ctx, b)
	if err != nil || n != 1 {
		t.Fatalf("one entry carries the tag: %d %v", n, err)
	}
	if _, ok := e.Get(ctx, key(1), "org", "fp2"); ok {
		t.Fatal("a purged entry is served neither from memory nor from the store")
	}
	if got, ok := e.Get(ctx, key(1), "org", "fp1"); !ok || got.Tier != TierDisk {
		t.Fatalf("other entries stay in the store, and memory refills from it: %v %+v", ok, got)
	}
	if n, _ := e.Purge(ctx, a); n != 1 {
		t.Fatalf("the key's remaining entry: %d", n)
	}
	if _, ok := e.Get(ctx, key(1), "org", "fp3"); !ok {
		t.Fatal("an unlabelled entry stays")
	}
	if n, _ := e.Purge(ctx, ""); n != 1 {
		t.Fatalf("purge all: %d", n)
	}
	if _, ok := e.Get(ctx, key(1), "org", "fp3"); ok {
		t.Fatal("everything is gone")
	}
	e.Close()
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "docs-v3") || strings.Contains(string(raw), "key-a") {
		t.Fatal("the cache file never holds a tag or key ID in clear")
	}
}

func TestPurgeInMemoryOnly(t *testing.T) {
	e := newExact(t, filepath.Join(t.TempDir(), "cache.db"), false)
	e.Put(key(1), "org", "fp1", &Entry{Model: "m"}, time.Hour, "x")
	if _, err := e.Purge(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Get(context.Background(), key(1), "org", "fp1"); ok {
		t.Fatal("memory is emptied")
	}
}

func TestSemanticPurgeInMemory(t *testing.T) {
	s := NewSemantic(func() store.SemanticStore { return nil }, t.Logf)
	ctx := context.Background()
	m := s.store()
	m.PutSemantic(ctx, store.SemanticRecord{Key: "k1", Context: "c", OrgID: "o", Expires: time.Now().Add(time.Hour), Labels: []string{"a"}})
	m.PutSemantic(ctx, store.SemanticRecord{Key: "k2", Context: "c", OrgID: "o", Expires: time.Now().Add(time.Hour), Labels: []string{"b"}})
	if n, _ := s.Purge(ctx, "a"); n != 1 {
		t.Fatal(n)
	}
	if l, _ := m.ListSemantic(ctx, "o", "c", time.Now(), 10); len(l) != 1 || l[0].Key != "k2" {
		t.Fatalf("%+v", l)
	}
}
