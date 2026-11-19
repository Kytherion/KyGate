package cache

// Purges (GV-4). An entry carries labels: the key that stored it
// and the application's tags (X-KyGate-Cache-Tags). Each label is a keyed
// hash under the organization's label key, so the cache store never holds a
// tag or a key ID in clear. A purge deletes the entries with one label, or
// every entry, in the cache store; and it empties this process's in-memory
// tier, which refills from the store, so that no purged answer is served
// from memory.

import (
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
)

// Label kinds.
const (
	LabelKey = "key" // the virtual key that stored the entry, by ID
	LabelTag = "tag" // a tag the application named
)

// Label is the keyed hash of one label. labelKey comes from
// store.DeriveKey(master, "cache-label", org).
func Label(labelKey []byte, kind, value string) string {
	m := hmac.New(sha256.New, labelKey)
	m.Write([]byte(kind + "\x00" + value))
	return hex.EncodeToString(m.Sum(nil)[:store.LabelSize/2])
}

// purgeTimeout bounds how long a purge waits for the writer.
const purgeTimeout = 30 * time.Second

type purgeReq struct {
	label string
	done  chan purgeResult
}

type purgeResult struct {
	n   int64
	err error
}

// Purge deletes the entries with a label ("" for all) from the cache store,
// after the writes already queued here, and empties the in-memory tier. It
// returns the number of entries deleted from the store.
func (e *Exact) Purge(ctx context.Context, label string) (int64, error) {
	e.mem.clear()
	d := e.active()
	if d == nil {
		return 0, nil
	}
	req := purgeReq{label: label, done: make(chan purgeResult, 1)}
	select {
	case e.purges <- req:
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-time.After(purgeTimeout):
		// The writer is stuck: purge directly.
		return d.Purge(ctx, label)
	}
	select {
	case r := <-req.done:
		// Entries read from the store between the clear and the purge.
		e.mem.clear()
		return r.n, r.err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// Purge deletes the semantic entries with a label ("" for all).
func (s *Semantic) Purge(ctx context.Context, label string) (int64, error) {
	return s.store().PurgeSemantic(ctx, label)
}

// clear empties the in-memory tier.
func (m *Memory) clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ll.Init()
	m.items = map[string]*list.Element{}
	m.size = 0
}

// ValidTag reports whether t can be a cache tag: 1 to 64 letters, digits,
// and . _ : / -.
func ValidTag(t string) bool {
	if t == "" || len(t) > 64 {
		return false
	}
	for _, c := range t {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._:/-", c)) {
			return false
		}
	}
	return true
}
