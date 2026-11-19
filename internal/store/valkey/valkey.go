// Package valkey is the Team profile's driver for Valkey, the
// Redis-compatible store chosen for its permissive license. Two instances,
// with opposite settings (architecture §4.9):
//
//   - Counters (store.Counters): budget and rate counters. That instance must
//     never evict (maxmemory-policy noeviction) and should persist (AOF).
//   - Cache (store.CacheStore): exact-cache entries, sealed exactly as in
//     memory. That instance evicts the least recently used entries
//     (maxmemory-policy allkeys-lru), so touching and trimming are its job.
//
// Several gateways share them. Keys start with "kygate:".
package valkey

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	vk "github.com/valkey-io/valkey-go"

	"github.com/Kytherion/KyGate/internal/store"
)

const prefix = "kygate:"

func open(url string) (vk.Client, error) {
	opt, err := vk.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("Valkey address %q: %w", redact(url), err)
	}
	opt.DisableCache = true // no client-side caching: every gateway must see the same counter
	c, err := vk.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("Valkey %s: %w", redact(url), err)
	}
	return c, nil
}

// redact hides a password in a URL, for messages.
func redact(url string) string {
	if i := strings.Index(url, "@"); i > 0 {
		if j := strings.Index(url, "://"); j > 0 && j < i {
			return url[:j+3] + "***" + url[i:]
		}
	}
	return url
}

// Counters implements store.Counters.
type Counters struct{ c vk.Client }

var _ store.Counters = (*Counters)(nil)

// OpenCounters connects to the counters instance (redis:// or rediss:// URL).
func OpenCounters(url string) (*Counters, error) {
	c, err := open(url)
	if err != nil {
		return nil, err
	}
	return &Counters{c: c}, nil
}

// Close closes the connection.
func (s *Counters) Close() { s.c.Close() }

// Add adds delta to a counter and sets its expiry, in one round trip.
func (s *Counters) Add(ctx context.Context, key string, delta float64, expires time.Time) (float64, error) {
	k := prefix + "n:" + key
	res := s.c.DoMulti(ctx,
		s.c.B().Incrbyfloat().Key(k).Increment(delta).Build(),
		s.c.B().Pexpireat().Key(k).MillisecondsTimestamp(expires.UnixMilli()).Build())
	v, err := res[0].ToString()
	if err != nil {
		return 0, err
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, err
	}
	if f < 0 {
		// A settlement below its reservation never makes spend negative.
		s.c.Do(ctx, s.c.B().Incrbyfloat().Key(k).Increment(-f).Build())
		f = 0
	}
	return f, nil
}

// Get returns a counter, or 0.
func (s *Counters) Get(ctx context.Context, key string) (float64, error) {
	v, err := s.c.Do(ctx, s.c.B().Get().Key(prefix+"n:"+key).Build()).ToString()
	if vk.IsValkeyNil(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.ParseFloat(v, 64)
}

// Cache implements store.CacheStore over the cache instance.
type Cache struct{ c vk.Client }

var _ store.CacheStore = (*Cache)(nil)

// OpenCache connects to the cache instance.
func OpenCache(url string) (*Cache, error) {
	c, err := open(url)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Do(ctx, c.B().Ping().Build()).Error(); err != nil {
		c.Close()
		return nil, fmt.Errorf("Valkey %s: %w", redact(url), err)
	}
	return &Cache{c: c}, nil
}

func cacheKey(k string) string { return prefix + "c:" + k }

// labelKey is the set of entry keys that carry one label (GV-4). It lives as
// long as its longest-lived entry.
func labelKey(l string) string { return prefix + "l:" + l }

// An entry's value carries its organization and expiry before the sealed
// bytes, which the exact cache checks on every read:
//
//	version (1) | expiry, Unix ms, big-endian (8) | org length (1) | org | sealed
const entryVersion = 1

func encodeEntry(r store.CacheRecord) []byte {
	b := make([]byte, 0, 10+len(r.OrgID)+len(r.Sealed))
	b = append(b, entryVersion)
	b = binary.BigEndian.AppendUint64(b, uint64(r.Expires.UnixMilli()))
	b = append(b, byte(len(r.OrgID)))
	b = append(b, r.OrgID...)
	return append(b, r.Sealed...)
}

func decodeEntry(key string, b []byte) (store.CacheRecord, error) {
	if len(b) < 10 || b[0] != entryVersion || len(b) < 10+int(b[9]) {
		return store.CacheRecord{}, fmt.Errorf("cache entry %s: unknown format", key)
	}
	n := int(b[9])
	return store.CacheRecord{Key: key, Expires: time.UnixMilli(int64(binary.BigEndian.Uint64(b[1:9]))), OrgID: string(b[10 : 10+n]), Sealed: b[10+n:]}, nil
}

func (s *Cache) GetEntry(ctx context.Context, key string) (store.CacheRecord, error) {
	b, err := s.c.Do(ctx, s.c.B().Get().Key(cacheKey(key)).Build()).AsBytes()
	if vk.IsValkeyNil(err) {
		return store.CacheRecord{}, store.ErrNotFound
	}
	if err != nil {
		return store.CacheRecord{}, err
	}
	return decodeEntry(key, b)
}

func (s *Cache) PutEntries(ctx context.Context, recs []store.CacheRecord) error {
	cmds := make(vk.Commands, 0, len(recs))
	for _, r := range recs {
		if !r.Expires.After(time.Now()) {
			continue
		}
		if len(r.OrgID) > 255 {
			continue
		}
		cmds = append(cmds, s.c.B().Set().Key(cacheKey(r.Key)).Value(vk.BinaryString(encodeEntry(r))).Pxat(r.Expires).Build())
		for _, l := range r.Labels {
			ms := r.Expires.UnixMilli()
			cmds = append(cmds,
				s.c.B().Sadd().Key(labelKey(l)).Member(r.Key).Build(),
				// A new set gets the entry's expiry; a set already there keeps
				// the later of the two.
				s.c.B().Pexpireat().Key(labelKey(l)).MillisecondsTimestamp(ms).Nx().Build(),
				s.c.B().Pexpireat().Key(labelKey(l)).MillisecondsTimestamp(ms).Gt().Build())
		}
	}
	for _, res := range s.c.DoMulti(ctx, cmds...) {
		if err := res.Error(); err != nil {
			return err
		}
	}
	return nil
}

// TouchEntries does nothing: the instance tracks use itself (allkeys-lru).
func (s *Cache) TouchEntries(context.Context, []string, time.Time) error { return nil }

func (s *Cache) DeleteEntries(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	ks := make([]string, len(keys))
	for i, k := range keys {
		ks[i] = cacheKey(k)
	}
	_, err := s.del(ctx, ks)
	return err
}

// Trim does nothing: entries expire by themselves, and the instance evicts
// the least recently used ones within its maxmemory.
func (s *Cache) Trim(context.Context, time.Time, int64) (int64, error) { return 0, nil }

func (s *Cache) Stats(ctx context.Context) (store.CacheStoreStats, error) {
	n, err := s.c.Do(ctx, s.c.B().Dbsize().Build()).AsInt64()
	if err != nil {
		return store.CacheStoreStats{}, err
	}
	info, _ := s.c.Do(ctx, s.c.B().Info().Section("memory").Build()).ToString()
	var used int64
	for _, line := range strings.Split(info, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "used_memory:"); ok {
			used, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	return store.CacheStoreStats{Entries: n, Bytes: used}, nil
}

func (s *Cache) Close() error {
	s.c.Close()
	return nil
}

// Purge deletes the entries that carry a label, then the label's set; with
// no label, every cache entry and label set KyGate wrote (GV-4).
func (s *Cache) Purge(ctx context.Context, label string) (int64, error) {
	if label == "" {
		var n int64
		for _, pattern := range []string{prefix + "c:*", prefix + "l:*"} {
			m, err := s.deleteMatching(ctx, pattern)
			if err != nil {
				return n, err
			}
			if pattern == prefix+"c:*" {
				n = m
			}
		}
		return n, nil
	}
	members, err := s.c.Do(ctx, s.c.B().Smembers().Key(labelKey(label)).Build()).AsStrSlice()
	if err != nil && !vk.IsValkeyNil(err) {
		return 0, err
	}
	ks := make([]string, len(members))
	for j, k := range members {
		ks[j] = cacheKey(k)
	}
	n, err := s.del(ctx, ks)
	if err != nil {
		return n, err
	}
	return n, s.c.Do(ctx, s.c.B().Del().Key(labelKey(label)).Build()).Error()
}

func (s *Cache) deleteMatching(ctx context.Context, pattern string) (int64, error) {
	var n int64
	var cursor uint64
	for {
		e, err := s.c.Do(ctx, s.c.B().Scan().Cursor(cursor).Match(pattern).Count(1000).Build()).AsScanEntry()
		if err != nil {
			return n, err
		}
		m, err := s.del(ctx, e.Elements)
		if err != nil {
			return n, err
		}
		n += m
		if cursor = e.Cursor; cursor == 0 {
			return n, nil
		}
	}
}

// del deletes keys one per command, pipelined: a cluster keeps keys in
// different slots, and one DEL may name keys of one slot only.
func (s *Cache) del(ctx context.Context, keys []string) (int64, error) {
	var n int64
	for i := 0; i < len(keys); i += 500 {
		batch := keys[i:min(i+500, len(keys))]
		cmds := make(vk.Commands, len(batch))
		for j, k := range batch {
			cmds[j] = s.c.B().Del().Key(k).Build()
		}
		for _, r := range s.c.DoMulti(ctx, cmds...) {
			m, err := r.AsInt64()
			if err != nil {
				return n, err
			}
			n += m
		}
	}
	return n, nil
}
