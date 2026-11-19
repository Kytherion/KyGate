// Package cache is the exact response cache (capability OP-1).
//
// Entries hold the masked answer, in placeholder form, never real values:
// rehydration happens after the cache, per request, from the caller's own
// value map. This is what lets one entry serve different users (architecture
// §3.4, §4.5). Entries are compressed with zstd and encrypted with a
// per-organization key.
//
// The exact cache has two tiers. The in-process tier (Memory) is small and
// fast. Behind it, a cache store keeps entries across a restart: in the Solo
// profile a SQLite file of its own, cache.db, when the policy sets
// cache.exact.persist. Both tiers hold the same sealed bytes. The store is
// read only when the in-process tier misses, and written in the background, so
// a response never waits for the disk. The cache fails open: a disk error, a
// damaged file, or an entry sealed under another master key is a miss.
//
// The semantic cache is in semantic.go, coalescing in flight.go; the Team
// profile's shared store is in internal/store/valkey.
package cache

import (
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/Kytherion/KyGate/internal/router"
	"github.com/Kytherion/KyGate/internal/store"
)

// Fingerprint is the keyed hash of a canonical masked request. The key is
// per organization, so that someone who reads the cache cannot test guesses,
// and two organizations never collide.
func Fingerprint(key []byte, parts ...[]byte) string {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		var n [8]byte
		l := len(p)
		for i := 0; i < 8; i++ {
			n[i] = byte(l >> (8 * i))
		}
		m.Write(n[:])
		m.Write(p)
	}
	return hex.EncodeToString(m.Sum(nil))
}

// Canonical returns the part of a request body that changes the answer, as
// canonical JSON: keys sorted, and without the streaming flag and request
// metadata, which do not change the answer.
func Canonical(body map[string]any) []byte {
	c := make(map[string]any, len(body))
	for k, v := range body {
		switch k {
		case "stream", "stream_options", "metadata", "user", "store", "service_tier":
			continue
		}
		c[k] = v
	}
	b, _ := json.Marshal(c) // encoding/json sorts map keys
	return b
}

// Where a hit was found.
const (
	TierMemory = "memory"
	TierDisk   = "disk"
)

// Entry is one cached answer.
type Entry struct {
	Family     string       `json:"family"`
	Body       []byte       `json:"body"`  // the masked, non-streamed answer
	Model      string       `json:"model"` // the model that answered
	Connection string       `json:"connection"`
	Hosting    string       `json:"hosting"`
	Usage      router.Usage `json:"usage"` // the original usage, for savings
	CostUSD    float64      `json:"cost_usd"`
	Created    time.Time    `json:"created"`

	// Tier is where this hit was found. It is not stored.
	Tier string `json:"-"`
}

// Stats describe the cache.
type Stats struct {
	Entries int       `json:"entries"` // in-process tier
	Bytes   int64     `json:"bytes"`   // in-process tier
	Hits    int64     `json:"hits"`    // both tiers
	Misses  int64     `json:"misses"`
	Evicted int64     `json:"evicted"` // from the in-process tier
	Disk    DiskStats `json:"disk"`
}

// DiskStats describe the cache store behind the in-process tier.
type DiskStats struct {
	// State is off (the policy keeps the cache in memory only), on, or
	// unavailable (the policy asks for it, and the file cannot be used).
	State    string `json:"state"`
	Entries  int64  `json:"entries"`
	Bytes    int64  `json:"bytes"`
	MaxBytes int64  `json:"max_bytes"`
	Hits     int64  `json:"hits"`
	Errors   int64  `json:"errors"`
	Dropped  int64  `json:"dropped"` // writes skipped because the write queue was full
	Error    string `json:"error,omitempty"`
}

// Settings come from the policy (cache.exact).
type Settings struct {
	MaxMemoryBytes int64 // max_size_mb
	Persist        bool  // persist
	MaxDiskBytes   int64 // max_disk_mb
}

const (
	diskReadTimeout = 250 * time.Millisecond
	queueSize       = 4096
	batchSize       = 128
	flushEvery      = 100 * time.Millisecond
	trimEvery       = time.Minute
	statsEvery      = 5 * time.Second
)

// Exact is the exact cache: the in-process tier, and, when the policy keeps
// entries on disk, a cache store behind it.
type Exact struct {
	mem    *Memory
	enc    *zstd.Encoder
	dec    *zstd.Decoder
	hits   atomic.Int64
	misses atomic.Int64

	open func() (store.CacheStore, error)
	logf func(format string, a ...any)

	mu      sync.Mutex // guards opening and closing
	disk    atomic.Pointer[diskHandle]
	openErr atomic.Pointer[string]
	closed  bool
	stop    chan struct{}
	stopped chan struct{}

	persist atomic.Bool
	maxDisk atomic.Int64
	ops     chan op
	purges  chan purgeReq // handled by the writer, after the writes queued before

	diskHits    atomic.Int64
	diskErrors  atomic.Int64
	diskDropped atomic.Int64
	diskStats   atomic.Pointer[store.CacheStoreStats]
	lastErrLog  atomic.Int64
}

type diskHandle struct{ s store.CacheStore }

type opKind uint8

const (
	opPut opKind = iota
	opTouch
	opDelete
)

type op struct {
	kind opKind
	rec  store.CacheRecord
}

// New returns an exact cache held in memory, up to maxMemoryBytes of sealed
// entries. UseDisk and Configure add the cache store.
func New(maxMemoryBytes int64) *Exact {
	enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	dec, _ := zstd.NewReader(nil)
	return &Exact{mem: newMemory(maxMemoryBytes), enc: enc, dec: dec, ops: make(chan op, queueSize), purges: make(chan purgeReq), logf: func(string, ...any) {}}
}

// UseDisk sets how the cache store is opened. It is opened by Configure, the
// first time the policy sets persist.
func (e *Exact) UseDisk(open func() (store.CacheStore, error), logf func(format string, a ...any)) {
	e.open = open
	if logf != nil {
		e.logf = logf
	}
}

// Configure applies the policy settings, at start and at each policy reload.
// When persist is set and the store is not open yet, it opens it. An error
// means the store cannot be used: the cache keeps serving from memory, and a
// later Configure tries again.
func (e *Exact) Configure(s Settings) error {
	e.mem.SetMaxBytes(s.MaxMemoryBytes)
	e.maxDisk.Store(s.MaxDiskBytes)
	e.persist.Store(s.Persist)
	if !s.Persist || e.open == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.disk.Load() != nil {
		return nil
	}
	d, err := e.open()
	if err != nil {
		msg := err.Error()
		e.openErr.Store(&msg)
		return err
	}
	e.openErr.Store(nil)
	e.disk.Store(&diskHandle{s: d})
	e.stop, e.stopped = make(chan struct{}), make(chan struct{})
	go e.run(d, e.stop, e.stopped)
	return nil
}

// Close writes the entries still queued, then closes the cache store.
func (e *Exact) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	h := e.disk.Swap(nil)
	if h == nil {
		return nil
	}
	close(e.stop)
	select {
	case <-e.stopped:
	case <-time.After(10 * time.Second):
		e.logf("cache file: pending writes did not finish; the last entries are not kept")
	}
	return h.s.Close()
}

// active returns the cache store when the policy keeps entries on disk.
func (e *Exact) active() store.CacheStore {
	if !e.persist.Load() {
		return nil
	}
	if h := e.disk.Load(); h != nil {
		return h.s
	}
	return nil
}

// SemanticStore returns the cache file as a semantic store, when the policy
// keeps the cache on disk and the file is open; nil otherwise.
func (e *Exact) SemanticStore() store.SemanticStore {
	if s, ok := e.active().(store.SemanticStore); ok {
		return s
	}
	return nil
}

// Get returns the entry for a fingerprint, decrypted with the org's key. It
// looks in memory first, then in the cache store; an entry found on disk is
// copied into memory.
func (e *Exact) Get(ctx context.Context, orgKey []byte, org, fp string) (*Entry, bool) {
	if sealed, ok := e.mem.get(org, fp); ok {
		if ent, err := e.unseal(orgKey, org, fp, sealed); err == nil {
			ent.Tier = TierMemory
			e.hits.Add(1)
			return ent, true
		}
	}
	if d := e.active(); d != nil {
		if ent, ok := e.getDisk(ctx, d, orgKey, org, fp); ok {
			e.hits.Add(1)
			return ent, true
		}
	}
	e.misses.Add(1)
	return nil, false
}

func (e *Exact) getDisk(ctx context.Context, d store.CacheStore, orgKey []byte, org, fp string) (*Entry, bool) {
	rctx, cancel := context.WithTimeout(ctx, diskReadTimeout)
	defer cancel()
	rec, err := d.GetEntry(rctx, fp)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) && ctx.Err() == nil {
			e.diskError(err)
		}
		return nil, false
	}
	if rec.OrgID != org || !time.Now().Before(rec.Expires) {
		return nil, false // expired entries are removed by the cleanup job
	}
	ent, err := e.unseal(orgKey, org, fp, rec.Sealed)
	if err != nil {
		// Sealed under another master key, or damaged: it can never be read.
		e.enqueue(op{kind: opDelete, rec: store.CacheRecord{Key: fp}})
		return nil, false
	}
	e.mem.put(org, fp, rec.Sealed, rec.Expires)
	e.enqueue(op{kind: opTouch, rec: store.CacheRecord{Key: fp}})
	e.diskHits.Add(1)
	ent.Tier = TierDisk
	return ent, true
}

// Put stores an entry in memory, and queues it for the cache store. It never
// waits for the disk. labels name it for a later purge (Label).
func (e *Exact) Put(orgKey []byte, org, fp string, ent *Entry, ttl time.Duration, labels ...string) error {
	raw, err := json.Marshal(ent)
	if err != nil {
		return err
	}
	sealed, err := store.Seal(orgKey, e.enc.EncodeAll(raw, nil), []byte(org+"/"+fp))
	if err != nil {
		return err
	}
	expires := time.Now().Add(ttl)
	e.mem.put(org, fp, sealed, expires)
	if e.active() != nil {
		e.enqueue(op{kind: opPut, rec: store.CacheRecord{Key: fp, OrgID: org, Sealed: sealed, Expires: expires, Labels: labels}})
	}
	return nil
}

func (e *Exact) unseal(orgKey []byte, org, fp string, sealed []byte) (*Entry, error) {
	plain, err := store.Open(orgKey, sealed, []byte(org+"/"+fp))
	if err != nil {
		return nil, err
	}
	raw, err := e.dec.DecodeAll(plain, nil)
	if err != nil {
		return nil, err
	}
	var ent Entry
	if err := json.Unmarshal(raw, &ent); err != nil {
		return nil, err
	}
	return &ent, nil
}

// Repeat reports whether the same caller sent the same request within the
// window, which is usually a "regenerate" click. It records this request.
func (e *Exact) Repeat(caller, fp string, window time.Duration) bool {
	return e.mem.Repeat(caller, fp, window)
}

// Stats returns cache statistics. The disk figures are refreshed in the
// background, every few seconds while entries are written.
func (e *Exact) Stats() Stats {
	s := e.mem.stats()
	s.Hits, s.Misses = e.hits.Load(), e.misses.Load()
	ds := DiskStats{State: "off", MaxBytes: e.maxDisk.Load(), Hits: e.diskHits.Load(), Errors: e.diskErrors.Load(), Dropped: e.diskDropped.Load()}
	if e.persist.Load() {
		if e.disk.Load() != nil {
			ds.State = "on"
		} else {
			ds.State = "unavailable"
			if msg := e.openErr.Load(); msg != nil {
				ds.Error = *msg
			}
		}
	}
	if st := e.diskStats.Load(); st != nil {
		ds.Entries, ds.Bytes = st.Entries, st.Bytes
	}
	s.Disk = ds
	return s
}

func (e *Exact) enqueue(o op) {
	select {
	case e.ops <- o:
	default:
		e.diskDropped.Add(1)
	}
}

func (e *Exact) diskError(err error) {
	e.diskErrors.Add(1)
	now := time.Now().Unix()
	if last := e.lastErrLog.Load(); now-last >= 60 && e.lastErrLog.CompareAndSwap(last, now) {
		e.logf("cache file: %v (the exact cache keeps serving from memory)", err)
	}
}

// run is the only writer of the cache store: it writes queued entries in
// small batches and runs the cleanup job.
func (e *Exact) run(d store.CacheStore, stop <-chan struct{}, stopped chan<- struct{}) {
	defer close(stopped)
	flush := time.NewTicker(flushEvery)
	defer flush.Stop()
	trim := time.NewTicker(trimEvery)
	defer trim.Stop()
	var lastStats time.Time
	refresh := func(force bool) {
		if !force && time.Since(lastStats) < statsEvery {
			return
		}
		lastStats = time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if st, err := d.Stats(ctx); err == nil {
			e.diskStats.Store(&st)
		} else {
			e.diskError(err)
		}
	}
	e.trim(d)
	refresh(true)

	var batch []op
	write := func() {
		if len(batch) > 0 {
			e.write(d, batch)
			batch = batch[:0]
			refresh(false)
		}
	}
	for {
		select {
		case o := <-e.ops:
			batch = append(batch, o)
			if len(batch) >= batchSize {
				write()
			}
		case <-flush.C:
			write()
		case p := <-e.purges:
			// Drain what was queued before the purge, write it, then purge, so
			// that no earlier write lands after it.
		pending:
			for {
				select {
				case o := <-e.ops:
					batch = append(batch, o)
				default:
					break pending
				}
			}
			write()
			ctx, cancel := context.WithTimeout(context.Background(), purgeTimeout)
			n, err := d.Purge(ctx, p.label)
			cancel()
			p.done <- purgeResult{n, err}
			refresh(true)
		case <-trim.C:
			write()
			e.trim(d)
			refresh(true)
		case <-stop:
		drain:
			for {
				select {
				case o := <-e.ops:
					batch = append(batch, o)
				default:
					break drain
				}
			}
			write()
			return
		}
	}
}

func (e *Exact) write(d store.CacheStore, batch []op) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	puts := map[string]int{}
	var recs []store.CacheRecord
	var touches, deletes []string
	for _, o := range batch {
		switch o.kind {
		case opPut:
			if i, ok := puts[o.rec.Key]; ok {
				recs[i] = o.rec
				continue
			}
			puts[o.rec.Key] = len(recs)
			recs = append(recs, o.rec)
		case opTouch:
			touches = append(touches, o.rec.Key)
		case opDelete:
			deletes = append(deletes, o.rec.Key)
		}
	}
	if err := d.PutEntries(ctx, recs); err != nil {
		e.diskError(err)
	}
	if err := d.TouchEntries(ctx, touches, time.Now()); err != nil {
		e.diskError(err)
	}
	if err := d.DeleteEntries(ctx, deletes); err != nil {
		e.diskError(err)
	}
}

func (e *Exact) trim(d store.CacheStore) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := d.Trim(ctx, time.Now(), e.maxDisk.Load()); err != nil {
		e.diskError(err)
	}
}

// Memory is the in-process tier: sealed entries with a byte budget and a
// per-entry expiry, evicting the least recently used entry first.
type Memory struct {
	mu      sync.Mutex
	maxSize int64
	size    int64
	ll      *list.List
	items   map[string]*list.Element
	evicted int64
	// recent remembers when a key last sent a fingerprint, to detect a
	// "regenerate" click.
	recent map[string]time.Time
}

type item struct {
	key     string
	org     string
	sealed  []byte
	expires time.Time
}

func newMemory(maxBytes int64) *Memory {
	return &Memory{maxSize: maxBytes, ll: list.New(), items: map[string]*list.Element{}, recent: map[string]time.Time{}}
}

// SetMaxBytes changes the budget, for a policy reload.
func (m *Memory) SetMaxBytes(n int64) {
	m.mu.Lock()
	m.maxSize = n
	m.evict()
	m.mu.Unlock()
}

func (m *Memory) get(org, fp string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.items[fp]
	if !ok {
		return nil, false
	}
	it := el.Value.(*item)
	if it.org != org {
		return nil, false
	}
	if !time.Now().Before(it.expires) {
		m.remove(el)
		return nil, false
	}
	m.ll.MoveToFront(el)
	return it.sealed, true
}

func (m *Memory) put(org, fp string, sealed []byte, expires time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.items[fp]; ok {
		m.remove(el)
	}
	m.items[fp] = m.ll.PushFront(&item{key: fp, org: org, sealed: sealed, expires: expires})
	m.size += int64(len(sealed))
	m.evict()
}

// Repeat reports whether the same caller sent the same request within the
// window. A window of 0 switches the rule off. A repeat inside the window does
// not restart it, so steady repeats reach the cache once the window has passed.
func (m *Memory) Repeat(caller, fp string, window time.Duration) bool {
	if window <= 0 {
		return false
	}
	k := caller + "/" + fp
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	last, seen := m.recent[k]
	if seen && now.Sub(last) < window {
		return true
	}
	m.recent[k] = now
	if len(m.recent) > 100000 {
		for rk, t := range m.recent {
			if now.Sub(t) > window {
				delete(m.recent, rk)
			}
		}
	}
	return false
}

func (m *Memory) stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Stats{Entries: len(m.items), Bytes: m.size, Evicted: m.evicted}
}

func (m *Memory) remove(el *list.Element) {
	it := el.Value.(*item)
	m.ll.Remove(el)
	delete(m.items, it.key)
	m.size -= int64(len(it.sealed))
}

func (m *Memory) evict() {
	for m.size > m.maxSize && m.ll.Len() > 0 {
		m.remove(m.ll.Back())
		m.evicted++
	}
}
