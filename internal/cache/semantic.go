package cache

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/Kytherion/KyGate/internal/store"
)

// Semantic is the semantic cache (OP-3), which runs without the Guard
// (architecture §3.4, §4.5):
//
//   - It compares only the last user message. Everything before it must be
//     identical: the caller passes a context fingerprint over the rest of the
//     request, and only entries of that context are candidates.
//   - Matching has two stages: cosine similarity of embeddings over a strict
//     threshold, then the hard checks (HardCheck).
//   - Entries hold the masked last message, its embedding, and the masked
//     answer, sealed like exact-cache entries. They live in cache.db when the
//     policy keeps the cache on disk, in memory otherwise.
//   - It fails open: every error is a miss.
type Semantic struct {
	disk func() store.SemanticStore
	mem  *semMemory
	enc  *zstd.Encoder
	dec  *zstd.Decoder
	logf func(format string, a ...any)

	lookups, hits, shadow, rejected, misses, errs, admitted atomic.Int64
	lastErrLog                                              atomic.Int64
	trimming                                                atomic.Bool
}

// candidatesPerContext bounds the entries compared for one lookup.
const candidatesPerContext = 200

// NewSemantic returns a semantic cache. disk returns the cache file when it is
// in use (Exact.SemanticStore), or nil to keep entries in memory.
func NewSemantic(disk func() store.SemanticStore, logf func(format string, a ...any)) *Semantic {
	enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	dec, _ := zstd.NewReader(nil)
	if disk == nil {
		disk = func() store.SemanticStore { return nil }
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Semantic{disk: disk, mem: newSemMemory(), enc: enc, dec: dec, logf: logf}
}

func (s *Semantic) store() store.SemanticStore {
	if d := s.disk(); d != nil {
		return d
	}
	return s.mem
}

// Match is a semantic lookup's result.
type Match struct {
	Entry      *Entry
	Similarity float64
}

// Lookup returns the best stored entry of this context whose embedding is at
// least minSim similar to vec and whose last message passes the hard checks.
// shadow only changes the counters: the caller decides whether to serve it.
func (s *Semantic) Lookup(ctx context.Context, orgKey []byte, org, contextFP, text string, vec []float32, minSim float64, shadow bool) (Match, bool) {
	s.lookups.Add(1)
	recs, err := s.store().ListSemantic(ctx, org, contextFP, time.Now(), candidatesPerContext)
	if err != nil {
		s.error(err)
		s.misses.Add(1)
		return Match{}, false
	}
	q := normalize(vec)
	type cand struct {
		p   *semPayload
		sim float64
	}
	var cands []cand
	for _, r := range recs {
		p, err := s.unseal(orgKey, org, r.Key, r.Sealed)
		if err != nil {
			continue // sealed under another master key, or damaged
		}
		if sim := dot(q, p.vector()); sim >= minSim {
			cands = append(cands, cand{p, sim})
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].sim > cands[j].sim })
	for _, c := range cands {
		if HardCheck(text, c.p.Text) != "" {
			s.rejected.Add(1)
			continue
		}
		e := c.p.Entry
		e.Tier = TierSemantic
		if shadow {
			s.shadow.Add(1)
		} else {
			s.hits.Add(1)
		}
		return Match{Entry: &e, Similarity: c.sim}, true
	}
	s.misses.Add(1)
	return Match{}, false
}

// Put stores an answer for a last message and its embedding. It never waits
// for the disk.
func (s *Semantic) Put(orgKey []byte, org, contextFP, key, text string, vec []float32, e *Entry, ttl time.Duration, maxEntries int, labels ...string) {
	p := semPayload{Text: text, Vec: encodeVector(normalize(vec)), Entry: *e}
	raw, err := json.Marshal(p)
	if err != nil {
		return
	}
	sealed, err := store.Seal(orgKey, s.enc.EncodeAll(raw, nil), aadSemantic(org, key))
	if err != nil {
		return
	}
	rec := store.SemanticRecord{Key: key, Context: contextFP, OrgID: org, Sealed: sealed, Expires: time.Now().Add(ttl), Labels: labels}
	st := s.store()
	n := s.admitted.Add(1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := st.PutSemantic(ctx, rec); err != nil {
			s.error(err)
			return
		}
		if n%64 == 1 && s.trimming.CompareAndSwap(false, true) {
			defer s.trimming.Store(false)
			if _, err := st.TrimSemantic(ctx, time.Now(), maxEntries); err != nil {
				s.error(err)
			}
		}
	}()
}

// SemanticStats describe the semantic cache since the start.
type SemanticStats struct {
	Lookups  int64  `json:"lookups"`
	Hits     int64  `json:"hits"`        // served
	Shadow   int64  `json:"shadow_hits"` // found in shadow mode, not served
	Rejected int64  `json:"rejected"`    // similar enough, stopped by the hard checks
	Misses   int64  `json:"misses"`
	Errors   int64  `json:"errors"`
	Admitted int64  `json:"admitted"`
	Entries  int64  `json:"entries"`
	Bytes    int64  `json:"bytes"`
	Where    string `json:"where"` // disk | memory
}

// Stats returns the counters and the size of the store.
func (s *Semantic) Stats(ctx context.Context) SemanticStats {
	st := SemanticStats{Lookups: s.lookups.Load(), Hits: s.hits.Load(), Shadow: s.shadow.Load(), Rejected: s.rejected.Load(),
		Misses: s.misses.Load(), Errors: s.errs.Load(), Admitted: s.admitted.Load(), Where: "memory"}
	if s.disk() != nil {
		st.Where = "disk"
	}
	if cs, err := s.store().SemanticStats(ctx); err == nil {
		st.Entries, st.Bytes = cs.Entries, cs.Bytes
	}
	return st
}

// RecordError counts a failure outside the store, such as an embedding call.
func (s *Semantic) RecordError(err error) { s.error(err) }

func (s *Semantic) error(err error) {
	s.errs.Add(1)
	now := time.Now().Unix()
	if last := s.lastErrLog.Load(); now-last >= 60 && s.lastErrLog.CompareAndSwap(last, now) {
		s.logf("semantic cache: %v (requests continue without it)", err)
	}
}

// TierSemantic marks an entry found by the semantic cache.
const TierSemantic = "semantic"

type semPayload struct {
	Text  string `json:"t"` // the masked last user message
	Vec   []byte `json:"v"` // its embedding, normalized, float32 little-endian
	Entry Entry  `json:"e"`
}

func (p *semPayload) vector() []float32 {
	v := make([]float32, len(p.Vec)/4)
	for i := range v {
		v[i] = math.Float32frombits(binary.LittleEndian.Uint32(p.Vec[i*4:]))
	}
	return v
}

func encodeVector(v []float32) []byte {
	b := make([]byte, len(v)*4)
	for i, f := range v {
		binary.LittleEndian.PutUint32(b[i*4:], math.Float32bits(f))
	}
	return b
}

func aadSemantic(org, key string) []byte { return []byte(org + "/semantic/" + key) }

func (s *Semantic) unseal(orgKey []byte, org, key string, sealed []byte) (*semPayload, error) {
	plain, err := store.Open(orgKey, sealed, aadSemantic(org, key))
	if err != nil {
		return nil, err
	}
	raw, err := s.dec.DecodeAll(plain, nil)
	if err != nil {
		return nil, err
	}
	var p semPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if len(p.Vec)%4 != 0 {
		return nil, errors.New("bad vector")
	}
	return &p, nil
}

func normalize(v []float32) []float32 {
	var n float64
	for _, f := range v {
		n += float64(f) * float64(f)
	}
	out := make([]float32, len(v))
	if n == 0 {
		return out
	}
	n = math.Sqrt(n)
	for i, f := range v {
		out[i] = float32(float64(f) / n)
	}
	return out
}

// Similarity is the cosine similarity of two vectors.
func Similarity(a, b []float32) float64 { return dot(normalize(a), normalize(b)) }

func dot(a, b []float32) float64 {
	if len(a) != len(b) {
		return 0 // another embedding model: never a match
	}
	var s float64
	for i := range a {
		s += float64(a[i]) * float64(b[i])
	}
	return s
}

// semMemory keeps semantic entries in memory when the policy keeps the cache
// in memory only.
type semMemory struct {
	mu      sync.Mutex
	byCtx   map[string][]store.SemanticRecord
	entries int
}

func newSemMemory() *semMemory { return &semMemory{byCtx: map[string][]store.SemanticRecord{}} }

func (m *semMemory) ListSemantic(_ context.Context, org, contextFP string, now time.Time, limit int) ([]store.SemanticRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.SemanticRecord
	list := m.byCtx[contextFP]
	for i := len(list) - 1; i >= 0 && len(out) < limit; i-- {
		if r := list[i]; r.OrgID == org && now.Before(r.Expires) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *semMemory) PutSemantic(_ context.Context, r store.SemanticRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.byCtx[r.Context]
	for i, x := range list {
		if x.Key == r.Key {
			list = append(list[:i], list[i+1:]...)
			m.entries--
			break
		}
	}
	if len(list) >= candidatesPerContext {
		list = list[1:]
		m.entries--
	}
	m.byCtx[r.Context] = append(list, r)
	m.entries++
	return nil
}

func (m *semMemory) TrimSemantic(_ context.Context, now time.Time, maxEntries int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var removed int64
	for k, list := range m.byCtx {
		kept := list[:0]
		for _, r := range list {
			if now.Before(r.Expires) {
				kept = append(kept, r)
			} else {
				removed++
				m.entries--
			}
		}
		if len(kept) == 0 {
			delete(m.byCtx, k)
		} else {
			m.byCtx[k] = kept
		}
	}
	// Over the limit: drop whole contexts, an arbitrary one at a time.
	for k, list := range m.byCtx {
		if maxEntries <= 0 || m.entries <= maxEntries {
			break
		}
		removed += int64(len(list))
		m.entries -= len(list)
		delete(m.byCtx, k)
	}
	return removed, nil
}

func (m *semMemory) SemanticStats(context.Context) (store.CacheStoreStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var s store.CacheStoreStats
	for _, list := range m.byCtx {
		for _, r := range list {
			s.Entries++
			s.Bytes += int64(len(r.Sealed))
		}
	}
	return s, nil
}

func (m *semMemory) PurgeSemantic(_ context.Context, label string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var removed int64
	for k, list := range m.byCtx {
		kept := list[:0]
		for _, r := range list {
			if label == "" || hasLabel(r.Labels, label) {
				removed++
				m.entries--
			} else {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			delete(m.byCtx, k)
		} else {
			m.byCtx[k] = kept
		}
	}
	return removed, nil
}

func hasLabel(labels []string, l string) bool {
	for _, x := range labels {
		if x == l {
			return true
		}
	}
	return false
}
