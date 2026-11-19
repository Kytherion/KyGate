package guard

import (
	"container/list"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"

	"github.com/Kytherion/KyGate/internal/detect"
)

// Memo holds the Guard's findings per segment, under a keyed hash of the
// segment's content (architecture §4.3, §4.4). Each turn of a conversation
// asks the Guard only about content it has not seen, and an earlier turn keeps
// the findings it was first masked with: ML scores are not exactly
// reproducible, so stability comes from the memo, not from running the model
// again (invariant 4).
//
// The memo holds offsets, types, and scores, never text: the key is an HMAC,
// and a finding names a position, not a value (invariant 3). It lives in the
// gateway's memory in Solo; Team moves it to Valkey.
type Memo struct {
	mu    sync.Mutex
	key   []byte
	max   int
	ll    *list.List
	items map[string]*list.Element
	hits  int64
	miss  int64
}

type memoItem struct {
	key      string
	findings []detect.Finding // Segment is 0; offsets are into the segment's text
	threats  []Threat
}

// NewMemo returns a memo of up to max segments, keyed with key.
func NewMemo(key []byte, max int) *Memo {
	return &Memo{key: key, max: max, ll: list.New(), items: map[string]*list.Element{}}
}

// Key is the memo key of one segment's inspection. It covers everything that
// changes the answer: the policy's cache version (data rules), the Guard's
// models, the types asked for, and the segment's role, kind, and text.
func (m *Memo) Key(cacheVersion, guardModels string, entityTypes, threatTypes []string, s Segment) string {
	h := hmac.New(sha256.New, m.key)
	w := func(b string) {
		var n [8]byte
		binary.LittleEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write([]byte(b))
	}
	w("memo/v1")
	w(cacheVersion)
	w(guardModels)
	for _, t := range entityTypes {
		w("e:" + t)
	}
	for _, t := range threatTypes {
		w("t:" + t)
	}
	w(s.Role.String())
	w(s.Kind.String())
	if s.Untrusted {
		w("untrusted")
	}
	w(s.Text)
	return hex.EncodeToString(h.Sum(nil))
}

// Get returns the memoized findings and threats of one segment, with their
// segment index set to idx.
func (m *Memo) Get(key string, idx int) ([]detect.Finding, []Threat, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.items[key]
	if !ok {
		m.miss++
		return nil, nil, false
	}
	m.hits++
	m.ll.MoveToFront(el)
	it := el.Value.(*memoItem)
	f := make([]detect.Finding, len(it.findings))
	for i, x := range it.findings {
		x.Segment = idx
		f[i] = x
	}
	t := make([]Threat, len(it.threats))
	for i, x := range it.threats {
		x.Segment = idx
		t[i] = x
	}
	return f, t, true
}

// Put memoizes one segment's findings and threats.
func (m *Memo) Put(key string, findings []detect.Finding, threats []Threat) {
	it := &memoItem{key: key}
	for _, f := range findings {
		f.Segment = 0
		it.findings = append(it.findings, f)
	}
	for _, t := range threats {
		t.Segment = 0
		it.threats = append(it.threats, t)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.items[key]; ok {
		el.Value = it
		m.ll.MoveToFront(el)
		return
	}
	m.items[key] = m.ll.PushFront(it)
	for m.ll.Len() > m.max {
		old := m.ll.Back()
		m.ll.Remove(old)
		delete(m.items, old.Value.(*memoItem).key)
	}
}

// MemoStats describe the memo.
type MemoStats struct {
	Segments int   `json:"segments"`
	Hits     int64 `json:"hits"`
	Misses   int64 `json:"misses"`
}

// Stats returns the memo's size and hit counts.
func (m *Memo) Stats() MemoStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return MemoStats{Segments: m.ll.Len(), Hits: m.hits, Misses: m.miss}
}
