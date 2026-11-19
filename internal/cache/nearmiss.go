package cache

// Near misses of the exact cache (a measurement before any
// per-client normalization, architecture §4.5). On an exact-cache miss, the
// request is compared with the same key's recent requests. When the closest
// one differs only outside the last user message, the miss was the same
// question asked again, and the differences are what defeated the cache: they
// are reported as labels such as "system:date" or "temperature:value".
//
// Nothing readable is kept. Each request is remembered, in memory only, as
// seeded hashes (hash/maphash) of its fields and of the lines of its long
// texts, under a seed drawn at random when the process starts and never
// stored. Labels name a field and a kind of difference, never a value. The
// comparison runs after the answer is sent, so it adds no latency.

import (
	"encoding/json"
	"fmt"
	"hash/maphash"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	nearMissRecent   = 32   // requests remembered per key and model
	nearMissKeys     = 1000 // keys remembered; the least recently seen goes first
	nearMissMaxLines = 4000 // lines hashed per text field
	nearMissMaxDiffs = 8    // more differing fields than this is a different request
)

// NearMiss remembers recent request shapes and explains exact-cache misses.
type NearMiss struct {
	seed   maphash.Seed
	mu     sync.Mutex
	rings  map[string]*nmRing
	clock  uint64
	lines  int // line hashes held by every remembered shape
	budget int // the most line hashes held; the oldest shapes go first

	// memo maps a line's hash to its loose hash: lines repeat from one
	// request to the next, and the volatile patterns are the costly part.
	memoMu sync.Mutex
	memo   map[uint64]uint64
}

const (
	nearMissMemo  = 1 << 20 // lines remembered; the memo restarts when full
	nearMissLines = 2 << 20 // line hashes held in all; the oldest shapes go first (about 32 MB)
)

type nmRing struct {
	shapes []*shape
	seen   uint64
}

// shape is one request, as keyed hashes.
type shape struct {
	size   int                 // line hashes held
	fields map[string]uint64   // leaf path -> hash of its value
	lines  map[string][]uint64 // text leaf path -> hash of each line
	loose  map[string][]uint64 // the same lines with volatile tokens replaced by their class
}

// NewNearMiss returns a tracker with a fresh random key.
func NewNearMiss() *NearMiss {
	return &NearMiss{seed: maphash.MakeSeed(), rings: map[string]*nmRing{}, memo: map[uint64]uint64{}, budget: nearMissLines}
}

// Observe explains a miss of the exact cache and remembers the request. scope
// groups requests that may be compared (a key and a model); body is the
// masked request body. It returns the labels of what differed from the
// closest recent request, or nil when nothing close enough was seen.
func (n *NearMiss) Observe(scope string, body map[string]any) []string {
	if n == nil {
		return nil
	}
	s, last := n.shapeOf(body)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.clock++
	r := n.rings[scope]
	if r == nil {
		if len(n.rings) >= nearMissKeys {
			n.evict()
		}
		r = &nmRing{}
		n.rings[scope] = r
	}
	r.seen = n.clock
	var best []string
	var prev *shape
	bestN := -1
	for _, p := range r.shapes {
		diffs, ok := differences(s, p, last)
		if ok && (bestN < 0 || len(diffs) < bestN) {
			best, bestN, prev = diffs, len(diffs), p
		}
	}
	r.shapes = append(r.shapes, s)
	n.lines += s.size
	if len(r.shapes) > nearMissRecent {
		n.lines -= r.shapes[0].size
		r.shapes = r.shapes[1:]
	}
	for n.lines > n.budget && n.dropOldest(r) {
	}
	if bestN <= 0 {
		return nil
	}
	return labels(best, s, prev, body)
}

func (n *NearMiss) evict() {
	var oldest string
	var at uint64
	for k, r := range n.rings {
		if oldest == "" || r.seen < at {
			oldest, at = k, r.seen
		}
	}
	for _, s := range n.rings[oldest].shapes {
		n.lines -= s.size
	}
	delete(n.rings, oldest)
}

// dropOldest drops the oldest shape of the least recently seen scope, keeping
// the newest shape of current. It reports whether it dropped one.
func (n *NearMiss) dropOldest(current *nmRing) bool {
	var victim *nmRing
	for _, r := range n.rings {
		if len(r.shapes) == 0 || (r == current && len(r.shapes) == 1) {
			continue
		}
		if victim == nil || r.seen < victim.seen {
			victim = r
		}
	}
	if victim == nil {
		return false
	}
	n.lines -= victim.shapes[0].size
	victim.shapes = victim.shapes[1:]
	return true
}

func (n *NearMiss) hash(parts ...string) uint64 {
	var h maphash.Hash
	h.SetSeed(n.seed)
	for _, p := range parts {
		h.WriteString(strconv.Itoa(len(p)))
		h.WriteByte(0)
		h.WriteString(p)
	}
	return h.Sum64()
}

// looseHash hashes a line with its volatile tokens replaced by their class.
// Every class holds a digit, so a line without one is its own loose form.
func (n *NearMiss) looseHash(line string, raw uint64) uint64 {
	if !strings.ContainsAny(line, "0123456789") {
		return raw
	}
	n.memoMu.Lock()
	l, ok := n.memo[raw]
	n.memoMu.Unlock()
	if ok {
		return l
	}
	l = n.hash(loosen(line))
	n.memoMu.Lock()
	if len(n.memo) >= nearMissMemo {
		n.memo = map[uint64]uint64{}
	}
	n.memo[raw] = l
	n.memoMu.Unlock()
	return l
}

// skipped are the body fields that never change an answer (as in Canonical).
var skipped = map[string]bool{"stream": true, "stream_options": true, "metadata": true, "user": true, "store": true, "service_tier": true}

// shapeOf hashes every leaf of the body. last is the path prefix of the last
// message when it is a user turn: a difference there is a new question.
func (n *NearMiss) shapeOf(body map[string]any) (*shape, string) {
	s := &shape{fields: map[string]uint64{}, lines: map[string][]uint64{}, loose: map[string][]uint64{}}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch t := v.(type) {
		case map[string]any:
			if len(t) == 0 {
				s.fields[path] = n.hash("{}")
			}
			for k, e := range t {
				if path == "" && skipped[k] {
					continue
				}
				walk(join(path, k), e)
			}
		case []any:
			s.fields[path+"#len"] = n.hash(strconv.Itoa(len(t)))
			for i, e := range t {
				walk(join(path, strconv.Itoa(i)), e)
			}
		case string:
			s.fields[path] = n.hash("s", t)
			if strings.Contains(t, "\n") || len(t) > 200 {
				ls := strings.Split(t, "\n")
				if len(ls) > nearMissMaxLines {
					ls = ls[:nearMissMaxLines]
				}
				h, l := make([]uint64, len(ls)), make([]uint64, len(ls))
				for i, line := range ls {
					h[i] = n.hash(line)
					l[i] = n.looseHash(line, h[i])
				}
				s.lines[path], s.loose[path] = h, l
				s.size += 2 * len(h)
			} else {
				s.loose[path] = []uint64{n.looseHash(t, n.hash(t))}
			}
		default:
			b, _ := json.Marshal(t)
			s.fields[path] = n.hash("v", string(b))
		}
	}
	walk("", body)
	last := ""
	if msgs, ok := body["messages"].([]any); ok && len(msgs) > 0 {
		if m, ok := msgs[len(msgs)-1].(map[string]any); ok && m["role"] == "user" {
			last = "messages." + strconv.Itoa(len(msgs)-1)
		}
	}
	return s, last
}

func join(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

// differences lists the leaf paths where a and b differ. ok is false when they
// differ in the last user message (a new question) or in too many places.
func differences(a, b *shape, last string) ([]string, bool) {
	var out []string
	seen := map[string]bool{}
	check := func(p string) bool {
		if seen[p] {
			return true
		}
		seen[p] = true
		if a.fields[p] == b.fields[p] {
			return true
		}
		if last != "" && (p == last || strings.HasPrefix(p, last+".")) {
			return false
		}
		out = append(out, p)
		return len(out) <= nearMissMaxDiffs
	}
	for p := range a.fields {
		if !check(p) {
			return nil, false
		}
	}
	for p := range b.fields {
		if !check(p) {
			return nil, false
		}
	}
	sort.Strings(out)
	return out, true
}

// Volatile tokens, by class, in the order they are replaced.
var volatile = []struct {
	name string
	re   *regexp.Regexp
}{
	{"id", regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)},
	{"date", regexp.MustCompile(`(?i)\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|\d{1,2}\.\d{1,2}\.\d{4}|(?:mon|tue|wed|thu|fri|sat|sun)[a-z]*,? (?:\d{1,2} )?(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]* \d{1,2}(?:,? \d{4})?)\b`)},
	{"time", regexp.MustCompile(`\b\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:\s?[AaPp][Mm])?\b|T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?`)},
	{"id", regexp.MustCompile(`(?i)\b[0-9a-f]{12,}\b`)},
	{"number", regexp.MustCompile(`\d+(?:\.\d+)?`)},
}

func loosen(s string) string {
	for _, v := range volatile {
		s = v.re.ReplaceAllString(s, "\x00"+v.name+"\x00")
	}
	return s
}

func kindsIn(s string) []string {
	var out []string
	for _, v := range volatile {
		if v.re.MatchString(s) {
			out = appendOnce(out, v.name)
		}
		s = v.re.ReplaceAllString(s, " ")
	}
	return out
}

func appendOnce(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// labels turns differing paths into "field:kind" labels, sorted and unique.
func labels(paths []string, s, prev *shape, body map[string]any) []string {
	var out []string
	for _, p := range paths {
		field := fieldName(p, body)
		for _, k := range kindOf(p, s, prev, body) {
			out = appendOnce(out, field+":"+k)
		}
	}
	sort.Strings(out)
	return out
}

// fieldName names a path without its indices: system, an earlier user turn,
// an assistant turn, a tool result, tools, or the top-level setting.
func fieldName(p string, body map[string]any) string {
	p = strings.TrimSuffix(p, "#len")
	parts := strings.Split(p, ".")
	switch parts[0] {
	case "messages":
		if len(parts) == 1 {
			return "messages (count)"
		}
		i, _ := strconv.Atoi(parts[1])
		msgs, _ := body["messages"].([]any)
		role := "message"
		if i < len(msgs) {
			if m, ok := msgs[i].(map[string]any); ok {
				role, _ = m["role"].(string)
			}
		}
		switch role {
		case "system", "developer":
			return "system"
		case "user":
			if containsToolResult(msgs, i) {
				return "tool result"
			}
			return "earlier user turn"
		case "assistant":
			return "assistant turn"
		case "tool":
			return "tool result"
		}
		return "message"
	case "system":
		return "system"
	case "tools", "functions", "tool_choice":
		return "tools"
	}
	return parts[0]
}

func containsToolResult(msgs []any, i int) bool {
	m, _ := msgs[i].(map[string]any)
	parts, _ := m["content"].([]any)
	for _, p := range parts {
		if pm, ok := p.(map[string]any); ok && pm["type"] == "tool_result" {
			return true
		}
	}
	return false
}

// kindOf says how a field differs: by volatile tokens only (date, time, id,
// number: the line is the same once they are replaced by their class), by
// whole lines added or removed ("lines"), by other text ("text"), or, for a
// number or a flag, "value"; "count" when a list changed length.
func kindOf(p string, s, prev *shape, body map[string]any) []string {
	if strings.HasSuffix(p, "#len") {
		return []string{"count"}
	}
	text, isText := lookup(body, p).(string)
	if !isText {
		return []string{"value"}
	}
	a, b := s.loose[p], prev.loose[p]
	if len(a) == 0 || len(b) == 0 {
		return []string{"text"}
	}
	if len(a) != len(b) {
		return []string{"lines"}
	}
	lines := strings.Split(text, "\n")
	var kinds []string
	for i := range a {
		raw := a[i] != b[i]
		if rl, pl := s.lines[p], prev.lines[p]; len(rl) == len(a) && len(pl) == len(b) {
			raw = rl[i] != pl[i]
		} else {
			raw = true // a short text: one line
		}
		if !raw {
			continue
		}
		if a[i] != b[i] {
			return []string{"text"}
		}
		if i < len(lines) {
			for _, k := range kindsIn(lines[i]) {
				kinds = appendOnce(kinds, k)
			}
		}
	}
	if len(kinds) == 0 {
		return []string{"text"}
	}
	sort.Strings(kinds)
	return kinds
}

// lookup returns the value at a dotted path.
func lookup(v any, p string) any {
	for _, k := range strings.Split(p, ".") {
		switch t := v.(type) {
		case map[string]any:
			v = t[k]
		case []any:
			i, err := strconv.Atoi(k)
			if err != nil || i >= len(t) {
				return nil
			}
			v = t[i]
		default:
			return nil
		}
	}
	return v
}

// String describes the tracker, for logs.
func (n *NearMiss) String() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return fmt.Sprintf("near-miss tracker: %d scopes", len(n.rings))
}
