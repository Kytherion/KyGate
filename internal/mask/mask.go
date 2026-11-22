// Package mask turns findings into typed, numbered placeholders and puts the
// real values back in answers, including streamed answers (capability PR-4).
//
// The value map lives only in gateway memory, for one request (principle 3).
// Clients resend the whole conversation on every call, so the map is rebuilt
// from the request each time and nothing sensitive is stored.
package mask

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
)

// placeholderRe matches the placeholder shape, such as [EMAIL_2] or [DICT_CODENAMES_1].
var placeholderRe = regexp.MustCompile(`\[[A-Z][A-Z0-9_]*_[0-9]+\]`)

// LiteralType is the placeholder type of text a request already holds in the
// shape of a placeholder of a type the policy masks, such as "[EMAIL_1]"
// typed by a user or kept from an earlier answer. Such text is masked like a
// value, as [LITERAL_n], so it can never be read as, or put back as, a value
// of this request; the caller gets it back as written.
const LiteralType = "LITERAL"

// LiteralSpans returns the parts of text that have the shape of a
// placeholder whose type is in types, as byte offsets.
func LiteralSpans(text string, types map[string]bool) [][2]int {
	if len(types) == 0 || !strings.Contains(text, "[") {
		return nil
	}
	var out [][2]int
	for _, m := range placeholderRe.FindAllStringIndex(text, -1) {
		p := text[m[0]+1 : m[1]-1] // TYPE_N
		if types[p[:strings.LastIndexByte(p, '_')]] {
			out = append(out, [2]int{m[0], m[1]})
		}
	}
	return out
}

// UnknownPlaceholders counts placeholder-shaped text in answers that matched
// no value: usually a placeholder the model altered (architecture §4.3).
var UnknownPlaceholders atomic.Int64

// ValueMap maps placeholders to real values for one request.
type ValueMap struct {
	byValue   map[string]string // type + "\x00" + value -> placeholder
	values    map[string]string // placeholder -> value
	counters  map[string]int
	maxLength int
}

// NewValueMap returns an empty map.
func NewValueMap() *ValueMap {
	return &ValueMap{byValue: map[string]string{}, values: map[string]string{}, counters: map[string]int{}}
}

// Holds reports whether text contains a placeholder of this map.
func (m *ValueMap) Holds(text string) bool {
	if len(m.values) == 0 || !strings.Contains(text, "[") {
		return false
	}
	for _, p := range placeholderRe.FindAllString(text, -1) {
		if _, ok := m.values[p]; ok {
			return true
		}
	}
	return false
}

// Len is the number of distinct masked values.
func (m *ValueMap) Len() int { return len(m.values) }

// PlaceholderType turns an entity type into the label used in placeholders.
// "dict/project-codenames" becomes "DICT_PROJECT_CODENAMES".
func PlaceholderType(entity string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(entity) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	s := strings.Trim(b.String(), "_")
	if s == "" || s[0] < 'A' || s[0] > 'Z' {
		s = "X" + s
	}
	return s
}

// Placeholder returns the placeholder for a value, creating it on first use.
// The same value always gets the same placeholder within a request, and
// numbers follow the order of first appearance.
func (m *ValueMap) Placeholder(entity, value string) string {
	k := entity + "\x00" + value
	if p, ok := m.byValue[k]; ok {
		return p
	}
	t := PlaceholderType(entity)
	m.counters[t]++
	p := "[" + t + "_" + strconv.Itoa(m.counters[t]) + "]"
	m.byValue[k] = p
	m.values[p] = value
	if len(p) > m.maxLength {
		m.maxLength = len(p)
	}
	return p
}

// Span is one region of a segment to replace.
type Span struct {
	Start, End int
	Entity     string
	Redact     bool // permanent: replaced and never put back
}

// Apply replaces spans in text. Spans must be sorted and must not overlap.
func (m *ValueMap) Apply(text string, spans []Span) string {
	if len(spans) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, s := range spans {
		if s.Start < last || s.End > len(text) || s.Start >= s.End {
			continue
		}
		b.WriteString(text[last:s.Start])
		if s.Redact {
			b.WriteString("[REDACTED_" + PlaceholderType(s.Entity) + "]")
		} else {
			b.WriteString(m.Placeholder(s.Entity, text[s.Start:s.End]))
		}
		last = s.End
	}
	b.WriteString(text[last:])
	return b.String()
}

// Rehydrate puts real values back. With jsonString set, each value is escaped
// for use inside a JSON string literal, as in tool-call arguments.
func (m *ValueMap) Rehydrate(text string, jsonString bool) string {
	if len(m.values) == 0 || !strings.Contains(text, "[") {
		countUnknown(text)
		return text
	}
	return placeholderRe.ReplaceAllStringFunc(text, func(p string) string {
		v, ok := m.values[p]
		if !ok {
			UnknownPlaceholders.Add(1)
			return p
		}
		if jsonString {
			return escapeJSON(v)
		}
		return v
	})
}

func countUnknown(text string) {
	if strings.Contains(text, "[") {
		UnknownPlaceholders.Add(int64(len(placeholderRe.FindAllStringIndex(text, -1))))
	}
}

func escapeJSON(v string) string {
	b, _ := json.Marshal(v)
	return string(b[1 : len(b)-1])
}

// Stream rehydrates text that arrives in pieces. A placeholder can be split
// across stream events ("[EM", "AIL_", "2]"), so text is held back only while
// it could still be the start of a placeholder.
type Stream struct {
	m          *ValueMap
	jsonString bool
	held       string
}

// NewStream returns a stream rehydrator for one text channel.
func (m *ValueMap) NewStream(jsonString bool) *Stream {
	return &Stream{m: m, jsonString: jsonString}
}

// Push takes the next piece of text and returns what can be emitted now.
func (s *Stream) Push(piece string) string {
	data := s.held + piece
	s.held = ""
	if len(s.m.values) == 0 {
		countUnknown(data)
		return data
	}
	cut := len(data)
	if i := strings.LastIndexByte(data, '['); i >= 0 && !strings.Contains(data[i:], "]") {
		tail := data[i:]
		if len(tail) < s.m.maxLength && couldBePlaceholder(tail) {
			cut = i
		}
	}
	s.held = data[cut:]
	return s.m.Rehydrate(data[:cut], s.jsonString)
}

// Flush returns any text still held back, at the end of the channel.
func (s *Stream) Flush() string {
	data := s.held
	s.held = ""
	return s.m.Rehydrate(data, s.jsonString)
}

// Pending reports whether text is held back.
func (s *Stream) Pending() bool { return s.held != "" }

func couldBePlaceholder(tail string) bool {
	for i, r := range tail {
		if i == 0 {
			if r != '[' {
				return false
			}
			continue
		}
		if !((r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}
