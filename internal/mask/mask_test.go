package mask

import (
	"strings"
	"testing"
)

func TestPlaceholdersStableAndOrdered(t *testing.T) {
	m := NewValueMap()
	a := m.Placeholder("EMAIL", "a@x.io")
	b := m.Placeholder("EMAIL", "b@x.io")
	a2 := m.Placeholder("EMAIL", "a@x.io")
	if a != "[EMAIL_1]" || b != "[EMAIL_2]" || a2 != a {
		t.Fatalf("got %s %s %s", a, b, a2)
	}
	if p := m.Placeholder("dict/project-codenames", "Apollo"); p != "[DICT_PROJECT_CODENAMES_1]" {
		t.Fatalf("got %s", p)
	}
}

func TestApplyAndRehydrate(t *testing.T) {
	m := NewValueMap()
	text := "Card 4111 and IBAN DE89 end"
	out := m.Apply(text, []Span{{Start: 5, End: 9, Entity: "CREDIT_CARD"}, {Start: 19, End: 23, Entity: "IBAN", Redact: true}})
	if out != "Card [CREDIT_CARD_1] and IBAN [REDACTED_IBAN] end" {
		t.Fatalf("got %q", out)
	}
	if got := m.Rehydrate("Dear [CREDIT_CARD_1], [REDACTED_IBAN]", false); got != "Dear 4111, [REDACTED_IBAN]" {
		t.Fatalf("got %q", got)
	}
}

func TestRehydrateJSONEscapes(t *testing.T) {
	m := NewValueMap()
	m.Placeholder("PERSON", `Ann "Q" O'Neil\x`)
	got := m.Rehydrate(`{"to":"[PERSON_1]"}`, true)
	if got != `{"to":"Ann \"Q\" O'Neil\\x"}` {
		t.Fatalf("got %s", got)
	}
}

// A placeholder split across stream events must come out whole.
func TestStreamSplitPlaceholder(t *testing.T) {
	m := NewValueMap()
	m.Placeholder("EMAIL", "alice@example.com")
	m.Placeholder("EMAIL", "bob@example.com")
	pieces := []string{"Hi [EM", "AIL_", "1], and [", "EMAIL_2", "] and [not a placeholder] and [EMAIL_9] [E"}
	for split := 0; split < 3; split++ {
		s := m.NewStream(false)
		var b strings.Builder
		for _, p := range pieces {
			b.WriteString(s.Push(p))
		}
		b.WriteString(s.Flush())
		want := "Hi alice@example.com, and bob@example.com and [not a placeholder] and [EMAIL_9] [E"
		if b.String() != want {
			t.Fatalf("got %q", b.String())
		}
	}
	// Character by character.
	s := m.NewStream(false)
	var b strings.Builder
	for _, r := range "x[EMAIL_2]y" {
		b.WriteString(s.Push(string(r)))
	}
	b.WriteString(s.Flush())
	if b.String() != "xbob@example.comy" {
		t.Fatalf("got %q", b.String())
	}
}

func TestStreamNoValuesPassesThrough(t *testing.T) {
	m := NewValueMap()
	s := m.NewStream(false)
	if got := s.Push("[EM"); got != "[EM" {
		t.Fatalf("with no masked values nothing is held back, got %q", got)
	}
}
