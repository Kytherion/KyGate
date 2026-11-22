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

// Only the shapes of the types asked for are literals.
func TestLiteralSpans(t *testing.T) {
	text := "a [EMAIL_1] b [STEP_2] c [CREDIT_CARD_10] d [email_1] [LITERAL_1]"
	var got []string
	for _, s := range LiteralSpans(text, map[string]bool{"EMAIL": true, "CREDIT_CARD": true, LiteralType: true}) {
		got = append(got, text[s[0]:s[1]])
	}
	if strings.Join(got, " ") != "[EMAIL_1] [CREDIT_CARD_10] [LITERAL_1]" {
		t.Fatalf("%v", got)
	}
	if LiteralSpans(text, nil) != nil {
		t.Fatal("no types, no literals")
	}
	// A literal is masked like a value, and comes back as written.
	m := NewValueMap()
	m.Placeholder("EMAIL", "a@x.io")
	masked := m.Apply("[EMAIL_1] or a@x.io", []Span{{Start: 0, End: 9, Entity: LiteralType}, {Start: 13, End: 19, Entity: "EMAIL"}})
	if masked != "[LITERAL_1] or [EMAIL_1]" || m.Rehydrate(masked, false) != "[EMAIL_1] or a@x.io" {
		t.Fatalf("%q", masked)
	}
}

// Rehydrating a stream in any pieces gives what rehydrating it whole gives.
func FuzzStreamEqualsWhole(f *testing.F) {
	f.Add("pay [CREDIT_CARD_1] now [EM", uint8(3), false)
	f.Add("[[EMAIL_1]] [EMAIL_1", uint8(1), true)
	f.Add(`{"to":"[EMAIL_1]","card":"[CREDIT_CARD_2]"}`, uint8(5), true)
	f.Fuzz(func(t *testing.T, s string, step uint8, js bool) {
		m := NewValueMap()
		m.Placeholder("CREDIT_CARD", "4111 1111 1111 1111")
		m.Placeholder("CREDIT_CARD", `5555 "5555" 4444`)
		m.Placeholder("EMAIL", "a@b.example")
		n := int(step%16) + 1
		st := m.NewStream(js)
		var got strings.Builder
		for i := 0; i < len(s); i += n {
			got.WriteString(st.Push(s[i:min(i+n, len(s))]))
		}
		got.WriteString(st.Flush())
		if want := m.Rehydrate(s, js); got.String() != want {
			t.Fatalf("pieces of %d: %q, whole: %q", n, got.String(), want)
		}
	})
}

func TestStreamNoValuesPassesThrough(t *testing.T) {
	m := NewValueMap()
	s := m.NewStream(false)
	if got := s.Push("[EM"); got != "[EM" {
		t.Fatalf("with no masked values nothing is held back, got %q", got)
	}
}
