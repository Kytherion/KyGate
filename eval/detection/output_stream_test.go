package detection

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/Kytherion/KyGate/internal/detect"
)

// TestStreamMatchesWhole is the differential gate of output inspection on
// streams: generated answers that mix prose with every construct output
// inspection knows (Markdown and HTML links and images, multi-line HTML,
// reference definitions used before or long after, bare addresses, secrets,
// private keys, protected placeholders), with tokens longer than the
// hold-back limit and lines longer than the rescan window, streamed in pieces
// of random sizes, must come out exactly as the same answer inspected whole,
// with the same counts, in enforce and in monitor mode.
func TestStreamMatchesWhole(t *testing.T) {
	rng := rand.New(rand.NewSource(20261119))
	docs := 100
	if testing.Short() {
		docs = 60
	}
	for d := 0; d < docs; d++ {
		text := genAnswer(rng, false)
		for _, enforce := range []bool{true, false} {
			rules := evalRules()
			rules.Enforce = enforce
			whole := detect.NewOutputInspector(rules)
			want := whole.Text(text, false)
			for _, sizes := range [][2]int{{1, 4}, {1, 40}, {200, 3000}} {
				in := detect.NewOutputInspector(rules)
				st := in.NewStream(false)
				var b strings.Builder
				for i := 0; i < len(text); {
					n := sizes[0] + rng.Intn(sizes[1]-sizes[0]+1)
					b.WriteString(st.Push(text[i:min(i+n, len(text))]))
					i += n
				}
				b.WriteString(st.Flush())
				if got := b.String(); got != want {
					t.Fatalf("answer %d (%d bytes, enforce %v, pieces %v): streamed differs from whole\n%s", d, len(text), enforce, sizes, firstDiff(got, want))
				}
				if a, c := fmt.Sprint(in.Counts()), fmt.Sprint(whole.Counts()); a != c {
					t.Fatalf("answer %d (enforce %v, pieces %v): counts %s, whole %s", d, enforce, sizes, a, c)
				}
			}
		}
	}
}

// TestStreamLongConstructsLeakNothing: a link or image longer than the
// hold-back limit cannot be held whole, so its start goes out before it is
// complete and the streamed answer may differ from the whole one (the rest of
// the construct is dropped, which breaks it). What must hold: nothing the
// policy removes survives in what was streamed. Inspecting the streamed text
// again finds nothing.
func TestStreamLongConstructsLeakNothing(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	docs := 100
	if testing.Short() {
		docs = 30
	}
	for d := 0; d < docs; d++ {
		text := genAnswer(rng, true)
		in := detect.NewOutputInspector(evalRules())
		st := in.NewStream(false)
		var b strings.Builder
		for i := 0; i < len(text); {
			n := 1 + rng.Intn(40)
			b.WriteString(st.Push(text[i:min(i+n, len(text))]))
			i += n
		}
		b.WriteString(st.Flush())
		if fs := detect.NewOutputInspector(evalRules()).Find(b.String(), false); len(fs) > 0 {
			f := fs[0]
			t.Fatalf("answer %d: %s survived the stream: %q", d, f.Type, b.String()[f.Start:min(f.End, f.Start+200)])
		}
	}
}

func firstDiff(a, b string) string {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	ctx := func(s string) string { return s[max(0, i-80):min(len(s), i+80)] }
	return fmt.Sprintf("at byte %d:\n got  …%q…\n want …%q…", i, ctx(a), ctx(b))
}

// genAnswer builds a synthetic answer. It holds no real secret: the keys are
// random strings in the vendors' formats. long adds links and images longer
// than the hold-back limit.
func genAnswer(rng *rand.Rand, long bool) string {
	words := strings.Fields("the payment reminder goes out on time and the customer reads it then pays with a card or a transfer as agreed")
	alnum := func(n int) string {
		const cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		b := make([]byte, n)
		for i := range b {
			b[i] = cs[rng.Intn(len(cs))]
		}
		return string(b)
	}
	host := func() string {
		return []string{"docs.example.org", "python.org", "www.python.org", "evil.example", "tracker.example.net", "localhost"}[rng.Intn(6)]
	}
	path := func() string {
		p := "/" + alnum(1+rng.Intn(12))
		switch rng.Intn(6) {
		case 0:
			p += "?d=[EMAIL_1]"
		case 1:
			p += "?c=%5BCREDIT_CARD_1%5D"
		case 2:
			if long {
				p += "/" + alnum(2500) // longer than the hold-back limit
			}
		}
		return p
	}
	url := func() string { return "https://" + host() + path() }
	parts := []func() string{
		func() string { return words[rng.Intn(len(words))] + " " },
		func() string { return words[rng.Intn(len(words))] + ". " },
		func() string { return "\n" },
		func() string { return "\n\n- " },
		func() string { return "[" + words[rng.Intn(len(words))] + " guide](" + url() + ") " },
		func() string { return "![chart](" + url() + ") " },
		func() string { return "![chart][r" + fmt.Sprint(rng.Intn(3)) + "] " },
		func() string { return "\n[r" + fmt.Sprint(rng.Intn(3)) + "]: " + url() + "\n" },
		func() string { return "<img src=\"" + url() + "\" alt=\"x\"> " },
		func() string { return "<a href=\"" + url() + "\">the\nlink " + words[rng.Intn(len(words))] + "</a> " },
		func() string { return "see " + url() + ". " },
		func() string { return "key sk-proj-" + alnum(40) + " " },
		func() string { return "AKIA" + strings.ToUpper(alnum(16)) + " " },
		func() string { return "eyJ" + alnum(20) + ".eyJ" + alnum(20) + "." + alnum(20) + " " },
		func() string {
			return "\n-----BEGIN PRIVATE KEY-----\n" + alnum(64+rng.Intn(3000)) + "\n-----END PRIVATE KEY-----\n"
		},
		func() string { return "[" + words[rng.Intn(len(words))] + " " }, // a bracket never closed
		func() string { return "a < b and " },
		func() string { return alnum(2100+rng.Intn(500)) + " " }, // a token longer than the hold-back limit
		func() string { return "[PERSON_1] " },
		func() string { return "`code [x](y)` " },
	}
	// Mostly prose, with a construct now and then; sometimes a very long line.
	n := 20 + rng.Intn(160)
	var b strings.Builder
	noNewlines := rng.Intn(5) == 0
	for i := 0; i < n; i++ {
		var s string
		if rng.Intn(3) == 0 {
			s = parts[rng.Intn(len(parts))]()
		} else {
			s = parts[rng.Intn(2)]()
		}
		if noNewlines {
			s = strings.ReplaceAll(s, "\n", " ")
		}
		b.WriteString(s)
	}
	return b.String()
}
