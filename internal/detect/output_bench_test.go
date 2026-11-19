package detect

import (
	"strings"
	"testing"
)

// answerOf returns a Markdown answer of about n bytes: prose, a list, a link,
// and code, as a model writes them.
func answerOf(n int) string {
	para := "Here is how the reminder works. The customer receives a short message with the amount, the due date, and a link to pay. " +
		"See [the payment guide](https://docs.example.com/pay) for details.\n\n" +
		"- First, check the invoice number.\n- Then, confirm the amount.\n- Finally, send the reminder.\n\n" +
		"```go\nfunc remind(id string) error { return send(id) }\n```\n\n"
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(para)
	}
	return b.String()[:n]
}

// benchStream feeds an answer in pieces of size bytes, as a streamed answer
// arrives: real models send a few characters per piece.
func benchStream(b *testing.B, n, size int) {
	text := answerOf(n)
	r := rules("remove")
	r.Allowed = []string{"docs.example.com"}
	b.SetBytes(int64(n))
	b.ReportAllocs()
	for b.Loop() {
		in := NewOutputInspector(r)
		st := in.NewStream(false)
		for i := 0; i < len(text); i += size {
			st.Push(text[i:min(i+size, len(text))])
		}
		st.Flush()
	}
}

func BenchmarkOutputStream2KBTokens(b *testing.B)  { benchStream(b, 2<<10, 4) }
func BenchmarkOutputStream16KBTokens(b *testing.B) { benchStream(b, 16<<10, 4) }
func BenchmarkOutputWhole16KB(b *testing.B) {
	text := answerOf(16 << 10)
	r := rules("remove")
	r.Allowed = []string{"docs.example.com"}
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for b.Loop() {
		NewOutputInspector(r).Text(text, false)
	}
}
