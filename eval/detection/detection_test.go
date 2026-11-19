// Package detection is the detection quality gate: precision and recall of the
// fast detectors per data type, on a synthetic corpus. A missed detection is a
// leak and a false alarm is a broken prompt, so both are tracked.
//
// Every value here is synthetic: test card numbers, documented example keys,
// and example.com addresses.
package detection

import (
	"testing"

	"github.com/Kytherion/KyGate/internal/detect"
)

type sample struct {
	text string
	want map[string]int // type -> number of values in text
}

var corpus = []sample{
	// Positives
	{"Please refund 4111 1111 1111 1111 by Friday.", map[string]int{"CREDIT_CARD": 1}},
	{"Visa 4012888888881881, Mastercard 5555-5555-5555-4444", map[string]int{"CREDIT_CARD": 2}},
	{"Amex 378282246310005 on file", map[string]int{"CREDIT_CARD": 1}},
	{"Wire to DE89 3704 0044 0532 0130 00 today", map[string]int{"IBAN": 1}},
	{"FR1420041010050500013M02606 and GB82WEST12345698765432", map[string]int{"IBAN": 2}},
	{"export OPENAI_API_KEY=sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd", map[string]int{"SECRET": 1}},
	{"ANTHROPIC_API_KEY=sk-ant-api03-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", map[string]int{"SECRET": 1}},
	{"aws_access_key_id = AKIAIOSFODNN7EXAMPLE", map[string]int{"SECRET": 1}},
	{"token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AB", map[string]int{"SECRET": 1}},
	{"slack xoxb-123456789012-abcdefghijkl", map[string]int{"SECRET": 1}},
	{"Contact alice.martin@example.com or bob@example.co.uk", map[string]int{"EMAIL": 2}},
	// Negatives: text that looks close and must not fire
	{"Order number 1234 5678 9012 3456 shipped", nil},
	{"The build took 4111 seconds over 1111 runs", nil},
	{"Version 2024.11.15 released; see RFC 3339", nil},
	{"Use the sk-learn library and sk- prefixes in docs", nil},
	{"DE00 1234 5678 9012 3456 78 is not a valid IBAN", nil},
	{"Email me at alice at example dot com", nil},
	{"git commit -m 'fix(api): handle 404'", nil},
	{"phone +1 415 555 0100, zip 94103", nil},
}

// Floors. Raise them as detectors improve; never lower them silently.
var floors = map[string]struct{ precision, recall float64 }{
	"CREDIT_CARD": {1.0, 1.0},
	"IBAN":        {1.0, 1.0},
	"SECRET":      {1.0, 1.0},
	"EMAIL":       {1.0, 1.0},
}

func TestDetectionQuality(t *testing.T) {
	set := detect.NewSet(nil)
	tp, fp, fn := map[string]int{}, map[string]int{}, map[string]int{}
	for _, s := range corpus {
		got := map[string]int{}
		for _, f := range set.Scan(0, s.text) {
			got[f.Type]++
		}
		for typ := range floors {
			w, g := s.want[typ], got[typ]
			switch {
			case g == w:
				tp[typ] += g
			case g > w:
				tp[typ] += w
				fp[typ] += g - w
				t.Logf("false alarm %s in %q", typ, s.text)
			default:
				tp[typ] += g
				fn[typ] += w - g
				t.Logf("missed %s in %q", typ, s.text)
			}
		}
	}
	for typ, floor := range floors {
		p := ratio(tp[typ], tp[typ]+fp[typ])
		r := ratio(tp[typ], tp[typ]+fn[typ])
		t.Logf("%-12s precision %.2f recall %.2f", typ, p, r)
		if p < floor.precision || r < floor.recall {
			t.Errorf("%s below its floor: precision %.2f (floor %.2f), recall %.2f (floor %.2f)", typ, p, floor.precision, r, floor.recall)
		}
	}
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}
