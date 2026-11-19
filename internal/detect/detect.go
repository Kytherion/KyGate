// Package detect holds the fast detectors that run inside the gateway process:
// patterns for secrets, identifiers that carry a checksum, and company
// dictionaries (capability PR-1). Detectors only report findings. Applying
// policy actions is the job of the enforce stage (principle 1).
package detect

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Finding is one detected value inside one segment. Offsets are UTF-8 byte
// offsets into the segment text, end exclusive (architecture §4.3).
type Finding struct {
	Segment  int     // index of the segment in the request
	Type     string  // SECRET, CREDIT_CARD, IBAN, EMAIL, dict/<name>
	Start    int     // byte offset, inclusive
	End      int     // byte offset, exclusive
	Score    float64 // 1.0 for deterministic detectors
	Detector string  // name and version of the detector
	Language string  // language of the segment, when an ML detector reports it ("en", "fr")
}

// Dictionary is a company term list, such as project code names.
type Dictionary struct {
	Name          string
	Terms         []string
	CaseSensitive bool
}

// Set is the configured collection of detectors for one policy version.
type Set struct {
	dicts []compiledDict
}

type compiledDict struct {
	typ string
	re  *regexp.Regexp
}

// NewSet builds a detector set. Dictionaries come from the policy.
func NewSet(dicts []Dictionary) *Set {
	s := &Set{}
	for _, d := range dicts {
		terms := make([]string, 0, len(d.Terms))
		for _, t := range d.Terms {
			t = strings.TrimSpace(t)
			if t != "" {
				terms = append(terms, regexp.QuoteMeta(t))
			}
		}
		if len(terms) == 0 {
			continue
		}
		// Longest first, so that "Project Apollo X" wins over "Project Apollo".
		sort.Slice(terms, func(i, j int) bool { return len(terms[i]) > len(terms[j]) })
		expr := `(?:^|[^\pL\pN_])(` + strings.Join(terms, "|") + `)(?:$|[^\pL\pN_])`
		if !d.CaseSensitive {
			expr = "(?i)" + expr
		}
		s.dicts = append(s.dicts, compiledDict{typ: "dict/" + d.Name, re: regexp.MustCompile(expr)})
	}
	return s
}

// secretPatterns are vendor credential formats. They are kept narrow on
// purpose: the starter policy blocks secrets, so a false alarm breaks a prompt.
var secretPatterns = []secretPattern{
	{"anthropic-key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`), []string{"sk-ant-"}},
	{"openai-key", regexp.MustCompile(`sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}`), []string{"sk-"}},
	{"kygate-virtual-key", regexp.MustCompile(`kg-[A-Za-z0-9_\-]{40,}`), []string{"kg-"}},
	{"aws-access-key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), []string{"AKIA", "ASIA"}},
	{"github-token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b`), []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}},
	{"gitlab-token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`), []string{"glpat-"}},
	{"slack-token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9\-]{10,}\b`), []string{"xox"}},
	{"google-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), []string{"AIza"}},
	{"stripe-key", regexp.MustCompile(`\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b`), []string{"_live_"}},
	{"private-key", regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )*PRIVATE KEY-----`), []string{"-----BEGIN "}},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`), []string{"eyJ"}},
}

// secretPattern is a credential format, with the literals one of which every
// match contains: a text without any of them is skipped without running the
// expression, which gives the same result, faster.
type secretPattern struct {
	name string
	re   *regexp.Regexp
	lits []string
}

// find returns the pattern's matches in text.
func (p secretPattern) find(text string) [][]int {
	for _, l := range p.lits {
		if strings.Contains(text, l) {
			return p.re.FindAllStringIndex(text, -1)
		}
	}
	return nil
}

var (
	cardCandidate = regexp.MustCompile(`\b\d(?:[ \-]?\d){12,18}\b`)
	ibanCandidate = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b`)
	emailPattern  = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}`)
)

// priority decides overlaps: the higher value wins; equal values keep the longer span.
var priority = map[string]int{"SECRET": 50, "CREDIT_CARD": 40, "IBAN": 40, "EMAIL": 10}

func prio(t string) int {
	if p, ok := priority[t]; ok {
		return p
	}
	if strings.HasPrefix(t, "dict/") {
		return 30
	}
	return 0
}

// Scan runs every detector on one segment.
func (s *Set) Scan(segment int, text string) []Finding {
	if text == "" {
		return nil
	}
	var out []Finding
	add := func(typ, det string, start, end int) {
		out = append(out, Finding{Segment: segment, Type: typ, Start: start, End: end, Score: 1, Detector: det})
	}
	for _, p := range secretPatterns {
		for _, m := range p.find(text) {
			add("SECRET", p.name+"/v1", m[0], m[1])
		}
	}
	for _, m := range cardCandidate.FindAllStringIndex(text, -1) {
		if validCard(text[m[0]:m[1]]) {
			add("CREDIT_CARD", "card-luhn/v1", m[0], m[1])
		}
	}
	for _, m := range ibanCandidate.FindAllStringIndex(text, -1) {
		if validIBAN(text[m[0]:m[1]]) {
			add("IBAN", "iban-mod97/v1", m[0], m[1])
		}
	}
	for _, m := range emailPattern.FindAllStringIndex(text, -1) {
		add("EMAIL", "email-pattern/v1", m[0], m[1])
	}
	for _, d := range s.dicts {
		for _, m := range d.re.FindAllStringSubmatchIndex(text, -1) {
			add(d.typ, "dictionary/v1", m[2], m[3])
		}
	}
	return Merge(out)
}

// Merge resolves overlapping findings with one fixed rule: higher priority
// wins, then the longer span, then the earlier start. The result is sorted
// and contains no overlaps.
func Merge(in []Finding) []Finding {
	if len(in) < 2 {
		return in
	}
	sort.Slice(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if prio(a.Type) != prio(b.Type) {
			return prio(a.Type) > prio(b.Type)
		}
		if (a.End - a.Start) != (b.End - b.Start) {
			return (a.End - a.Start) > (b.End - b.Start)
		}
		return a.Start < b.Start
	})
	var kept []Finding
	for _, f := range in {
		overlap := false
		for _, k := range kept {
			if f.Segment == k.Segment && f.Start < k.End && k.Start < f.End {
				overlap = true
				break
			}
		}
		if !overlap {
			kept = append(kept, f)
		}
	}
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].Segment != kept[j].Segment {
			return kept[i].Segment < kept[j].Segment
		}
		return kept[i].Start < kept[j].Start
	})
	return kept
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func validCard(raw string) bool {
	// Mixed separators ("4111-1111 1111") are rare in real numbers and common in noise.
	if strings.Contains(raw, " ") && strings.Contains(raw, "-") {
		return false
	}
	d := digitsOnly(raw)
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	if !knownCardPrefix(d) {
		return false
	}
	return luhn(d)
}

func knownCardPrefix(d string) bool {
	two := atoi(d[:2])
	four := atoi(d[:4])
	switch {
	case d[0] == '4': // Visa
		return true
	case two >= 51 && two <= 55, four >= 2221 && four <= 2720: // Mastercard
		return true
	case two == 34 || two == 37: // American Express
		return len(d) == 15
	case strings.HasPrefix(d, "6011"), two == 65, four >= 6440 && four <= 6499: // Discover
		return true
	case four >= 3528 && four <= 3589: // JCB
		return true
	case two == 36 || two == 38 || two == 30: // Diners
		return true
	case two == 62: // UnionPay
		return true
	}
	return false
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

func luhn(d string) bool {
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

func validIBAN(raw string) bool {
	s := strings.ReplaceAll(raw, " ", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	// Move the first four characters to the end, map letters to numbers, mod 97.
	r := s[4:] + s[:4]
	rem := 0
	for _, c := range r {
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		case unicode.IsUpper(c) && c <= 'Z':
			v := int(c-'A') + 10
			rem = (rem*100 + v) % 97
		default:
			return false
		}
	}
	return rem == 1
}
