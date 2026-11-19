package cache

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// HardCheck decides whether a stored last message may stand in for a new one
// that its embedding found similar. It returns "" when the candidate passes,
// or the reason it is rejected.
//
// The semantic cache runs without the Guard, so these rules are the
// second stage of the match (architecture §3.4).
// They are strict on purpose: two messages match only when they carry the
// same content words, numbers, negations, code identifiers, and language,
// and differ only in order, case, punctuation, filler words, and plurals.
// "Capital of France" never matches "capital of Germany", and a synonym does
// not match either; that would need a cross-encoder.
func HardCheck(q, c string) string {
	ql, cl := language(q), language(c)
	if ql != "" && cl != "" && ql != cl {
		return "the language differs"
	}
	if !sameStrings(numbers(q), numbers(c)) {
		return "the numbers differ"
	}
	if negations(q) != negations(c) {
		return "a negation differs"
	}
	if !sameStrings(identifiers(q), identifiers(c)) {
		return "the code identifiers differ"
	}
	qw, cw := contentWords(q), contentWords(c)
	if !sameStrings(qw, cw) {
		return "the words differ"
	}
	// "100 USD to EUR" is not "100 EUR to USD": with a word that gives a
	// direction or an order, the content words must also come in the same order.
	if (relational(q) || relational(c)) && !sameOrder(qw, cw) {
		return "the word order differs"
	}
	return ""
}

var relationalWords = set(
	"to", "from", "into", "than", "versus", "vs", "before", "after", "over", "under", "between", "against", "per",
	"vers", "contre", "avant", "après", "entre", "plus", "moins",
	"hacia", "desde", "contra", "antes", "después",
	"nach", "gegen", "vor", "über", "unter",
)

func relational(s string) bool {
	for _, w := range words(s) {
		if relationalWords[w] {
			return true
		}
	}
	return false
}

func sameOrder(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

var (
	numberRe = regexp.MustCompile(`\d+(?:[.,]\d+)*`)
	// Identifiers that look like code: dotted or slashed paths, snake_case,
	// camelCase, calls, and anything in backticks.
	identRe = regexp.MustCompile("`[^`]+`|[A-Za-z_][A-Za-z0-9_]*(?:[./:][A-Za-z0-9_]+)+|[A-Za-z0-9]*_[A-Za-z0-9_]+|[a-z]+[A-Z][A-Za-z0-9]*|[A-Za-z_][A-Za-z0-9_]*\\(\\)")
)

func numbers(s string) []string {
	out := numberRe.FindAllString(s, -1)
	for i, n := range out {
		out[i] = strings.ReplaceAll(n, ",", ".")
	}
	return out
}

func identifiers(s string) []string {
	return identRe.FindAllString(s, -1)
}

func words(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

var negationWords = set(
	// English (contractions arrive split: "don't" gives "don" and "t")
	"not", "no", "never", "none", "nothing", "nobody", "without", "nor", "cannot", "t",
	// French ("n'est" arrives split as "n" and "est")
	"ne", "n", "pas", "jamais", "sans", "aucun", "aucune", "rien", "personne",
	// Spanish
	"nunca", "sin", "ningún", "ninguna", "nada",
	// German
	"nicht", "kein", "keine", "keinen", "nie", "ohne", "nichts",
)

func negations(s string) int {
	n := 0
	for _, w := range words(s) {
		if negationWords[w] {
			n++
		}
	}
	return n
}

// Function words and fillers that do not change what is asked. Negations
// are not here: they are counted on their own.
var fillers = set(
	// English
	"a", "an", "the", "is", "are", "was", "were", "be", "been", "am", "do", "does", "did", "s", "re", "ve", "ll", "d", "m",
	"what", "which", "who", "whom", "how", "why", "when", "where", "of", "in", "on", "at", "to", "for", "from", "by",
	"with", "about", "as", "into", "and", "or", "it", "its", "this", "that", "these", "those", "there", "here",
	"i", "me", "my", "you", "your", "we", "us", "our", "please", "tell", "explain", "give", "show", "can", "could",
	"would", "will", "shall", "should", "may", "might", "let", "know", "want", "like", "just", "some", "any",
	"hi", "hello", "hey", "thanks", "thank", "kindly", "quick", "quickly", "question", "so", "then", "also",
	// the first half of a contraction whose "t" is counted as a negation
	"don", "doesn", "didn", "isn", "aren", "wasn", "weren", "won", "wouldn", "couldn", "shouldn", "haven", "hasn", "hadn", "ain",
	// French
	"le", "la", "les", "l", "un", "une", "des", "de", "du", "d", "et", "ou", "est", "sont", "c", "ce", "cette", "ces",
	"qu", "que", "quel", "quelle", "quels", "quelles", "qui", "quoi", "comment", "pourquoi", "quand", "où", "en",
	"dans", "sur", "pour", "par", "avec", "au", "aux", "à", "je", "j", "me", "m", "moi", "tu", "te", "toi", "vous",
	"nous", "mon", "ma", "mes", "ton", "ta", "tes", "votre", "vos", "s", "il", "elle", "y", "dis", "dites",
	"peux", "pouvez", "peut", "explique", "expliquez", "donne", "donnez", "merci", "bonjour", "salut", "stp", "svp",
	"plaît", "plait",
	// Spanish
	"el", "los", "las", "una", "unos", "unas", "es", "son", "del", "al", "por", "para", "con", "qué", "cuál", "cómo",
	// German
	"der", "die", "das", "ein", "eine", "ist", "sind", "und", "oder", "von", "zu", "mit", "für", "was", "wie", "bitte",
)

func contentWords(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, w := range words(s) {
		if fillers[w] || negationWords[w] || numberRe.MatchString(w) {
			continue
		}
		// Plurals: "lists" and "list" are the same word.
		if len(w) > 3 && strings.HasSuffix(w, "s") && !strings.HasSuffix(w, "ss") {
			w = w[:len(w)-1]
		}
		if !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	return out
}

var languages = map[string]map[string]bool{
	"en": set("the", "is", "are", "what", "how", "of", "and", "to", "in", "it", "you", "with", "for", "this", "that"),
	"fr": set("le", "la", "les", "est", "et", "des", "du", "une", "que", "pour", "dans", "avec", "quelle", "quel", "comment"),
	"es": set("el", "los", "las", "es", "y", "del", "una", "que", "para", "con", "qué", "cómo", "por"),
	"de": set("der", "die", "das", "ist", "und", "ein", "eine", "nicht", "mit", "für", "wie", "was", "zu"),
}

// language guesses the language of a short message from its function words.
// It returns "" when it cannot tell.
func language(s string) string {
	best, bestN, second := "", 0, 0
	ws := words(s)
	for lang, sw := range languages {
		n := 0
		for _, w := range ws {
			if sw[w] {
				n++
			}
		}
		switch {
		case n > bestN:
			best, second, bestN = lang, bestN, n
		case n > second:
			second = n
		}
	}
	if bestN < 2 || bestN == second {
		return ""
	}
	return best
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func set(ws ...string) map[string]bool {
	m := make(map[string]bool, len(ws))
	for _, w := range ws {
		m[w] = true
	}
	return m
}
