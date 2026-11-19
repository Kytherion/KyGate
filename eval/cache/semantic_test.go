package cache

// The semantic-cache gate (OP-3), without the Guard. It
// measures the false-hit rate of the hard checks against a deliberately weak
// stand-in embedder, a bag of words, at the loosest threshold a policy may
// set (0.80). A bag of words scores "capital of France" and "capital of
// Germany" as close, so every false hit it lets through must be stopped by
// the hard checks. The real embedding model's false-hit rate is measured on
// real traffic, in shadow mode, before serving is switched on.
//
// Every value here is synthetic.

import (
	"context"
	"fmt"
	"hash/fnv"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/Kytherion/KyGate/internal/cache"
)

func bag(s string) []float32 {
	v := make([]float32, 512)
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		h := fnv.New32a()
		h.Write([]byte(w))
		v[h.Sum32()%512]++
	}
	return v
}

// stored, then a question that must reuse its answer, then questions that
// must not.
var corpus = []struct {
	stored string
	same   []string
	other  []string
}{
	{"What is the capital of France?",
		[]string{"what's the capital of france", "Tell me France's capital", "WHAT IS THE CAPITAL OF FRANCE"},
		[]string{"What is the capital of Germany?", "What is the capital of France in 1800?", "What is not the capital of France?", "Quelle est la capitale de la France ?"}},
	{"How do I sort a list in Python?",
		[]string{"how do i sort lists in python", "How do I sort a list in Python"},
		[]string{"How do I sort a list in Go?", "How do I reverse a list in Python?", "How do I sort a list in Python 2?", "How do I not sort a list in Python?"}},
	{"What does os.path.join do?",
		[]string{"what does os.path.join do"},
		[]string{"What does os.path.split do?", "What does os.path.join return?", "What does path.join do?"}},
	{"Convert 100 USD to EUR",
		[]string{"convert 100 usd to eur", "Please convert 100 USD to EUR"},
		[]string{"Convert 150 USD to EUR", "Convert 100 EUR to USD", "Convert 100 USD to GBP"}},
	{"Write a haiku about autumn",
		[]string{"write a haiku about autumn", "Write a haiku about autumn please"},
		[]string{"Write a haiku about spring", "Write a limerick about autumn", "Write a long haiku about autumn"}},
	{"Is it safe to eat raw eggs?",
		[]string{"is it safe to eat raw eggs", "Is it safe to eat raw egg?"},
		[]string{"Is it unsafe to eat raw eggs?", "Is it safe to eat raw fish?", "Is it not safe to eat raw eggs?", "Is it safe for children to eat raw eggs?"}},
	{"Quelle est la capitale de l'Italie ?",
		[]string{"quelle est la capitale de l'italie", "Dis-moi quelle est la capitale de l'Italie"},
		[]string{"Quelle est la capitale de l'Espagne ?", "What is the capital of Italy?", "Quelle n'est pas la capitale de l'Italie ?"}},
	{"Summarize the plot of Hamlet in 3 sentences",
		[]string{"summarize the plot of hamlet in 3 sentences"},
		[]string{"Summarize the plot of Hamlet in 5 sentences", "Summarize the plot of Macbeth in 3 sentences", "Summarize the themes of Hamlet in 3 sentences"}},
}

// Floors: no false hit; most look-alikes reuse the stored answer.
const (
	maxFalseHitRate = 0.0
	minHitRate      = 0.90
)

func TestSemanticFalseHitRate(t *testing.T) {
	ctx := context.Background()
	key := orgKey(3)
	var same, sameHits, other, falseHits int
	for i, c := range corpus {
		s := cache.NewSemantic(nil, t.Logf) // in memory
		ctxFP := fmt.Sprintf("ctx-%d", i)
		s.Put(key, "org", ctxFP, fmt.Sprintf("fp-%d", i), c.stored, bag(c.stored), &cache.Entry{Model: "m", Body: []byte(`{}`)}, time.Hour, 1000)
		waitEntries(t, s, 1)
		for _, q := range c.same {
			same++
			if _, ok := s.Lookup(ctx, key, "org", ctxFP, q, bag(q), 0.80, false); ok {
				sameHits++
			} else {
				t.Logf("missed look-alike: %q for %q", q, c.stored)
			}
		}
		for _, q := range c.other {
			other++
			if _, ok := s.Lookup(ctx, key, "org", ctxFP, q, bag(q), 0.80, false); ok {
				falseHits++
				t.Errorf("false hit: %q reused the answer to %q", q, c.stored)
			}
		}
	}
	falseRate := float64(falseHits) / float64(other)
	hitRate := float64(sameHits) / float64(same)
	t.Logf("semantic cache, hard checks at similarity 0.80 with a bag-of-words embedder: false hits %d/%d (%.1f%%), look-alike hits %d/%d (%.1f%%)",
		falseHits, other, 100*falseRate, sameHits, same, 100*hitRate)
	if falseRate > maxFalseHitRate {
		t.Fatalf("false-hit rate %.3f, floor %.3f", falseRate, maxFalseHitRate)
	}
	if hitRate < minHitRate {
		t.Fatalf("look-alike hit rate %.3f, floor %.3f", hitRate, minHitRate)
	}
}

func waitEntries(t *testing.T, s *cache.Semantic, n int64) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if s.Stats(context.Background()).Entries >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("entry not stored")
}
