package cache

import (
	"testing"
	"time"
)

func TestHardCheck(t *testing.T) {
	pass := [][2]string{
		{"What is the capital of France?", "what's the capital of france"},
		{"Tell me France's capital", "What is the capital of France?"},
		{"How do I sort a list in Python?", "how do i sort lists in python"},
		{"Quelle est la capitale de la France ?", "quelle est la capitale de la france"},
		{"Explain `os.path.join`", "Please explain `os.path.join`"},
		{"Why doesn't my build fail?", "why doesn't my build fail"},
	}
	for _, p := range pass {
		if r := HardCheck(p[0], p[1]); r != "" {
			t.Errorf("%q vs %q: rejected (%s)", p[0], p[1], r)
		}
	}
	reject := [][3]string{
		{"What is the capital of France?", "What is the capital of Germany?", "the words differ"},
		{"Population of Lyon in 2020", "Population of Lyon in 2021", "the numbers differ"},
		{"Is this safe?", "Is this not safe?", "a negation differs"},
		{"Why does my build fail?", "Why doesn't my build fail?", "a negation differs"},
		{"What does os.path.join do?", "What does os.path.split do?", "the code identifiers differ"},
		{"What does userName mean?", "What does username mean?", "the code identifiers differ"},
		{"What is the capital of France?", "Quelle est la capitale de la France ?", "the language differs"},
		{"Write a poem about cats", "Write a poem about dogs", "the words differ"},
		{"Is it safe", "Is it safe for children", "the words differ"},
		{"Convert 100 USD to EUR", "Convert 100 EUR to USD", "the word order differs"},
		{"Is Paris bigger than Lyon?", "Is Lyon bigger than Paris?", "the word order differs"},
	}
	for _, r := range reject {
		if got := HardCheck(r[0], r[1]); got != r[2] {
			t.Errorf("%q vs %q: got %q, want %q", r[0], r[1], got, r[2])
		}
	}
}

func TestRepeatWindow(t *testing.T) {
	m := newMemory(1 << 20)
	if m.Repeat("k", "fp", 0) || m.Repeat("k", "fp", 0) {
		t.Fatal("a window of 0 switches the rule off")
	}
	w := 80 * time.Millisecond
	if m.Repeat("k", "fp2", w) {
		t.Fatal("a first request is not a repeat")
	}
	if !m.Repeat("k", "fp2", w) {
		t.Fatal("a quick repeat is a repeat")
	}
	time.Sleep(50 * time.Millisecond)
	if !m.Repeat("k", "fp2", w) {
		t.Fatal("still inside the window")
	}
	// A repeat inside the window does not restart it: 50 + 40 ms > 80 ms.
	time.Sleep(40 * time.Millisecond)
	if m.Repeat("k", "fp2", w) {
		t.Fatal("repeats must not restart the window")
	}
}
