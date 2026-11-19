package cache

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const ideSystem = "You are a coding assistant.\nToday's date is 2026-11-17.\nWorking directory: /home/dev/app\nGit status: clean"

func req(system, question string, extra ...any) map[string]any {
	b := map[string]any{"model": "m", "stream": true, "messages": []any{
		map[string]any{"role": "system", "content": system},
		map[string]any{"role": "user", "content": question},
	}}
	for i := 0; i+1 < len(extra); i += 2 {
		b[extra[i].(string)] = extra[i+1]
	}
	return b
}

func TestNearMissNamesWhatDefeatedTheCache(t *testing.T) {
	cases := []struct {
		name   string
		second map[string]any
		want   []string
	}{
		{"the date in the system prompt", req(strings.Replace(ideSystem, "2026-11-17", "2026-11-18", 1), "Fix the bug"), []string{"system:date"}},
		{"a time and a cursor position", req(ideSystem+"\nNow 10:42, cursor at line 120", "Fix the bug"), []string{"system:lines"}},
		{"other text in the system prompt", req(strings.Replace(ideSystem, "clean", "2 files changed", 1), "Fix the bug"), []string{"system:text"}},
		{"a setting", req(ideSystem, "Fix the bug", "temperature", 0.7), []string{"temperature:value"}},
		{"a new question is not a near miss", req(ideSystem, "Write the tests"), nil},
		{"the streaming flag never counts", req(ideSystem, "Fix the bug", "stream", false), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := NewNearMiss()
			if got := n.Observe("key:a/m", req(ideSystem, "Fix the bug")); got != nil {
				t.Fatalf("first request: %v", got)
			}
			if got := n.Observe("key:a/m", c.second); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestNearMissTimeAndCursorOnTheSameLine(t *testing.T) {
	n := NewNearMiss()
	n.Observe("s", req("Context\nCursor: line 12, column 4 at 10:41:07", "Explain this"))
	got := n.Observe("s", req("Context\nCursor: line 98, column 2 at 10:43:55", "Explain this"))
	if !reflect.DeepEqual(got, []string{"system:number", "system:time"}) {
		t.Fatalf("%v", got)
	}
}

func TestNearMissOtherFieldsAndScopes(t *testing.T) {
	n := NewNearMiss()
	turn := func(cursor string) map[string]any {
		return map[string]any{"model": "m", "system": "Be brief.", "messages": []any{
			map[string]any{"role": "user", "content": "Open main.go, cursor " + cursor},
			map[string]any{"role": "assistant", "content": "Opened."},
			map[string]any{"role": "user", "content": "What does run do?"},
		}}
	}
	n.Observe("s", turn("12:4"))
	if got := n.Observe("s", turn("13:9")); !reflect.DeepEqual(got, []string{"earlier user turn:number"}) {
		t.Fatalf("%v", got)
	}
	if got := n.Observe("other", turn("13:9")); got != nil {
		t.Fatalf("another scope is not compared: %v", got)
	}
	// An identical repeat is not a near miss (it is a plain repeat).
	if got := n.Observe("s", turn("13:9")); got != nil {
		t.Fatalf("%v", got)
	}
}

func TestNearMissKeepsNoText(t *testing.T) {
	n := NewNearMiss()
	n.Observe("s", req("secret project Hyperion\nline two", "q"))
	for _, r := range n.rings {
		for _, s := range r.shapes {
			for p := range s.fields {
				if strings.Contains(p, "Hyperion") {
					t.Fatal("paths are field names, never text")
				}
			}
		}
	}
}

// Remembered requests hold at most the budget of line hashes; the oldest go
// first, and the newest of the current scope always stays.
func TestNearMissMemoryIsBounded(t *testing.T) {
	n := NewNearMiss()
	n.budget = 100
	long := strings.Repeat("a line\n", 30) // 31 lines: 62 hashes per request
	for i := 0; i < 10; i++ {
		n.Observe("s"+strconv.Itoa(i%3), req(long+strconv.Itoa(i), "q"))
		if n.lines > n.budget && n.lines > 62 {
			t.Fatalf("round %d: %d line hashes held", i, n.lines)
		}
	}
	total := 0
	for _, r := range n.rings {
		for _, s := range r.shapes {
			total += s.size
		}
	}
	if total != n.lines {
		t.Fatalf("the count drifted: %d held, %d counted", total, n.lines)
	}
}
