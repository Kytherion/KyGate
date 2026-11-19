package pipeline_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
)

func ideChat(date, question string) map[string]any {
	return map[string]any{"model": "gpt-4o-mini", "messages": []any{
		map[string]any{"role": "system", "content": "You are a coding assistant.\nToday's date is " + date + ".\nGit status: clean"},
		map[string]any{"role": "user", "content": question},
	}}
}

// The same question with another date in the system prompt misses the exact
// cache; the event says why, and the report counts it with its cost.
func TestNearMissIsRecordedAndReported(t *testing.T) {
	h := newHarness(t, "")
	h.post("/v1/chat/completions", h.keyA, ideChat("2026-11-17", "Fix the bug in main.go"))
	resp, _ := h.post("/v1/chat/completions", h.keyA, ideChat("2026-11-18", "Fix the bug in main.go"))
	if resp.Header.Get("X-KyGate-Cache") != "miss" {
		t.Fatalf("cache %q", resp.Header.Get("X-KyGate-Cache"))
	}
	e := h.event(resp.Header.Get("X-KyGate-Request-Id"))
	if !reflect.DeepEqual(e.NearMiss, []string{"system:date"}) {
		t.Fatalf("near miss %v", e.NearMiss)
	}
	// A different question is not a near miss; neither is another key.
	resp, _ = h.post("/v1/chat/completions", h.keyA, ideChat("2026-11-18", "Write tests for main.go"))
	if e := h.event(resp.Header.Get("X-KyGate-Request-Id")); e.NearMiss != nil {
		t.Fatalf("%v", e.NearMiss)
	}
	resp, _ = h.post("/v1/chat/completions", h.keyB, ideChat("2026-11-19", "Fix the bug in main.go"))
	if e := h.event(resp.Header.Get("X-KyGate-Request-Id")); e.NearMiss != nil {
		t.Fatalf("another key is not compared: %v", e.NearMiss)
	}

	rows, err := h.db.NearMisses(context.Background(), store.Range{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)})
	if err != nil || len(rows) != 1 || rows[0].Label != "system:date" || rows[0].Requests != 1 || rows[0].CostUSD <= 0 || rows[0].Keys != 1 {
		t.Fatalf("%v %+v", err, rows)
	}
}
