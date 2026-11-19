package pipeline_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
)

// Quality signals (OB-4): ratings of answers, counted only for the key that
// made the request, split by how the answer was served.
func TestFeedbackOnAnswers(t *testing.T) {
	h := newHarness(t, "")
	h.g.Feedback = h.db
	resp, _ := h.post("/v1/chat/completions", h.keyA, chat("Remind ACME about invoice 7.", false))
	model := resp.Header.Get("X-KyGate-Request-Id")
	resp, _ = h.post("/v1/chat/completions", h.keyA, chat("Remind ACME about invoice 7.", false))
	hit := resp.Header.Get("X-KyGate-Request-Id")
	if model == "" || hit == "" || resp.Header.Get("X-KyGate-Cache") != "hit" {
		t.Fatalf("ids %q %q, cache %q", model, hit, resp.Header.Get("X-KyGate-Cache"))
	}
	rate := func(key, body string) int {
		t.Helper()
		req, _ := http.NewRequest("POST", h.gw.URL+"/kygate/v1/feedback", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+key)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	for _, c := range []struct {
		key, body string
		code      int
	}{
		{h.keyA, `{"request_id":"` + model + `","rating":"good"}`, 202},
		{h.keyA, `{"request_id":"` + model + `","rating":"bad","reason":"wrong"}`, 202}, // replaces the first
		{h.keyA, `{"request_id":"` + hit + `","rating":"bad","reason":"outdated"}`, 202},
		{h.keyB, `{"request_id":"` + hit + `","rating":"good"}`, 202},                         // accepted, never counted: not its request
		{h.keyA, `{"request_id":"` + model + `","rating":"bad","reason":"it said Bob"}`, 400}, // no free text
		{h.keyA, `{"request_id":"` + model + `","rating":"meh"}`, 400},
		{h.keyA, `{"request_id":"../x","rating":"bad"}`, 400},
		{"kg-unknown", `{"request_id":"` + model + `","rating":"bad"}`, 401},
	} {
		if got := rate(c.key, c.body); got != c.code {
			t.Errorf("%s: %d, want %d", c.body, got, c.code)
		}
	}
	h.events() // deliver the spool
	rows, err := h.db.Quality(context.Background(), store.Range{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, r := range rows {
		got[r.Served+"/"+r.Rating+"/"+r.Reason] += r.Count
	}
	if len(got) != 2 || got["model/bad/wrong"] != 1 || got["exact/bad/outdated"] != 1 {
		t.Fatalf("ratings by how the answer was served: %v", got)
	}
}
