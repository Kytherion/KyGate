package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
)

func TestSecurityReport(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "kygate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().Truncate(time.Hour).Add(30 * time.Minute)
	ev := func(id, key, outcome string, alert bool, guard string, f ...store.FindingCount) store.Event {
		return store.Event{ID: id, Time: now, OrgID: "o", KeyName: key, Family: "openai", Endpoint: "chat", Status: 200,
			Outcome: outcome, Cache: "miss", Mode: "enforce", Alert: alert, Guard: guard, Findings: f}
	}
	events := []store.Event{
		ev("1", "alice", "ok", false, "", store.FindingCount{Type: "CREDIT_CARD", Action: "mask", Count: 2, Applied: true}),
		ev("2", "alice", "blocked", false, "ok", store.FindingCount{Type: "PROMPT_INJECTION", Action: "block", Count: 1, Applied: true}),
		ev("3", "alice", "ok", false, "", store.FindingCount{Type: "OUTPUT_IMAGE", Action: "remove", Count: 1, Applied: true},
			store.FindingCount{Type: "EMAIL", Action: "allow", Count: 1, Applied: true}),
		ev("4", "bob", "ok", true, "", store.FindingCount{Type: "OUTPUT_LINK", Action: "alert", Count: 3, Applied: true}),
		ev("5", "bob", "refused", false, "unavailable"),
		ev("6", "bob", "ok", false, ""),
		// Monitor mode: recorded, not applied, so no answer was changed.
		ev("7", "carol", "ok", false, "", store.FindingCount{Type: "OUTPUT_SECRET", Action: "remove", Count: 1, Applied: false}),
	}
	if err := db.InsertEvents(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	rg := store.Range{From: now.Add(-time.Hour), To: now.Add(time.Hour)}
	rows, err := db.Security(context.Background(), rg, "key")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]store.SecurityRow{}
	for _, r := range rows {
		got[r.Key] = r
	}
	want := map[string]store.SecurityRow{
		"alice": {Key: "alice", Requests: 3, WithData: 2, Threats: 1, AnswersChanged: 1, Blocked: 1},
		"bob":   {Key: "bob", Requests: 3, OutputAlerts: 1, Refused: 1, Alerts: 1, GuardDown: 1},
		"carol": {Key: "carol", Requests: 1},
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %+v\nwant %+v", k, got[k], w)
		}
	}
	if rows[0].Key != "alice" {
		t.Errorf("the key with the most to report comes first: %v", rows[0].Key)
	}
	series, err := db.Security(context.Background(), rg, "hour")
	if err != nil || len(series) != 1 || series[0].Requests != 7 || series[0].WithData != 2 {
		t.Fatalf("%v %+v", err, series)
	}
	if _, err := db.Security(context.Background(), rg, "model"); err == nil {
		t.Fatal("unknown grouping")
	}
}
