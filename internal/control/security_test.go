package control

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
	"github.com/Kytherion/KyGate/internal/store/sqlite"
)

// The security report answers by key and by hour for a 24-hour range, and
// carries counts only.
func TestSecurityEndpoint(t *testing.T) {
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "kygate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = db.InsertEvents(context.Background(), []store.Event{{ID: "1", Time: time.Now().Add(-time.Minute), OrgID: "o", KeyName: "alice",
		Family: "openai", Endpoint: "chat", Status: 403, Outcome: "blocked", Cache: "off", Mode: "enforce",
		Findings: []store.FindingCount{{Type: "PROMPT_INJECTION", Action: "block", Count: 1, Applied: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	c := &Console{Events: db}
	w := httptest.NewRecorder()
	c.security(w, httptest.NewRequest("GET", "/api/v1/security?range=24h", nil))
	var out struct {
		Bucket  string              `json:"bucket"`
		Sources []store.SecurityRow `json:"sources"`
		Series  []store.SecurityRow `json:"series"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != 200 {
		t.Fatalf("%d %v %s", w.Code, err, w.Body)
	}
	if out.Bucket != "hour" || len(out.Sources) != 1 || out.Sources[0].Key != "alice" || out.Sources[0].Threats != 1 || out.Sources[0].Blocked != 1 || len(out.Series) != 1 {
		t.Fatalf("%+v", out)
	}
	if !strings.Contains(w.Body.String(), `"guard_unavailable"`) {
		t.Fatalf("%s", w.Body)
	}
}
