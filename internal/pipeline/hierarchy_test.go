package pipeline_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/identity"
	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store"
)

// placeB puts bob's key in project "ledger" of team "finance", writes the
// given per-level files, and reloads keys and policies as a running KyGate does.
func placeB(t *testing.T, h *harness, files map[string]string) {
	ctx := context.Background()
	org, _ := h.db.Meta(ctx, "org_id")
	team := store.Team{ID: identity.NewID("team_"), Name: "finance", OrgID: org, CreatedAt: time.Now()}
	proj := store.Project{ID: identity.NewID("proj_"), Name: "ledger", TeamID: team.ID, OrgID: org, CreatedAt: time.Now()}
	if err := h.db.CreateTeam(ctx, team); err != nil {
		t.Fatal(err)
	}
	if err := h.db.CreateProject(ctx, proj); err != nil {
		t.Fatal(err)
	}
	if ok, err := h.db.SetKeyProject(ctx, "bob", proj.ID); !ok || err != nil {
		t.Fatal(ok, err)
	}
	dir := filepath.Join(filepath.Dir(h.polPath), policy.LevelsDir)
	os.MkdirAll(dir, 0o700)
	for name, body := range files {
		os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600)
	}
	h.holder.Reload()
	if err := h.keys.LoadFrom(ctx, h.db); err != nil {
		t.Fatal(err)
	}
}

// A team's policy file applies to its keys only, and can only tighten.
func TestTeamPolicyAppliesToItsKeys(t *testing.T) {
	h := newHarness(t, "")
	placeB(t, h, map[string]string{"team-finance.yaml": "data:\n  entities:\n    EMAIL: { action: block }\n    CREDIT_CARD: { action: allow }\n"})
	msg := chat("Write to alice.martin@example.com about card "+cardA, false)
	resp, _ := h.post("/v1/chat/completions", h.keyA, msg)
	if resp.StatusCode != 200 {
		t.Fatalf("alice is in no team: the organization's policy allows EMAIL: %d", resp.StatusCode)
	}
	resp, body := h.post("/v1/chat/completions", h.keyB, msg)
	if resp.StatusCode != 403 || resp.Header.Get("X-KyGate-Blocked") != "EMAIL" {
		t.Fatalf("bob's team blocks EMAIL: %d %s", resp.StatusCode, body)
	}
	e := h.event(resp.Header.Get("X-KyGate-Request-Id"))
	if e.TeamName != "finance" || e.ProjectName != "ledger" || e.PolicyVersion == h.holder.Current().Version {
		t.Fatalf("%+v", e)
	}
	// The team tried to loosen CREDIT_CARD to allow: the organization's mask stays.
	resp, _ = h.post("/v1/chat/completions", h.keyB, chat("Charge card "+cardA, false))
	if resp.StatusCode != 200 || resp.Header.Get("X-KyGate-Masked") != "1" {
		t.Fatalf("%d masked %q", resp.StatusCode, resp.Header.Get("X-KyGate-Masked"))
	}
	rows, err := h.db.GroupBy(context.Background(), store.Range{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)}, "team")
	if err != nil || len(rows) != 2 {
		t.Fatalf("%v %+v", err, rows)
	}
}

// A team's budget is the team's own total.
func TestTeamBudget(t *testing.T) {
	h := newHarness(t, "")
	placeB(t, h, map[string]string{"team-finance.yaml": "budgets:\n  daily_usd: { hard: 0.01 }\n"})
	resp, body := h.post("/v1/messages", h.keyB, messages("Hello", false))
	if resp.StatusCode != 429 || resp.Header.Get("X-KyGate-Budget") != "hard:team:daily" || !strings.Contains(body, "this team's daily budget") {
		t.Fatalf("%d %q %s", resp.StatusCode, resp.Header.Get("X-KyGate-Budget"), body)
	}
	if resp, _ := h.post("/v1/messages", h.keyA, messages("Hello", false)); resp.StatusCode != 200 {
		t.Fatalf("alice is not in the team: %d", resp.StatusCode)
	}
}
