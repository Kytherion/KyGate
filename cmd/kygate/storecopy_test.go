package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/Kytherion/KyGate/internal/control"
	"github.com/Kytherion/KyGate/internal/identity"
	"github.com/Kytherion/KyGate/internal/store"
	"github.com/Kytherion/KyGate/internal/store/postgres"
	"github.com/Kytherion/KyGate/internal/store/sqlite"
)

// A Solo installation copied into PostgreSQL keeps its keys, hierarchy,
// people, provider keys (still readable with the same master key), events, and
// audit trail. Needs KYGATE_TEST_POSTGRES_URL (see internal/store/postgres).
func TestStoreCopy(t *testing.T) {
	base := os.Getenv("KYGATE_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("KYGATE_TEST_POSTGRES_URL is not set")
	}
	ctx := context.Background()
	dir := t.TempDir()
	src, err := sqlite.Open(filepath.Join(dir, control.DBFile))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	setup, err := control.Setup(ctx, src, dir, filepath.Join(dir, control.PolicyFile))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	src.CreateTeam(ctx, store.Team{ID: "t1", Name: "finance", OrgID: setup.OrgID, CreatedAt: now})
	src.CreateProject(ctx, store.Project{ID: "p1", Name: "ledger", TeamID: "t1", OrgID: setup.OrgID, CreatedAt: now})
	secret, k, _ := identity.CreateKey(ctx, src, "ledger-app", setup.OrgID)
	src.SetKeyProject(ctx, k.ID, "p1")
	userSecret, _, err := control.CreateUserSecret(ctx, src, setup.MasterKey, setup.OrgID, "ledger-app")
	if err != nil {
		t.Fatal(err)
	}
	src.SetKeyRequireUser(ctx, k.ID, true)
	identity.CreateKey(ctx, src, "old", setup.OrgID)
	src.RevokeKey(ctx, "old")
	src.PutUser(ctx, store.User{Email: "ana@example.com", Role: "team_lead", TeamID: "t1", CreatedAt: now})
	if err := control.AddCredential(ctx, src, setup.MasterKey, setup.OrgID, "openai", "openai", "", "eu", "sk-test-stand-in-123"); err != nil {
		t.Fatal(err)
	}
	var evs []store.Event
	for i := 0; i < 1203; i++ { // more than two pages of 500
		evs = append(evs, store.Event{ID: fmt.Sprintf("e%04d", i), Time: now.Add(-time.Duration(i) * time.Second), OrgID: setup.OrgID,
			KeyID: k.ID, KeyName: "ledger-app", Family: "openai", Endpoint: "chat", Status: 200, Outcome: "ok", Cache: "miss", Mode: "enforce", CostUSD: 0.01})
	}
	evs[0].Payload = []byte{1, 2, 3}
	src.InsertEvents(ctx, evs)
	src.RecordAdmin(ctx, store.AdminAction{Time: now, Actor: "command line", Action: "team.create", Target: "finance"})

	admin, _ := sql.Open("pgx", base)
	name := fmt.Sprintf("kygate_copy_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE ` + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`); admin.Close() })
	i := strings.LastIndex(base, "/")
	url := base[:i+1] + name + base[i+strings.Index(base[i:], "?"):]
	dst, err := postgres.Open(url)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()

	n, err := copyStore(ctx, src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if n.keys != 3 || n.teams != 1 || n.projects != 1 || n.users != 1 || n.creds != 1 || n.events != 1203 || n.admin != 1 {
		t.Fatalf("%+v", n)
	}
	// The same installation: the master key verifies, the provider key opens,
	// the virtual key resolves to its project and team.
	if err := control.VerifyMasterKey(ctx, dst, setup.MasterKey, setup.OrgID); err != nil {
		t.Fatal(err)
	}
	conns, _, err := control.StoredConnections(ctx, dst, setup.MasterKey, setup.OrgID)
	if err != nil || len(conns) != 1 {
		t.Fatalf("%v %d", err, len(conns))
	}
	if conns[0].Region != "eu" {
		t.Fatalf("the connection keeps its region: %q", conns[0].Region)
	}
	keys := identity.NewResolver()
	keys.Unseal = control.UserSecretOpener(setup.MasterKey, setup.OrgID)
	if err := keys.LoadFrom(ctx, dst); err != nil {
		t.Fatal(err)
	}
	c, ok := keys.Resolve(secret)
	if !ok || c.ProjectName != "ledger" || c.TeamName != "finance" || !c.RequiresUser() {
		t.Fatalf("%+v %v", c, ok)
	}
	// The key's signing secret still opens, so its applications' tokens still pass.
	tok, _ := identity.SignAppToken(userSecret, "ana", time.Hour, time.Now())
	if err := keys.User(ctx, &c, tok, nil, []byte("k"), time.Now()); err != nil || c.User == "" {
		t.Fatalf("user tokens after the copy: %v", err)
	}
	if keys.Count() != 2 { // default and ledger-app
		t.Fatal("the revoked key stays revoked")
	}
	if e, err := dst.GetEvent(ctx, "e0000"); err != nil || string(e.Payload) != string([]byte{1, 2, 3}) {
		t.Fatalf("payloads are copied: %v", err)
	}
	if tot, _ := dst.Totals(ctx, store.Range{From: now.Add(-time.Hour), To: now.Add(time.Hour)}); tot.Requests != 1203 {
		t.Fatalf("%+v", tot)
	}
	if _, err := copyStore(ctx, src, dst); err == nil || !strings.Contains(err.Error(), "already holds") {
		t.Fatalf("a second copy into the same database is refused: %v", err)
	}
}
