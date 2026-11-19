package control

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kytherion/KyGate/internal/policy"
)

// With PostgreSQL, policies live in the database: seeded at the first start
// (imported from files when there are some), written through the admin API,
// and read by every process. SQLite stands in for PostgreSQL
// here; the conformance suite holds both drivers to the same calls.
func TestPoliciesInTheDatabase(t *testing.T) {
	a := newAdminRig(t)
	ctx := context.Background()
	// The rig's policy.yaml and a level file, as an older Team installation
	// had them on the control volume.
	os.MkdirAll(filepath.Join(a.dir, "policies"), 0o700)
	os.WriteFile(filepath.Join(a.dir, "policies", "team-finance.yaml"), []byte("mode: enforce\n"), 0o600)
	got, err := SeedPolicies(ctx, a.db, filepath.Join(a.dir, "policy.yaml"))
	if err != nil || !strings.Contains(got, "1 level files") {
		t.Fatalf("imported once: %q %v", got, err)
	}
	if again, _ := SeedPolicies(ctx, a.db, filepath.Join(a.dir, "policy.yaml")); again != "" {
		t.Fatal("never twice")
	}
	docs := DBDocs{DB: a.db, BasePath: filepath.Join(a.dir, "policy.yaml")}
	h, err := policy.NewHolderFrom(docs)
	if err != nil {
		t.Fatal(err)
	}
	if h.Current().Path != "database:org" || len(h.Levels()) != 1 {
		t.Fatalf("%q %d", h.Current().Path, len(h.Levels()))
	}
	a.console.Policies = h
	// The files no longer matter: the database is the source.
	os.Remove(filepath.Join(a.dir, "policy.yaml"))
	body := strings.Replace(string(policy.Starter()), "mode: enforce", "mode: monitor", 1)
	if code, out := a.do("PUT", "/api/v1/admin/policies/org", body); code != 200 || !strings.Contains(out, "database:org") {
		t.Fatalf("%d %s", code, out)
	}
	if h.Current().Mode != policy.Monitor {
		t.Fatal("the holder reloads from the database")
	}
	if code, out := a.do("GET", "/api/v1/admin/policies/team-finance", ""); code != 200 || out != "mode: enforce\n" {
		t.Fatalf("%d %q", code, out)
	}
	if code, _ := a.do("PUT", "/api/v1/admin/policies/team-finance", "mode: [broken"); code != 422 {
		t.Fatal("validated before it is stored")
	}
	if code, _ := a.do("DELETE", "/api/v1/admin/policies/team-finance", ""); code != 204 {
		t.Fatal(code)
	}
	if code, _ := a.do("GET", "/api/v1/admin/policies/team-finance", ""); code != 404 {
		t.Fatal(code)
	}
	// A second process sees the change after its next reload.
	other, _ := policy.NewHolderFrom(docs)
	if other.Current().Mode != policy.Monitor || len(other.Levels()) != 0 {
		t.Fatal("same policies in every process")
	}
	// A fresh database with no files: the starter policy.
	b := newAdminRig(t)
	os.Remove(filepath.Join(b.dir, "policy.yaml"))
	if got, _ := SeedPolicies(ctx, b.db, filepath.Join(b.dir, "policy.yaml")); got != "starter" {
		t.Fatal(got)
	}
}
