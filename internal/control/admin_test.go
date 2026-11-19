package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store/sqlite"
)

type adminRig struct {
	t       *testing.T
	console *Console
	srv     *httptest.Server
	token   string
	db      *sqlite.DB
	dir     string
}

func newAdminRig(t *testing.T) *adminRig {
	dir := t.TempDir()
	db, err := sqlite.Open(filepath.Join(dir, "kygate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	polPath := filepath.Join(dir, "policy.yaml")
	setup, err := Setup(context.Background(), db, dir, polPath)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := policy.NewHolder(polPath)
	if err != nil {
		t.Fatal(err)
	}
	c := &Console{Config: db, Events: db, Policies: holder, MasterKey: setup.MasterKey, OrgID: setup.OrgID, Logf: t.Logf}
	srv := httptest.NewServer(c.Handler())
	t.Cleanup(srv.Close)
	return &adminRig{t: t, console: c, srv: srv, token: setup.AdminToken, db: db, dir: dir}
}

func (a *adminRig) do(method, path, body string) (int, string) {
	a.t.Helper()
	req, _ := http.NewRequest(method, a.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+a.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAdminHierarchyAndKeys(t *testing.T) {
	a := newAdminRig(t)
	if code, _ := a.do("POST", "/api/v1/admin/teams", `{"name":"finance"}`); code != 201 {
		t.Fatalf("team: %d", code)
	}
	if code, _ := a.do("POST", "/api/v1/admin/teams", `{"name":"finance"}`); code != 409 {
		t.Fatalf("a name is unique: %d", code)
	}
	if code, body := a.do("POST", "/api/v1/admin/teams", `{"name":"no spaces"}`); code != 400 || !strings.Contains(body, "letters") {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := a.do("POST", "/api/v1/admin/projects", `{"name":"ledger","team":"finance"}`); code != 201 {
		t.Fatalf("project: %d", code)
	}
	code, body := a.do("POST", "/api/v1/admin/keys", `{"name":"ledger-app","project":"ledger"}`)
	var k struct {
		Key       string `json:"key"`
		ID        string `json:"id"`
		ProjectID string `json:"project_id"`
	}
	json.Unmarshal([]byte(body), &k)
	if code != 201 || !strings.HasPrefix(k.Key, "kg-") || k.ProjectID == "" {
		t.Fatalf("%d %s", code, body)
	}
	_, h := a.do("GET", "/api/v1/admin/hierarchy", "")
	if strings.Contains(h, k.Key) || !strings.Contains(h, `"name":"ledger-app"`) {
		t.Fatal("the key is shown once, never listed")
	}
	if code, body := a.do("DELETE", "/api/v1/admin/projects/ledger", ""); code != 409 || !strings.Contains(body, "active keys") {
		t.Fatalf("a project with keys stays: %d %s", code, body)
	}
	if code, _ := a.do("DELETE", "/api/v1/admin/teams/finance", ""); code != 409 {
		t.Fatalf("a team with projects stays: %d", code)
	}
	if code, _ := a.do("PUT", "/api/v1/admin/keys/ledger-app/project", `{"project":""}`); code != 204 {
		t.Fatalf("move: %d", code)
	}
	if code, _ := a.do("POST", "/api/v1/admin/keys/ledger-app/revoke", ""); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := a.do("DELETE", "/api/v1/admin/projects/ledger", ""); code != 204 {
		t.Fatalf("delete project: %d", code)
	}
	_, log := a.do("GET", "/api/v1/admin/log", "")
	for _, act := range []string{"team.create", "project.create", "key.create", "key.move", "key.revoke", "project.delete"} {
		if !strings.Contains(log, act) {
			t.Fatalf("%s not in the audit trail: %s", act, log)
		}
	}
	// Without the token, nothing.
	req, _ := http.NewRequest("POST", a.srv.URL+"/api/v1/admin/teams", strings.NewReader(`{"name":"x"}`))
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Fatalf("%d", resp.StatusCode)
	}
}

func TestAdminProviderKeyIsNeverReturned(t *testing.T) {
	a := newAdminRig(t)
	secret := "sk-test-stand-in-0123456789abcdef"
	code, body := a.do("POST", "/api/v1/admin/providers", `{"name":"openai-2","provider":"openai","key":"`+secret+`"}`)
	if code != 201 || strings.Contains(body, secret) {
		t.Fatalf("%d %s", code, body)
	}
	_, log := a.do("GET", "/api/v1/admin/log", "")
	if strings.Contains(log, secret) || !strings.Contains(log, "provider.add") {
		t.Fatalf("%s", log)
	}
	creds, _ := a.db.ListCredentials(context.Background())
	if len(creds) != 1 || strings.Contains(string(creds[0].Ciphertext), secret) {
		t.Fatal("stored sealed")
	}
	if code, _ := a.do("DELETE", "/api/v1/admin/providers/openai-2", ""); code != 204 {
		t.Fatalf("%d", code)
	}
}

func TestAdminPolicies(t *testing.T) {
	a := newAdminRig(t)
	if code, body := a.do("PUT", "/api/v1/admin/policies/team-finance", "data:\n  entities:\n    EMAIL: { action: obliterate }\n"); code != 422 {
		t.Fatalf("a file that would not load is refused: %d %s", code, body)
	}
	code, body := a.do("PUT", "/api/v1/admin/policies/team-finance", "data:\n  entities:\n    EMAIL: { action: block }\naudit:\n  retention_days: 1\n")
	if code != 200 || !strings.Contains(body, "audit is set in the organization") {
		t.Fatalf("%d %s", code, body)
	}
	if _, err := os.Stat(filepath.Join(a.dir, policy.LevelsDir, "team-finance.yaml")); err != nil {
		t.Fatal(err)
	}
	if code, body := a.do("GET", "/api/v1/admin/policies/team-finance", ""); code != 200 || !strings.Contains(body, "EMAIL") {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := a.do("PUT", "/api/v1/admin/policies/org", "kind: Policy\nmode: sometimes\n"); code != 422 {
		t.Fatalf("%d", code)
	}
	if code, _ := a.do("PUT", "/api/v1/admin/policies/../../etc", "x"); code == 200 {
		t.Fatal("no path outside the policies folder")
	}
	if code, _ := a.do("DELETE", "/api/v1/admin/policies/team-finance", ""); code != 204 {
		t.Fatalf("%d", code)
	}
	if _, err := os.Stat(filepath.Join(a.dir, policy.LevelsDir, "team-finance.yaml.bak")); err != nil {
		t.Fatal("a deleted policy is kept as .bak")
	}
}
