package control

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Kytherion/KyGate/internal/provider"
	"github.com/Kytherion/KyGate/internal/store/sqlite"
)

// A connection's region, OpenAI organization, and project come from the
// environment, by the connection's name.
func TestConnectionSettingsFromTheEnvironment(t *testing.T) {
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "kygate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old := provider.Environ
	provider.Environ = func() []string {
		return []string{"OPENAI_API_KEY=sk-test-1", "OPENAI_API_KEY_TEAM=sk-test-2", "KYGATE_OPENAI_ORG_OPENAI_TEAM=org-team",
			"KYGATE_OPENAI_PROJECT_OPENAI_TEAM=proj-team", "KYGATE_REGION_OPENAI=eu", "ANTHROPIC_API_KEY=sk-ant-test", "KYGATE_OPENAI_ORG_ANTHROPIC=org-x"}
	}
	defer func() { provider.Environ = old }()
	conns, _, err := Connections(context.Background(), db, make([]byte, 32), "org_test", nil)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]*provider.Connection{}
	for _, c := range conns {
		by[c.Name] = c
	}
	if c := by["openai-team"]; c == nil || c.Organization != "org-team" || c.Project != "proj-team" {
		t.Fatalf("%+v", c)
	}
	if c := by["openai"]; c == nil || c.Region != "eu" || c.Organization != "" {
		t.Fatalf("%+v", c)
	}
	if c := by["anthropic"]; c == nil || c.Organization != "" {
		t.Fatal("an organization applies to OpenAI connections only")
	}
}
