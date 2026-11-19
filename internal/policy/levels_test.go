package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const orgPolicy = `kind: Policy
mode: monitor
data:
  on_guard_unavailable: fast_detectors_only
  entities:
    SECRET:      { action: block }
    EMAIL:       { action: allow }
    CREDIT_CARD: { action: mask }
  unreadable_content: allow
threats:
  prompt_injection: { action: alert, min_score: 0.8 }
output:
  images: { action: alert }
  allowed_domains: [a.example, b.example]
cache:
  exact: { enabled: true, ttl: 30d }
routing:
  mode: off
budgets:
  org: { monthly_usd: { hard: 100 } }
  per_key: { daily_usd: { hard: 5 } }
audit:
  retention_days: 90
`

func level(kind, name, body string) LevelFile {
	return LevelFile{Kind: kind, Name: name, Path: kind + "-" + name + ".yaml", Data: []byte(body)}
}

func TestStrictestWinsForSecurity(t *testing.T) {
	p, err := Effective([]byte(orgPolicy), "policy.yaml", []LevelFile{level("team", "finance", `
mode: enforce
data:
  on_guard_unavailable: block
  entities:
    EMAIL:       { action: mask }
    CREDIT_CARD: { action: allow }        # looser: ignored
    IBAN:        { action: block }
  unreadable_content: block
threats:
  prompt_injection: { action: block, min_score: 0.9, segments: [user] }
output:
  images: { action: remove }
  allowed_domains: [b.example, c.example]
audit:
  retention_days: 7
`)})
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != Enforce || p.Data.OnGuardUnavailable != "block" || p.Data.UnreadableContent != Block {
		t.Fatalf("%+v", p.Data)
	}
	if p.ActionFor("EMAIL") != Mask || p.ActionFor("CREDIT_CARD") != Mask || p.ActionFor("IBAN") != Block {
		t.Fatalf("EMAIL %s CREDIT_CARD %s IBAN %s", p.ActionFor("EMAIL"), p.ActionFor("CREDIT_CARD"), p.ActionFor("IBAN"))
	}
	r := p.Threats["prompt_injection"]
	if r.Action != Block || r.MinScore != 0.8 || strings.Join(r.Segments, ",") != "user,tool_result" {
		t.Fatalf("the lower score and both segments: %+v", r)
	}
	if p.Output.Images.Action != Remove || strings.Join(p.Output.AllowedDomains, ",") != "b.example" {
		t.Fatalf("%+v", p.Output)
	}
	if p.Audit.RetentionDays != 90 || !strings.Contains(strings.Join(p.Warnings, "\n"), "audit is set in the organization's policy only") {
		t.Fatalf("audit is the organization's: %d %v", p.Audit.RetentionDays, p.Warnings)
	}
}

func TestMostSpecificWinsAndLevelBudgets(t *testing.T) {
	p, err := Effective([]byte(orgPolicy), "policy.yaml", []LevelFile{
		level("team", "eng", "routing: { mode: shadow }\nbudgets: { monthly_usd: { soft: 40, hard: 50 }, per_key: { daily_usd: { hard: 2 } } }\n"),
		level("project", "api", "cache: { exact: { ttl: 1d } }\nbudgets: { daily_usd: { hard: 3 } }\nrouting: { mode: off }\n"),
		level("key", "ci", "budgets: { daily_usd: { hard: 1 } }\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.RoutingShadow() || time.Duration(p.Cache.Exact.TTL) != 24*time.Hour || !p.CacheEnabled() {
		t.Fatalf("the project's routing and TTL, the org's enabled: %+v", p.Cache.Exact)
	}
	b := p.Budget
	if b.Org.Monthly.Hard != 100 || b.Team.Monthly.Hard != 50 || b.Project.Daily.Hard != 3 || b.ForKey("ci").Daily.Hard != 1 || b.ForKey("other").Daily.Hard != 2 {
		t.Fatalf("%+v", b)
	}
}

func TestLevelFilesAndTheHolder(t *testing.T) {
	dir := t.TempDir()
	org := filepath.Join(dir, "policy.yaml")
	os.WriteFile(org, []byte(orgPolicy), 0o600)
	lv := filepath.Join(dir, LevelsDir)
	os.MkdirAll(lv, 0o700)
	os.WriteFile(filepath.Join(lv, "team-finance.yaml"), []byte("data:\n  entities:\n    EMAIL: { action: block }\n"), 0o600)
	os.WriteFile(filepath.Join(lv, "notes.yaml"), []byte("x: 1\n"), 0o600)
	var errs []string
	h, err := NewHolder(org)
	if err != nil {
		t.Fatal(err)
	}
	h.OnError = func(e error) { errs = append(errs, e.Error()) }
	if h.For("finance", "", "").ActionFor("EMAIL") != Block || h.For("sales", "", "") != h.Current() {
		t.Fatal("finance gets its file; a team without one gets the organization's policy")
	}
	if h.For("finance", "", "") != h.For("finance", "", "") {
		t.Fatal("effective policies are kept, not merged per request")
	}
	// An invalid edit keeps the last good version.
	time.Sleep(20 * time.Millisecond)
	os.WriteFile(filepath.Join(lv, "team-finance.yaml"), []byte("data:\n  entities:\n    EMAIL: { action: obliterate }\n"), 0o600)
	h.reloadIfChanged()
	if h.For("finance", "", "").ActionFor("EMAIL") != Block || len(errs) == 0 || !strings.Contains(strings.Join(errs, "\n"), "last good version") {
		t.Fatalf("%v", errs)
	}
	if !strings.Contains(strings.Join(errs, "\n"), "notes.yaml: not used") {
		t.Fatalf("a badly named file is reported: %v", errs)
	}
}

const minimal = "kind: Policy\ndata:\n  unreadable_content: allow\n"

// Region pinning (GV-4): a level can only narrow the regions.
func TestRegionsIntersect(t *testing.T) {
	org := orgPolicy + "\n" // no regions: no pinning
	p, err := Effective([]byte(strings.Replace(org, "  unreadable_content: allow\n", "  unreadable_content: allow\n  regions: [EU, us]\n", 1)), "policy.yaml",
		[]LevelFile{level("team", "finance", "data:\n  regions: [eu, ap]\n")})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Data.Regions, ",") != "eu" || !p.AllowsRegion("eu") || p.AllowsRegion("us") || p.AllowsRegion("") {
		t.Fatalf("eu only: %v", p.Data.Regions)
	}
	p, err = Effective([]byte(strings.Replace(org, "  unreadable_content: allow\n", "  unreadable_content: allow\n  regions: [us]\n", 1)), "policy.yaml",
		[]LevelFile{level("team", "finance", "data:\n  regions: [eu]\n")})
	if err != nil {
		t.Fatal(err)
	}
	if p.AllowsRegion("eu") || p.AllowsRegion("us") || p.AllowsRegion("") {
		t.Fatalf("nothing in common: no region is allowed, %v", p.Data.Regions)
	}
	p, _ = Effective([]byte(org), "policy.yaml", []LevelFile{level("project", "x", "data:\n  regions: [eu]\n")})
	if !p.AllowsRegion("eu") || p.AllowsRegion("us") {
		t.Fatalf("a level pins when the organization does not: %v", p.Data.Regions)
	}
	if p, _ := Parse([]byte(org), ""); !p.AllowsRegion("") || !p.AllowsRegion("us") {
		t.Fatal("no regions: no pinning")
	}
	if _, err := Parse([]byte(minimal+"  regions: [\"eu west\"]\n"), ""); err == nil {
		t.Fatal("a region name is checked")
	}
}

func TestRetentionPerKind(t *testing.T) {
	p, err := Parse([]byte(minimal+"audit:\n  retention_days: 60\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Audit.PayloadRetentionDays != 60 || p.Audit.AdminRetentionDays != 0 {
		t.Fatalf("an upgrade keeps payloads as long as events, and the trail forever: %+v", p.Audit)
	}
	p, _ = Parse([]byte(minimal+"audit:\n  retention_days: 60\n  payload_retention_days: 400\n"), "")
	if p.Audit.PayloadRetentionDays != 60 {
		t.Fatal("a payload never outlives its event")
	}
	if _, err := Parse([]byte(minimal+"audit:\n  admin_retention_days: -1\n"), ""); err == nil {
		t.Fatal("a negative period is refused")
	}
	s, _ := Parse(Starter(), "")
	if s.Audit.PayloadRetentionDays != 30 || s.Audit.AdminRetentionDays != 365 || len(s.Data.Regions) != 0 {
		t.Fatalf("the starter policy: %+v %v", s.Audit, s.Data.Regions)
	}
}

func TestOnCountersUnavailable(t *testing.T) {
	p, err := Parse([]byte(minimal), "")
	if err != nil || p.Budget.OnCountersUnavailable != "last_known" {
		t.Fatalf("the design's default: %v %q", err, p.Budget.OnCountersUnavailable)
	}
	p, _ = Parse([]byte(minimal+"budgets:\n  on_counters_unavailable: refuse\n"), "")
	if p.Budget.OnCountersUnavailable != "refuse" {
		t.Fatal(p.Budget.OnCountersUnavailable)
	}
	if _, err := Parse([]byte(minimal+"budgets:\n  on_counters_unavailable: maybe\n"), ""); err == nil {
		t.Fatal("checked")
	}
}
