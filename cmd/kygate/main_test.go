package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kytherion/KyGate/internal/policy"
)

// policy check --strict fails, for a CI job, when it cannot show that the
// Guard covers what the policy needs it for.
func TestPolicyCheckStrict(t *testing.T) {
	t.Setenv("KYGATE_GUARD", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	pol := strings.Replace(string(policy.Starter()), "    EMAIL:       { action: allow }", "    EMAIL:       { action: allow }\n    PERSON:      { action: mask }", 1)
	if err := os.WriteFile(path, []byte(pol), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := policyCmd([]string{"check", path, "--data-dir", dir}); err != nil {
		t.Fatalf("without --strict it only notes: %v", err)
	}
	if err := policyCmd([]string{"check", path, "--data-dir", dir, "--strict"}); err == nil || !strings.Contains(err.Error(), "--strict needs --guard") {
		t.Fatalf("%v", err)
	}
	if err := policyCmd([]string{"check", filepath.Join(dir, "starter.yaml"), "--data-dir", dir, "--strict"}); err == nil {
		t.Fatal("a missing file must fail")
	}
	starter := filepath.Join(dir, "starter.yaml")
	os.WriteFile(starter, policy.Starter(), 0o600)
	if err := policyCmd([]string{"check", starter, "--data-dir", dir, "--strict"}); err != nil {
		t.Fatalf("a policy that needs no Guard passes: %v", err)
	}
}

// A command whose flags are defined twice panics at run time: each command
// that takes the shared flags must parse.
func TestCommandFlagsDoNotClash(t *testing.T) {
	for name, run := range map[string]func([]string) error{"policy show": policyShow} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: %v", name, r)
				}
			}()
			run([]string{"--data-dir", t.TempDir()})
		}()
	}
}
