package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kytherion/KyGate/internal/policy"
)

// 'kygate policy enable' writes the change, keeps the previous file as .bak,
// and the result loads.
func TestPolicyEnableWritesWithABackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	orig := policy.Starter()
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KYGATE_GUARD", "")
	if err := policyEnable([]string{"PERSON", "ADDRESS", "--policy", path, "--data-dir", dir, "--yes"}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	bak, _ := os.ReadFile(path + ".bak")
	if string(bak) != string(orig) {
		t.Fatal("the backup must hold the previous policy")
	}
	p, err := policy.Parse(got, path)
	if err != nil || p.Data.Entities["PERSON"].Action != policy.Alert || p.Data.Entities["ADDRESS"].Action != policy.Alert {
		t.Fatalf("alert is the default, to measure first: %v %+v", err, p.Data.Entities)
	}
	// Then mask, and require a model for one type.
	if err := policyEnable([]string{"PERSON", "--action", "mask", "--require-model", "--policy", path, "--data-dir", dir, "--yes"}); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(path)
	if !strings.Contains(string(got), "PERSON:      { action: mask, detection: model }") {
		t.Fatalf("%s", got)
	}
	if _, err := os.Stat(path + ".new"); !os.IsNotExist(err) {
		t.Fatal("no temporary file may be left")
	}
}

// Without --yes and with no answer, nothing is written.
func TestPolicyEnableAsksFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, policy.Starter(), 0o600)
	t.Setenv("KYGATE_GUARD", "")
	stdin := os.Stdin
	r, w, _ := os.Pipe()
	w.Close() // an empty answer
	os.Stdin = r
	defer func() { os.Stdin = stdin }()
	if err := policyEnable([]string{"PERSON", "--policy", path, "--data-dir", dir}); err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("got %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(policy.Starter()) {
		t.Fatal("the policy must be unchanged")
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatal("no backup without a change")
	}
}
