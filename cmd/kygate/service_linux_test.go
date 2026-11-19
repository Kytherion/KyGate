package main

import (
	"strings"
	"testing"
)

func TestUnitFile(t *testing.T) {
	cfg := &serviceConfig{Name: "kygate", Exe: "/home/dev/bin/ky gate", DataDir: "/home/dev/.kygate 100%"}
	u := unitFile(cfg)
	for _, want := range []string{
		`ExecStart="/home/dev/bin/ky gate" service run --data-dir "/home/dev/.kygate 100%%"`,
		"Restart=on-failure", "WantedBy=default.target",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
}

func TestGuardUnit(t *testing.T) {
	cfg := &serviceConfig{Name: "kygate", Exe: "/bin/kygate", DataDir: "/d", GuardCmd: []string{"/venv/bin/kygate-guard", "--listen", "127.0.0.1:4002"}}
	if u := unitFile(cfg); !strings.Contains(u, "Wants=kygate-guard.service\nAfter=kygate-guard.service\n") {
		t.Fatalf("the gateway's unit must start the Guard first:\n%s", u)
	}
	if g := guardUnitFile(cfg); !strings.Contains(g, `ExecStart="/venv/bin/kygate-guard" "--listen" "127.0.0.1:4002"`) || !strings.Contains(g, "Restart=on-failure") {
		t.Fatalf("guard unit:\n%s", g)
	}
	if u := unitFile(&serviceConfig{Name: "kygate", Exe: "/bin/kygate", DataDir: "/d"}); strings.Contains(u, "guard") {
		t.Fatal("no Guard, no dependency")
	}
}
