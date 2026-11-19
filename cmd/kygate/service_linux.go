package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Linux: a systemd user unit. It needs no root, runs as the user on the
// user's data directory, and systemd restarts KyGate when it fails. With
// lingering on ('loginctl enable-linger'), it starts at boot and keeps running
// after logout.

const (
	defaultServiceName = "kygate"
	serviceSupported   = true
)

func serviceKind() string { return "a systemd user unit that starts KyGate when you log in" }

func logHint(cfg *serviceConfig) string { return "journalctl --user -u " + cfg.Name }

func unitPath(name string) string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "systemd", "user", name+".service")
}

// systemdQuote quotes one word of a systemd command line.
func systemdQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "%", "%%")
	return `"` + s + `"`
}

func guardUnitName(cfg *serviceConfig) string { return cfg.Name + "-guard" }

// guardUnitFile runs the Guard, which the gateway's unit wants.
func guardUnitFile(cfg *serviceConfig) string {
	var cmd []string
	for _, a := range cfg.GuardCmd {
		cmd = append(cmd, systemdQuote(a))
	}
	return `# Installed by 'kygate service install --guard-exe'. Remove it with 'kygate service uninstall'.
[Unit]
Description=KyGate Guard (ML detection for the KyGate gateway)

[Service]
Type=simple
ExecStart=` + strings.Join(cmd, " ") + `
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
`
}

func unitFile(cfg *serviceConfig) string {
	guardDeps := ""
	if len(cfg.GuardCmd) > 0 {
		guardDeps = "Wants=" + guardUnitName(cfg) + ".service\nAfter=" + guardUnitName(cfg) + ".service\n"
	}
	return `# Installed by 'kygate service install'. Remove it with 'kygate service uninstall'.
[Unit]
Description=KyGate AI gateway
After=network-online.target
Wants=network-online.target
` + guardDeps + `
[Service]
Type=simple
ExecStart=` + systemdQuote(cfg.Exe) + ` service run --data-dir ` + systemdQuote(cfg.DataDir) + `
Restart=on-failure
RestartSec=3
TimeoutStopSec=45

[Install]
WantedBy=default.target
`
}

func systemctl(args ...string) (string, error) {
	out, err := exec.Command("systemctl", append([]string{"--user"}, args...)...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("systemctl --user %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func registerService(cfg *serviceConfig) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("this system has no systemd; run 'kygate serve' under your own service manager")
	}
	p := unitPath(cfg.Name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(unitFile(cfg)), 0o644); err != nil {
		return err
	}
	gp := unitPath(guardUnitName(cfg))
	if len(cfg.GuardCmd) > 0 {
		if err := os.WriteFile(gp, []byte(guardUnitFile(cfg)), 0o644); err != nil {
			return err
		}
	} else {
		os.Remove(gp)
	}
	if _, err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if _, err := systemctl("enable", cfg.Name); err != nil {
		return err
	}
	if len(cfg.GuardCmd) > 0 {
		if _, err := systemctl("enable", guardUnitName(cfg)); err != nil {
			return err
		}
	}
	if out, err := exec.Command("loginctl", "show-user", os.Getenv("USER"), "--property=Linger").Output(); err == nil && strings.TrimSpace(string(out)) == "Linger=no" {
		fmt.Println("To start KyGate at boot and keep it running after you log out, run once: loginctl enable-linger " + os.Getenv("USER"))
	}
	return nil
}

func unregisterService(cfg *serviceConfig) error {
	p := unitPath(cfg.Name)
	if !fileExists(p) {
		return nil
	}
	systemctl("disable", cfg.Name)
	if err := os.Remove(p); err != nil {
		return err
	}
	if gp := unitPath(guardUnitName(cfg)); fileExists(gp) {
		systemctl("disable", "--now", guardUnitName(cfg))
		os.Remove(gp)
	}
	_, err := systemctl("daemon-reload")
	return err
}

func startService(cfg *serviceConfig) error {
	_, err := systemctl("start", cfg.Name)
	return err
}

func stopService(cfg *serviceConfig) error {
	if !fileExists(unitPath(cfg.Name)) {
		return nil
	}
	_, err := systemctl("stop", cfg.Name)
	if len(cfg.GuardCmd) > 0 {
		systemctl("stop", guardUnitName(cfg))
	}
	return err
}

func serviceState(cfg *serviceConfig) (registered, running bool) {
	out, _ := exec.Command("systemctl", "--user", "is-active", cfg.Name).Output()
	return fileExists(unitPath(cfg.Name)), strings.TrimSpace(string(out)) == "active"
}

// runService is what systemd starts: KyGate itself, logging to the journal.
// systemd stops it with SIGTERM, which 'kygate serve' handles gracefully.
func runService(cfg *serviceConfig) error {
	for k, v := range cfg.Env {
		if os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
	return serve(cfg.serveArgs()[1:])
}

func superviseService(cfg *serviceConfig) error {
	return fmt.Errorf("on Linux, systemd supervises KyGate")
}

// persistentEnv reports whether the systemd user manager passes the variable
// to its services.
func persistentEnv(name string) bool {
	out, err := exec.Command("systemctl", "--user", "show-environment").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, name+"=") {
			return true
		}
	}
	return false
}
