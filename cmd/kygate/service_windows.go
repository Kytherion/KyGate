package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
)

// Windows: a scheduled task for the current user, started at logon. A
// scheduled task needs no administrator rights and runs as the user, on the
// user's own data directory and environment. A Windows service would need
// both an elevation and an account with access to that directory.

const (
	defaultServiceName = "KyGate"
	serviceSupported   = true

	createNoWindow         = 0x08000000
	createNewProcessGroup  = 0x00000200
	createBreakawayFromJob = 0x01000000
	detachedProcess        = 0x00000008
)

func serviceKind() string { return "a Windows scheduled task that starts KyGate when you log on" }

func logHint(cfg *serviceConfig) string { return cfg.path(logFileName) }

func taskXML(cfg *serviceConfig, userID string) string {
	esc := func(s string) string {
		var b bytes.Buffer
		xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	args := fmt.Sprintf(`service run --data-dir "%s"`, cfg.DataDir)
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>KyGate AI gateway, installed by 'kygate service install'. Remove it with 'kygate service uninstall'.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + esc(userID) + `</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + esc(userID) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + esc(cfg.Exe) + `</Command>
      <Arguments>` + esc(args) + `</Arguments>
    </Exec>
  </Actions>
</Task>
`
}

func schtasks(args ...string) (string, error) {
	out, err := exec.Command("schtasks", args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("schtasks %s: %s", args[0], strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func registerService(cfg *serviceConfig) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	// Task Scheduler reads task files in UTF-16.
	u16 := utf16.Encode([]rune(taskXML(cfg, u.Username)))
	b := []byte{0xFF, 0xFE}
	for _, c := range u16 {
		b = append(b, byte(c), byte(c>>8))
	}
	f, err := os.CreateTemp("", "kygate-task-*.xml")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	f.Close()
	_, err = schtasks("/Create", "/TN", cfg.Name, "/XML", f.Name(), "/F")
	return err
}

func unregisterService(cfg *serviceConfig) error {
	if _, err := schtasks("/Query", "/TN", cfg.Name); err != nil {
		return nil // not registered
	}
	_, err := schtasks("/Delete", "/TN", cfg.Name, "/F")
	return err
}

func startService(cfg *serviceConfig) error {
	_, err := schtasks("/Run", "/TN", cfg.Name)
	return err
}

// stopService asks the supervisor and KyGate to stop with the stop file, so
// that open streams finish and the cache file is flushed, then forces it
// after 45 seconds.
func stopService(cfg *serviceConfig) error {
	pid, alive := supervisorPID(cfg)
	if !alive {
		os.Remove(cfg.path(serviceStopFile))
		return nil
	}
	if err := os.WriteFile(cfg.path(serviceStopFile), nil, 0o600); err != nil {
		return err
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(pid, cfg.Exe) {
			os.Remove(cfg.path(serviceStopFile))
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(pid)).Run()
	os.Remove(cfg.path(serviceStopFile))
	os.Remove(cfg.path(servicePIDFile))
	return nil
}

func serviceState(cfg *serviceConfig) (registered, running bool) {
	_, err := schtasks("/Query", "/TN", cfg.Name)
	_, alive := supervisorPID(cfg)
	return err == nil, alive
}

func supervisorPID(cfg *serviceConfig) (int, bool) {
	b, err := os.ReadFile(cfg.path(servicePIDFile))
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, false
	}
	return pid, processAlive(pid, cfg.Exe)
}

// processAlive checks the PID and the image name, so that a reused PID is
// not taken for KyGate.
func processAlive(pid int, exe string) bool {
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), strings.ToLower(`"`+filepath.Base(exe)+`"`))
}

func hidden(flags uint32) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: flags}
}

// runService is what the scheduled task starts. It hands over to a hidden
// supervisor and exits, so that the console window the task opens closes at
// once.
func runService(cfg *serviceConfig) error {
	if _, alive := supervisorPID(cfg); alive {
		return nil
	}
	start := func(flags uint32) error {
		cmd := exec.Command(cfg.Exe, "service", "supervise", "--data-dir", cfg.DataDir)
		cmd.SysProcAttr = hidden(flags)
		if err := cmd.Start(); err != nil {
			return err
		}
		return cmd.Process.Release()
	}
	// Leave the task's job, so that the supervisor outlives the launcher.
	if err := start(createNoWindow | createNewProcessGroup | createBreakawayFromJob); err != nil {
		return start(createNoWindow | createNewProcessGroup)
	}
	return nil
}

// superviseService runs 'kygate serve' and starts it again when it stops
// without being asked to, waiting longer after each quick failure.
func superviseService(cfg *serviceConfig) error {
	if pid, alive := supervisorPID(cfg); alive && pid != os.Getpid() {
		return nil
	}
	if err := os.WriteFile(cfg.path(servicePIDFile), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		return err
	}
	defer os.Remove(cfg.path(servicePIDFile))
	os.Remove(cfg.path(serviceStopFile))

	slog, err := openLog(cfg.path("service.log"), 1<<20)
	if err != nil {
		return err
	}
	defer slog.Close()
	logf := func(format string, a ...any) {
		fmt.Fprintf(slog, "%s supervisor: %s\n", time.Now().Format("2006/01/02 15:04:05"), fmt.Sprintf(format, a...))
	}
	stopRequested := func() bool { return fileExists(cfg.path(serviceStopFile)) }

	envList := os.Environ()
	for k, v := range cfg.Env {
		if os.Getenv(k) == "" {
			envList = append(envList, k+"="+v)
		}
	}
	args := append(cfg.serveArgs(), "--log-file", cfg.path(logFileName), "--stop-file", cfg.path(serviceStopFile))
	backoff := time.Second
	logf("started (pid %d)", os.Getpid())
	if len(cfg.GuardCmd) > 0 {
		guardDone := make(chan struct{})
		go superviseGuard(cfg, stopRequested, logf, guardDone)
		defer func() { <-guardDone }()
	}
	for {
		if stopRequested() {
			break
		}
		cmd := exec.Command(cfg.Exe, args...)
		cmd.Env = envList
		cmd.SysProcAttr = hidden(createNoWindow)
		began := time.Now()
		err := cmd.Run()
		if stopRequested() {
			break
		}
		if time.Since(began) > 5*time.Minute {
			backoff = time.Second
		}
		logf("KyGate stopped unexpectedly (%v); starting it again in %s", exitReason(err), backoff)
		for end := time.Now().Add(backoff); time.Now().Before(end) && !stopRequested(); {
			time.Sleep(250 * time.Millisecond)
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
	os.Remove(cfg.path(serviceStopFile))
	logf("stopped on request")
	return nil
}

// superviseGuard runs the Guard next to the gateway and starts it again when
// it stops, until a stop is requested. The Guard holds no state, so stopping
// it needs no grace period.
func superviseGuard(cfg *serviceConfig, stopRequested func() bool, logf func(string, ...any), done chan<- struct{}) {
	defer close(done)
	glog, err := openLog(cfg.path("guard.log"), 10<<20)
	if err != nil {
		logf("guard: cannot open guard.log: %v", err)
		return
	}
	defer glog.Close()
	backoff := time.Second
	for !stopRequested() {
		cmd := exec.Command(cfg.GuardCmd[0], cfg.GuardCmd[1:]...)
		cmd.Stdout, cmd.Stderr = glog, glog
		cmd.SysProcAttr = hidden(createNoWindow)
		began := time.Now()
		if err := cmd.Start(); err != nil {
			logf("guard: cannot start %s: %v", cfg.GuardCmd[0], err)
		} else {
			exited := make(chan error, 1)
			go func() { exited <- cmd.Wait() }()
			stopped := false
			for !stopped {
				select {
				case err := <-exited:
					if !stopRequested() {
						logf("guard: stopped unexpectedly (%v); starting it again in %s", exitReason(err), backoff)
					}
					stopped = true
				case <-time.After(250 * time.Millisecond):
					if stopRequested() {
						cmd.Process.Kill()
						<-exited
						stopped = true
					}
				}
			}
		}
		if stopRequested() {
			return
		}
		if time.Since(began) > 5*time.Minute {
			backoff = time.Second
		}
		for end := time.Now().Add(backoff); time.Now().Before(end) && !stopRequested(); {
			time.Sleep(250 * time.Millisecond)
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

func exitReason(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if code := ee.ExitCode(); code != -1 && uint32(code) != 0xFFFFFFFF {
			return fmt.Sprintf("exit code %d", code)
		}
		return "it was ended from outside"
	}
	if err != nil {
		return err.Error()
	}
	return "exit code 0"
}

// persistentEnv reports whether a variable is set for the user account or the
// machine, so that a process started by the system also sees it.
func persistentEnv(name string) bool {
	for _, key := range []string{`HKCU\Environment`, `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`} {
		if exec.Command("reg", "query", key, "/v", name).Run() == nil {
			return true
		}
	}
	return false
}
