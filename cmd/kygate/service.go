package main

// 'kygate service' runs KyGate in the background, so that closing a terminal
// does not stop it. It uses what each system
// already has, and needs no administrator rights:
//
//   - Windows: a scheduled task for the current user, started at logon. It
//     launches a hidden supervisor that runs 'kygate serve' and restarts it
//     if it stops unexpectedly. Logs go to <data-dir>/kygate.log.
//   - Linux: a systemd user unit with Restart=on-failure. Logs go to the
//     journal.
//
// The service runs as the user who installed it, on the same data directory,
// so keys, policy, cache, and events carry over. A provider key that exists
// only in a terminal's environment is not visible in the background, and is
// never written to disk by KyGate (invariant 10): install asks the user to
// store it with 'kygate provider add' instead.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/Kytherion/KyGate/internal/control"
	"github.com/Kytherion/KyGate/internal/detect/guard"
	"github.com/Kytherion/KyGate/internal/policy"
)

// serviceConfig is what 'kygate service install' records in the data directory.
type serviceConfig struct {
	Name          string            `json:"name"`
	Exe           string            `json:"exe"`
	DataDir       string            `json:"data_dir"`
	Listen        string            `json:"listen"`
	ConsoleListen string            `json:"console_listen"`
	Policy        string            `json:"policy,omitempty"`
	Env           map[string]string `json:"env,omitempty"` // settings that are not secrets
	Installed     time.Time         `json:"installed"`
	// GuardCmd runs the Guard next to the gateway: the kygate-guard program
	// and its arguments. Empty: no Guard, or one that runs elsewhere.
	GuardCmd  []string `json:"guard_cmd,omitempty"`
	GuardAddr string   `json:"guard_addr,omitempty"`
}

const (
	serviceFile     = "service.json"
	servicePIDFile  = "service.pid"  // the Windows supervisor
	serviceStopFile = "service.stop" // asks a Windows background KyGate to stop
	logFileName     = "kygate.log"
)

func (s *serviceConfig) serveArgs() []string {
	args := []string{"serve", "--data-dir", s.DataDir, "--listen", s.Listen, "--console-listen", s.ConsoleListen}
	if s.Policy != "" {
		args = append(args, "--policy", s.Policy)
	}
	return args
}

func (s *serviceConfig) path(name string) string { return filepath.Join(s.DataDir, name) }

func loadServiceConfig(dataDir string) (*serviceConfig, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, serviceFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("KyGate is not installed as a service for %s: run 'kygate service install'", dataDir)
	}
	if err != nil {
		return nil, err
	}
	var s serviceConfig
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", serviceFile, err)
	}
	return &s, nil
}

func (s *serviceConfig) save() error {
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(s.path(serviceFile), append(b, '\n'), 0o600)
}

func serviceUsage() error {
	return errors.New(`usage:
  kygate service install [--data-dir DIR] [--listen ADDR] [--console-listen ADDR] [--policy FILE] [--name NAME]
                         [--guard-exe PATH [--guard-args ARGS] [--guard-listen ADDR]]
  kygate service start | stop | restart | status | uninstall   [--data-dir DIR]`)
}

func serviceCmd(args []string) error {
	if len(args) == 0 {
		return serviceUsage()
	}
	if !serviceSupported {
		return errors.New("'kygate service' supports Windows and Linux. On this system, run 'kygate serve' under your own service manager")
	}
	sub, rest := args[0], args[1:]
	if sub == "install" {
		return serviceInstall(rest)
	}
	var c common
	fs := flag.NewFlagSet("service "+sub, flag.ExitOnError)
	c.register(fs)
	parse(fs, rest)
	dataDir, err := filepath.Abs(c.dataDir)
	if err != nil {
		return err
	}
	cfg, err := loadServiceConfig(dataDir)
	if err != nil {
		return err
	}
	switch sub {
	case "start":
		return serviceStart(cfg)
	case "stop":
		if err := stopService(cfg); err != nil {
			return err
		}
		fmt.Println("KyGate stopped. It starts again at your next logon, or with 'kygate service start'.")
		return nil
	case "restart":
		if err := stopService(cfg); err != nil {
			return err
		}
		return serviceStart(cfg)
	case "status":
		return serviceStatus(cfg)
	case "uninstall", "remove":
		return serviceUninstall(cfg)
	case "run":
		// What the system's service manager runs. Not for direct use.
		return runService(cfg)
	case "supervise":
		return superviseService(cfg)
	}
	return serviceUsage()
}

func serviceInstall(args []string) error {
	var c common
	fs := flag.NewFlagSet("service install", flag.ExitOnError)
	c.register(fs)
	listen := fs.String("listen", env("KYGATE_LISTEN", "127.0.0.1:4000"), "model API address")
	consoleListen := fs.String("console-listen", env("KYGATE_CONSOLE_LISTEN", "127.0.0.1:4001"), "console address")
	name := fs.String("name", defaultServiceName, "service name")
	guardExe := fs.String("guard-exe", "", "run the Guard too: the kygate-guard program, for example guard/.venv/Scripts/kygate-guard.exe")
	guardArgs := fs.String("guard-args", "", "arguments for the Guard, for example \"--recognizers C:\\kygate\\names.json\"")
	guardListen := fs.String("guard-listen", "127.0.0.1:4002", "address of the Guard that the service runs")
	parse(fs, args)

	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return fmt.Errorf("cannot find the kygate binary: %w", err)
	}
	if strings.Contains(exe, "go-build") {
		return errors.New("this kygate was started with 'go run', whose binary is deleted afterwards. Build it first ('go build -o kygate ./cmd/kygate') and run that binary")
	}
	dataDir, err := filepath.Abs(c.dataDir)
	if err != nil {
		return err
	}
	cfg := &serviceConfig{Name: *name, Exe: exe, DataDir: dataDir, Listen: *listen, ConsoleListen: *consoleListen, Installed: time.Now().UTC()}
	if c.policy != "" {
		if cfg.Policy, err = filepath.Abs(c.policy); err != nil {
			return err
		}
	}

	// The first start happens here, in the terminal, so that the virtual key
	// and the admin token are shown once on screen and never written to a log.
	ctx := context.Background()
	db, err := c.openDB()
	if err != nil {
		return err
	}
	setup, err := control.Setup(ctx, db, dataDir, cfg.policyPath())
	if err != nil {
		db.Close()
		return err
	}
	stored, err := db.ListCredentials(ctx)
	db.Close()
	if err != nil {
		return err
	}
	if setup.VirtualKey != "" || setup.AdminToken != "" {
		fmt.Println("\nFirst start. These secrets are shown once and cannot be shown again; store them now.")
		tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		if setup.VirtualKey != "" {
			fmt.Fprintf(tw, "  Virtual key\t%s\t(use it in place of your provider key)\n", setup.VirtualKey)
		}
		if setup.AdminToken != "" {
			fmt.Fprintf(tw, "  Admin token\t%s\t(opens the console)\n", setup.AdminToken)
		}
		tw.Flush()
		fmt.Println()
	}
	if os.Getenv(control.MasterKeyEnv) != "" && !persistentEnv(control.MasterKeyEnv) {
		return fmt.Errorf("the master key comes from %s in this terminal only, so KyGate in the background could not read its own data. Set it for your user account, or use the key file %s",
			control.MasterKeyEnv, filepath.Join(dataDir, control.MasterKeyFile))
	}

	// Provider keys that live only in this terminal's environment.
	storedNames := map[string]bool{}
	for _, s := range stored {
		storedNames[s.Name] = true
	}
	var missing []string
	for _, v := range secretEnv() {
		if storedNames[connectionName(v)] || persistentEnv(v) {
			continue
		}
		missing = append(missing, v)
	}
	if len(missing) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "%s is set only in this terminal, so KyGate in the background would not see it, and KyGate never writes a key from the environment to disk.\n", strings.Join(missing, ", "))
		b.WriteString("Store it once, encrypted under the master key, then run 'kygate service install' again:\n")
		for _, v := range missing {
			fmt.Fprintf(&b, "  %s\n", storeCommand(v, dataDir))
		}
		return errors.New(strings.TrimRight(b.String(), "\n"))
	}
	if len(stored) == 0 && len(secretEnv()) == 0 && len(nonSecretEnv()) == 0 {
		fmt.Println("Warning: no provider key is configured. KyGate will run, and refuse model requests until you add one with 'kygate provider add'.")
	}
	cfg.Env = nonSecretEnv()
	if *guardExe != "" {
		ge, err := filepath.Abs(*guardExe)
		if err != nil {
			return err
		}
		if !fileExists(ge) {
			return fmt.Errorf("--guard-exe: %s does not exist. Install the Guard first: pip install ./guard, in a virtual environment", ge)
		}
		ga, err := splitArgs(*guardArgs)
		if err != nil {
			return fmt.Errorf("--guard-args: %w", err)
		}
		cfg.GuardCmd = append([]string{ge, "--listen", *guardListen}, ga...)
		cfg.GuardAddr = *guardListen
		if cfg.Env == nil {
			cfg.Env = map[string]string{}
		}
		cfg.Env["KYGATE_GUARD"] = *guardListen
	} else if a := cfg.Env["KYGATE_GUARD"]; a != "" {
		cfg.GuardAddr = a // a Guard that runs elsewhere, such as in a container
	}

	// Replacing an earlier installation: stop it first.
	if old, err := loadServiceConfig(dataDir); err == nil {
		stopService(old)
		if old.Name != cfg.Name {
			unregisterService(old)
		}
	}
	if err := cfg.save(); err != nil {
		return err
	}
	if err := registerService(cfg); err != nil {
		return fmt.Errorf("could not register the service: %w", err)
	}
	fmt.Printf("Installed: %s.\n", serviceKind())
	if answers(cfg.Listen) {
		fmt.Printf("Not started yet: something already answers on %s, probably KyGate in a terminal. Stop it (Ctrl+C), then run 'kygate service start'.\n", cfg.Listen)
		return nil
	}
	return serviceStart(cfg)
}

func serviceStart(cfg *serviceConfig) error {
	if answers(cfg.Listen) {
		return fmt.Errorf("something already answers on %s, probably KyGate in a terminal. Stop it (Ctrl+C) first", cfg.Listen)
	}
	if err := startService(cfg); err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if answers(cfg.Listen) {
			return serviceStatus(cfg)
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("KyGate did not start within 30 seconds; see %s", logHint(cfg))
}

func serviceStatus(cfg *serviceConfig) error {
	registered, running := serviceState(cfg)
	state := "stopped"
	switch {
	case !registered:
		state = "not registered with the system (run 'kygate service install' again)"
	case running || answers(cfg.Listen):
		state = "running, " + readiness(cfg.Listen)
	}
	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "KyGate service %q\t%s\n", cfg.Name, serviceKind())
	fmt.Fprintf(tw, "  State\t%s\n", state)
	fmt.Fprintf(tw, "  Model API\thttp://%s/v1\t(OpenAI SDKs), http://%s (Anthropic SDKs)\n", displayAddr(cfg.Listen), displayAddr(cfg.Listen))
	fmt.Fprintf(tw, "  Console\thttp://%s\n", displayAddr(cfg.ConsoleListen))
	switch {
	case cfg.GuardAddr == "":
		fmt.Fprintf(tw, "  Guard\tnot configured\n")
	case tcpAnswers(cfg.GuardAddr):
		fmt.Fprintf(tw, "  Guard\t%s, answering%s%s\n", cfg.GuardAddr, guardRunBy(cfg), guardLevels(cfg))
	default:
		fmt.Fprintf(tw, "  Guard\t%s, not answering%s\n", cfg.GuardAddr, guardRunBy(cfg))
	}
	fmt.Fprintf(tw, "  Data directory\t%s\n", cfg.DataDir)
	fmt.Fprintf(tw, "  Logs\t%s\n", logHint(cfg))
	return tw.Flush()
}

func serviceUninstall(cfg *serviceConfig) error {
	stopService(cfg)
	if err := unregisterService(cfg); err != nil {
		return err
	}
	for _, f := range []string{serviceFile, servicePIDFile, serviceStopFile} {
		os.Remove(cfg.path(f))
	}
	fmt.Printf("Uninstalled. KyGate no longer starts on its own; the data in %s is kept.\n", cfg.DataDir)
	return nil
}

func (s *serviceConfig) policyPath() string {
	if s.Policy != "" {
		return s.Policy
	}
	return filepath.Join(s.DataDir, control.PolicyFile)
}

// guardLevels asks the Guard which level finds each data type the policy
// needs it for.
func guardLevels(cfg *serviceConfig) string {
	p, err := policy.Load(cfg.policyPath())
	if err != nil {
		return ""
	}
	if !p.NeedsGuard() {
		return "; not used: the policy names none of the types it finds (kygate policy enable --list)"
	}
	gd, err := guard.Dial(cfg.GuardAddr)
	if err != nil {
		return ""
	}
	defer gd.Close()
	if _, err := gd.Info(context.Background()); err != nil {
		return ""
	}
	return "; levels: " + levelsLine(p, gd.State())
}

func guardRunBy(cfg *serviceConfig) string {
	if len(cfg.GuardCmd) > 0 {
		return " (run by the service)"
	}
	return " (runs elsewhere)"
}

// tcpAnswers reports whether something accepts connections on addr.
func tcpAnswers(addr string) bool {
	c, err := net.DialTimeout("tcp", dialAddr(addr), time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// splitArgs splits a command line on spaces, keeping double-quoted parts
// together, so a path with spaces can be passed in --guard-args.
func splitArgs(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	in, has := false, false
	for _, r := range s {
		switch {
		case r == '"':
			in, has = !in, true
		case r == ' ' && !in:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if in {
		return nil, errors.New("a quote is not closed")
	}
	if has {
		out = append(out, cur.String())
	}
	return out, nil
}

// answers reports whether an HTTP server answers /healthz on addr.
func answers(addr string) bool {
	client := http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + dialAddr(addr) + "/healthz")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func readiness(addr string) string {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + dialAddr(addr) + "/readyz")
	if err != nil {
		return "not answering"
	}
	defer resp.Body.Close()
	var body struct {
		Status      string `json:"status"`
		Reason      string `json:"reason"`
		Connections int    `json:"connections"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode == 200 {
		return fmt.Sprintf("ready (%d provider connections)", body.Connections)
	}
	return "not ready: " + body.Reason
}

// dialAddr turns a listen address such as ":4000" into one a client can dial.
func dialAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// secretEnv lists the provider-key variables set in this environment.
func secretEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if strings.TrimSpace(v) == "" {
			continue
		}
		if k == "OPENAI_API_KEY" || strings.HasPrefix(k, "OPENAI_API_KEY_") || k == "ANTHROPIC_API_KEY" ||
			strings.HasPrefix(k, "ANTHROPIC_API_KEY_") || (strings.HasPrefix(k, "KYGATE_LOCAL_") && strings.HasSuffix(k, "_KEY")) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// nonSecretEnv returns the settings the service should keep: local model
// server addresses, provider base URLs, the catalog path, and the
// OpenTelemetry settings. Never a key, never OTLP headers.
func nonSecretEnv() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if strings.TrimSpace(v) == "" {
			continue
		}
		switch {
		case strings.HasPrefix(k, "KYGATE_LOCAL_") && !strings.HasSuffix(k, "_KEY"),
			k == "OPENAI_BASE_URL", k == "ANTHROPIC_BASE_URL", k == "KYGATE_CATALOG", k == "KYGATE_GUARD",
			// OpenTelemetry settings, except headers, which can carry a token.
			strings.HasPrefix(k, "OTEL_") && !strings.Contains(k, "HEADERS"):
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// connectionName is the connection a provider-key variable creates, the same
// name 'kygate provider add --name' would store it under.
func connectionName(v string) string {
	switch {
	case v == "OPENAI_API_KEY":
		return "openai"
	case v == "ANTHROPIC_API_KEY":
		return "anthropic"
	case strings.HasPrefix(v, "OPENAI_API_KEY_"):
		return "openai-" + strings.ToLower(strings.TrimPrefix(v, "OPENAI_API_KEY_"))
	case strings.HasPrefix(v, "ANTHROPIC_API_KEY_"):
		return "anthropic-" + strings.ToLower(strings.TrimPrefix(v, "ANTHROPIC_API_KEY_"))
	case strings.HasPrefix(v, "KYGATE_LOCAL_"):
		// The same name provider.FromEnv gives the connection.
		return "local-" + strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(v, "KYGATE_LOCAL_"), "_KEY"))
	}
	return strings.ToLower(v)
}

func storeCommand(v, dataDir string) string {
	name := connectionName(v)
	prov := "local"
	switch {
	case strings.HasPrefix(v, "OPENAI_"):
		prov = "openai"
	case strings.HasPrefix(v, "ANTHROPIC_"):
		prov = "anthropic"
	}
	extra := ""
	if prov == "local" {
		extra = " --base-url $KYGATE_LOCAL_" + strings.ToUpper(strings.TrimPrefix(name, "local-"))
	}
	dd := ""
	if dataDir != defaultDataDir() {
		dd = " --data-dir '" + dataDir + "'"
	}
	cmd := fmt.Sprintf("kygate provider add --name %s --provider %s%s%s", name, prov, extra, dd)
	if runtime.GOOS == "windows" {
		ps := strings.Replace(cmd, "$KYGATE_LOCAL_", "$env:KYGATE_LOCAL_", 1)
		return fmt.Sprintf("Git Bash:   printf %%s \"$%s\" | %s\n  PowerShell: $env:%s | %s", v, cmd, v, ps)
	}
	return fmt.Sprintf("printf %%s \"$%s\" | %s", v, cmd)
}

// ---- background logging ----

// rotatingLog is the log file of a background KyGate: it keeps one previous
// file, so the logs never take more than twice the limit.
type rotatingLog struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

func openLog(path string, max int64) (*rotatingLog, error) {
	l := &rotatingLog{path: path, max: max}
	return l, l.open()
}

func (l *rotatingLog) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.size = f, st.Size()
	return nil
}

func (l *rotatingLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return 0, os.ErrClosed
	}
	if l.size > 0 && l.size+int64(len(p)) > l.max {
		l.f.Close()
		os.Remove(l.path + ".1")
		os.Rename(l.path, l.path+".1")
		if err := l.open(); err != nil {
			l.f = nil
			return 0, err
		}
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

func (l *rotatingLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// watchStopFile stops KyGate gracefully when the file appears: the way
// 'kygate service stop' asks a background KyGate on Windows to finish its
// open streams, flush the cache file, and deliver its events.
func watchStopFile(ctx context.Context, path string, stop context.CancelFunc) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if fileExists(path) {
				stop()
				return
			}
		}
	}
}
