// Command kygate is the single KyGate binary: the gateway, the control role
// with its console, and the command-line tools.
//
//	kygate serve                         start KyGate
//	kygate key create|list|revoke|move   manage virtual keys
//	kygate team|project create|list|delete   the hierarchy
//	kygate provider add|list|remove      manage stored provider keys
//	kygate admin-token reset             replace the console admin token
//	kygate policy check [file]           validate a policy file
//	kygate service install|start|stop|status|uninstall
//	                                     run KyGate in the background
//	kygate version
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Kytherion/KyGate/internal/cache"
	"github.com/Kytherion/KyGate/internal/control"
	"github.com/Kytherion/KyGate/internal/detect/guard"
	"github.com/Kytherion/KyGate/internal/edition"
	"github.com/Kytherion/KyGate/internal/events"
	"github.com/Kytherion/KyGate/internal/identity"
	"github.com/Kytherion/KyGate/internal/limits"
	"github.com/Kytherion/KyGate/internal/mask"
	"github.com/Kytherion/KyGate/internal/pipeline"
	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/provider"
	"github.com/Kytherion/KyGate/internal/provider/openaicompat"
	"github.com/Kytherion/KyGate/internal/router"
	"github.com/Kytherion/KyGate/internal/store"
	"github.com/Kytherion/KyGate/internal/store/postgres"
	"github.com/Kytherion/KyGate/internal/store/sqlite"
	"github.com/Kytherion/KyGate/internal/store/valkey"
	"github.com/Kytherion/KyGate/internal/telemetry"
	"github.com/Kytherion/KyGate/web"
)

// Version of this build.
var Version = "0.1.0"

// editionTitle is the edition's name for people: Community or Enterprise.
func editionTitle() string {
	if edition.Enterprise {
		return "Enterprise"
	}
	return "Community"
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "serve":
		err = serve(args)
	case "key", "keys":
		err = keyCmd(args)
	case "team", "teams":
		err = teamCmd(args)
	case "user", "users":
		err = userCmd(args)
	case "sso":
		err = ssoCmd(args)
	case "scim":
		err = scimCmd(args)
	case "store":
		err = storeCmd(args)
	case "purge":
		err = purgeCmd(args)
	case "audit":
		err = auditCmd(args)
	case "master-key":
		err = masterKeyCmd(args)
	case "project", "projects":
		err = projectCmd(args)
	case "provider", "providers":
		err = providerCmd(args)
	case "admin-token":
		err = adminTokenCmd(args)
	case "policy":
		err = policyCmd(args)
	case "service":
		err = serviceCmd(args)
	case "version", "--version", "-v":
		fmt.Println("kygate", Version, edition.Name)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kygate:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `KyGate: a self-hosted AI gateway that protects and optimizes model calls.

Usage:
  kygate serve [--data-dir DIR] [--listen ADDR] [--console-listen ADDR] [--policy FILE] [--guard ADDR] [--guard-timeout 5s]
               [--role all|gateway|control] [--database-url URL] [--counters-url URL] [--cache-url URL]   (Team profile)
  kygate key create NAME [--project P] | key list | key revoke NAME|ID | key move NAME --project P
  kygate key user-secret NAME [--remove]     the key's signing secret for user tokens (X-KyGate-User), shown once
  kygate key require-user NAME [--off]       refuse requests on this key that name no person
  kygate key user-token NAME --user ID [--ttl 1h]   sign a user token with the key's secret, for tests and scripts
  kygate team create NAME | team list | team delete NAME
  kygate project create NAME [--team T] | project list | project delete NAME
  kygate provider add --name NAME --provider openai|anthropic|local [--base-url URL] [--region R]
  kygate provider region NAME [REGION]  a stored connection's region (no REGION clears it); see data.regions
  kygate provider list | provider remove NAME
  kygate admin-token reset
  kygate policy check [FILE] [--guard ADDR]
  kygate policy show --key NAME          the key's effective policy: the organization's merged with its team's, project's, and key's files
  kygate policy enable TYPE... [--action alert|mask|redact|block|local_only] [--require-model] [--yes]
  kygate policy enable PROMPT_INJECTION [--action alert|block|allow] [--yes]
  kygate policy enable --list [--guard ADDR]
  kygate service install [--data-dir DIR] [--listen ADDR] [--console-listen ADDR] [--policy FILE]
  kygate service start | stop | restart | status | uninstall   [--data-dir DIR]
  kygate store copy --to postgres://... [--data-dir DIR]   copy a Solo installation into PostgreSQL (Team)
  kygate purge events [--key K] [--team T] [--project P] [--user ID] [--from DATE] [--to DATE] [--payloads-only] [--yes]
  kygate purge cache --key K | --tag T | --all [--cache-url URL] [--yes]
  kygate version

Enterprise edition only:
  kygate user add EMAIL --role admin|security|finance|team_lead|viewer [--team T] | user list | user remove EMAIL
  kygate sso secret                      store the single sign-on client secret, sealed (reads standard input)
  kygate scim token | scim revoke | scim status   SCIM provisioning at /scim/v2 on the console's port
  kygate audit verify [--json] | audit status   the tamper-evident audit ledger (exit 1 when verification finds problems)
  kygate master-key status | wrap --kms URI [--remove-plain] | rewrap --kms URI | new --kms URI
                                         keep the master key wrapped by Vault or a cloud KMS

Provider keys from the environment (read at start):
  OPENAI_API_KEY, OPENAI_API_KEY_<SUFFIX>, OPENAI_BASE_URL
  ANTHROPIC_API_KEY, ANTHROPIC_API_KEY_<SUFFIX>, ANTHROPIC_BASE_URL
  KYGATE_LOCAL_<NAME>=<url>, KYGATE_LOCAL_<NAME>_KEY   local OpenAI-compatible model servers

Settings from the environment:
  KYGATE_DATA_DIR, KYGATE_LISTEN, KYGATE_CONSOLE_LISTEN, KYGATE_POLICY,
  KYGATE_CATALOG, KYGATE_MASTER_KEY, KYGATE_GUARD, KYGATE_GUARD_TIMEOUT,
  KYGATE_ROLE, KYGATE_DATABASE_URL, KYGATE_COUNTERS_URL, KYGATE_CACHE_URL,
  KYGATE_KMS, KYGATE_MASTER_KEY_WRAPPED   the master key in a key-management service (Enterprise)
  KYGATE_GUARD_TLS_CA, KYGATE_GUARD_TLS_CERT, KYGATE_GUARD_TLS_KEY   TLS and mutual TLS to the Guard

Traces (off unless an endpoint is set): the standard OpenTelemetry variables
  OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_HEADERS, OTEL_TRACES_SAMPLER,
  OTEL_SERVICE_NAME
`)
}

func envDuration(name string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

func env(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func defaultDataDir() string {
	if v := os.Getenv("KYGATE_DATA_DIR"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".kygate"
	}
	return filepath.Join(home, ".kygate")
}

type common struct {
	dataDir     string
	policy      string
	databaseURL string
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.dataDir, "data-dir", defaultDataDir(), "data directory")
	fs.StringVar(&c.databaseURL, "database-url", env("KYGATE_DATABASE_URL", ""), "PostgreSQL URL (Team profile); without it, SQLite in the data directory")
	fs.StringVar(&c.policy, "policy", env("KYGATE_POLICY", ""), "policy file (default: policy.yaml in the data directory)")
}

// cliPolicyDocs opens the policies for a command: files in Solo, or the
// database (opened here, closed by the returned function).
func (c *common) cliPolicyDocs() (policy.Docs, func(), error) {
	if c.databaseURL == "" {
		return policy.FileDocs{Path: c.policyPath()}, func() {}, nil
	}
	db, err := c.openExisting()
	if err != nil {
		return nil, nil, err
	}
	return c.policyDocs(db), func() { db.Close() }, nil
}

// policyDocs is where this installation's policies live: files in Solo, the
// database with PostgreSQL.
func (c *common) policyDocs(db store.Database) policy.Docs {
	if c.databaseURL != "" {
		return control.DBDocs{DB: db, BasePath: c.policyPath()}
	}
	return policy.FileDocs{Path: c.policyPath()}
}

func (c *common) policyPath() string {
	if c.policy != "" {
		return c.policy
	}
	return filepath.Join(c.dataDir, control.PolicyFile)
}

func (c *common) openDB() (store.Database, error) {
	if err := os.MkdirAll(c.dataDir, 0o700); err != nil {
		return nil, err
	}
	if c.databaseURL != "" {
		return postgres.Open(c.databaseURL)
	}
	return sqlite.Open(filepath.Join(c.dataDir, control.DBFile))
}

// openExisting opens the database of an installation that 'kygate serve' has
// already set up. Management commands never create a data directory.
func (c *common) openExisting() (store.Database, error) {
	if c.databaseURL != "" {
		return postgres.Open(c.databaseURL)
	}
	if !fileExists(filepath.Join(c.dataDir, control.DBFile)) {
		return nil, fmt.Errorf("no KyGate installation in %s: run 'kygate serve' once, or pass --data-dir", c.dataDir)
	}
	return sqlite.Open(filepath.Join(c.dataDir, control.DBFile))
}

// parse accepts flags before and after positional arguments, so that
// "kygate key create bob --data-dir DIR" works as written.
func parse(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			return pos
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// ---------------- serve ----------------

func serve(args []string) error {
	var c common
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	c.register(fs)
	listen := fs.String("listen", env("KYGATE_LISTEN", "127.0.0.1:4000"), "model API address")
	consoleListen := fs.String("console-listen", env("KYGATE_CONSOLE_LISTEN", "127.0.0.1:4001"), "console address")
	role := fs.String("role", env("KYGATE_ROLE", "all"), "all | gateway (the model API only) | control (the console, the admin API, and retention)")
	countersURL := fs.String("counters-url", env("KYGATE_COUNTERS_URL", ""), "Valkey URL for budget and rate counters, shared by gateways (Team); it must never evict")
	cacheURL := fs.String("cache-url", env("KYGATE_CACHE_URL", ""), "Valkey URL for the exact cache, shared by gateways (Team); it should evict least recently used entries")
	maxConc := fs.Int("max-concurrency", 1024, "requests in flight before new ones are refused")
	guardAddr := fs.String("guard", env("KYGATE_GUARD", ""), "address of the Guard, the ML service, such as 127.0.0.1:4002 (optional)")
	guardTimeout := fs.Duration("guard-timeout", envDuration("KYGATE_GUARD_TIMEOUT", 5*time.Second), "deadline of one call to the Guard; a slower answer counts as the Guard being unavailable")
	logFile := fs.String("log-file", "", "write logs to this file instead of the terminal (rotated at 10 MB); used by 'kygate service'")
	stopFile := fs.String("stop-file", "", "stop gracefully when this file appears; used by 'kygate service' on Windows")
	fs.Parse(args)
	switch *role {
	case "all", "gateway", "control":
	default:
		return fmt.Errorf("--role must be all, gateway, or control, not %q", *role)
	}
	gatewayRole, controlRole := *role != "control", *role != "gateway"

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// In the background there is no terminal: logs go to a file, and secrets
	// never do (printBanner).
	out := io.Writer(os.Stdout)
	if *logFile != "" {
		lw, err := openLog(*logFile, 10<<20)
		if err != nil {
			return fmt.Errorf("log file: %w", err)
		}
		defer lw.Close()
		log.SetOutput(lw)
		out = lw
	}
	if *stopFile != "" {
		os.Remove(*stopFile)
		go watchStopFile(ctx, *stopFile, cancel)
	}

	db, err := c.openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	// With PostgreSQL, policies live in the database, so that every gateway
	// reads the same version without a shared volume.
	// With PostgreSQL, several processes share one installation: each must
	// get the same master key from its environment. A key made locally by
	// one process would lock the others out.
	if c.databaseURL != "" && os.Getenv(control.MasterKeyEnv) == "" && os.Getenv(control.MasterKeyWrappedEnv) == "" &&
		os.Getenv(control.KMSEnv) == "" && !fileExists(filepath.Join(c.dataDir, control.MasterKeyFile)) &&
		!fileExists(filepath.Join(c.dataDir, control.MasterKeyWrappedFile)) {
		return fmt.Errorf("with PostgreSQL, every KyGate process needs the same master key: set %s (32 bytes, base64), or %s (made with 'kygate master-key new --kms URI')",
			control.MasterKeyEnv, control.MasterKeyWrappedEnv)
	}
	docs := c.policyDocs(db)
	_, inDB := docs.(control.DBDocs)
	if !controlRole {
		// The control process creates the organization and its policies at
		// the first start; a gateway waits for them.
		for i := 0; ; i++ {
			if _, err := db.Meta(ctx, "org_id"); err == nil {
				if _, err := docs.Get(policy.OrgDoc); err == nil {
					break
				}
			}
			if i == 120 || ctx.Err() != nil {
				return errors.New("this gateway found no installation in the database: start the control process (--role=control) first")
			}
			time.Sleep(time.Second)
		}
	}
	setupPolicy := c.policyPath()
	if inDB {
		setupPolicy = ""
	}
	setup, err := control.Setup(ctx, db, c.dataDir, setupPolicy)
	if err != nil {
		return err
	}
	if inDB && controlRole {
		seeded, err := control.SeedPolicies(ctx, db, c.policyPath())
		if err != nil {
			return err
		}
		switch {
		case seeded == "starter":
			setup.PolicyCreated = true
		case seeded != "":
			log.Printf("policies: %s", seeded)
		}
	}
	holder, err := policy.NewHolderFrom(docs)
	if err != nil {
		return fmt.Errorf("%w\n(fix the policy, or check it with 'kygate policy check')", err)
	}
	pol := holder.Current()

	catalogPath := env("KYGATE_CATALOG", "")
	if catalogPath == "" {
		if p := filepath.Join(c.dataDir, control.CatalogFile); fileExists(p) {
			catalogPath = p
		}
	}
	catalog, err := router.LoadCatalog(catalogPath)
	if err != nil {
		return err
	}

	selfAddrs := []string{*listen, *consoleListen}
	registry := provider.NewRegistry()
	conns, warnings, err := control.Connections(ctx, db, setup.MasterKey, setup.OrgID, selfAddrs)
	if err != nil {
		return err
	}
	registry.Replace(conns)

	keys := identity.NewResolver()
	keys.Unseal = control.UserSecretOpener(setup.MasterKey, setup.OrgID)
	if err := keys.LoadFrom(ctx, db); err != nil {
		return err
	}
	// User tokens from the company's identity provider (AC-3), as the
	// organization's policy names it.
	idp := identity.NewIdP(log.Printf)
	configureIdP := func(p *policy.Policy) {
		u := p.Identity.UserTokens
		idp.Configure(u.Issuer, u.Audiences, u.UserClaim)
	}
	configureIdP(pol)

	spool, err := events.OpenSpool(filepath.Join(c.dataDir, control.SpoolDir), 512<<20)
	if err != nil {
		return err
	}
	defer spool.Close()
	spool.Logf = log.Printf

	metrics := telemetry.Default
	// Traces are off unless an OTLP endpoint is configured (OTEL_EXPORTER_OTLP_ENDPOINT).
	stopTracing, terr := telemetry.SetupTracing(ctx, Version)
	if terr != nil {
		log.Printf("traces: off, the OTLP exporter could not start: %v", terr)
	}
	defer func() {
		flush, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stopTracing(flush)
	}()
	exact := cache.New(int64(pol.Cache.Exact.MaxSizeMB) << 20)
	cachePath := filepath.Join(c.dataDir, control.CacheFile)
	if *cacheURL != "" {
		cachePath = "Valkey (" + redactURL(*cacheURL) + ")"
		exact.UseDisk(func() (store.CacheStore, error) { return valkey.OpenCache(*cacheURL) }, log.Printf)
	} else {
		exact.UseDisk(func() (store.CacheStore, error) { return sqlite.OpenCache(cachePath) }, log.Printf)
	}
	// A damaged or unreadable cache file never stops a start: the cache runs
	// in memory only (architecture §4.5, §5.4).
	cacheErr := exact.Configure(cacheSettings(pol))
	defer exact.Close()
	// The semantic cache keeps its entries in the same file, or in memory
	// when the policy keeps the cache in memory only.
	semanticStore := exact.SemanticStore
	if ss, ok := db.(store.SemanticStore); ok && c.databaseURL != "" {
		// Team: the semantic entries live in PostgreSQL, sealed as in Solo.
		semanticStore = func() store.SemanticStore { return ss }
	}
	semantic := cache.NewSemantic(semanticStore, log.Printf)

	// The Guard is optional. A policy that names an ML data type needs it;
	// while it does not answer, on_guard_unavailable applies.
	var gd *guard.Client
	if *guardAddr != "" {
		if gd, err = guard.Dial(*guardAddr); err != nil {
			return fmt.Errorf("guard: %w", err)
		}
		gd.Timeout = *guardTimeout
		defer gd.Close()
		gd.Info(ctx)
	}
	memo := guard.NewMemo(store.DeriveKey(setup.MasterKey, "memo", setup.OrgID), 100000)
	limit := limits.NewConcurrency(*maxConc)
	metrics.Gauge("kygate_requests_in_flight", func() float64 { return float64(limit.InFlight()) })
	metrics.Gauge("kygate_spool_bytes", func() float64 { return float64(spool.Bytes()) })
	metrics.Gauge("kygate_cache_entries", func() float64 { return float64(exact.Stats().Entries) })
	metrics.Gauge("kygate_cache_bytes", func() float64 { return float64(exact.Stats().Bytes) })
	metrics.Gauge("kygate_cache_disk_entries", func() float64 { return float64(exact.Stats().Disk.Entries) })
	metrics.Gauge("kygate_cache_disk_bytes", func() float64 { return float64(exact.Stats().Disk.Bytes) })
	metrics.Gauge("kygate_cache_disk_hits", func() float64 { return float64(exact.Stats().Disk.Hits) })
	metrics.Gauge("kygate_cache_disk_errors", func() float64 { return float64(exact.Stats().Disk.Errors) })
	metrics.Gauge("kygate_rehydration_unknown_placeholders", func() float64 { return float64(mask.UnknownPlaceholders.Load()) })
	metrics.Gauge("kygate_events_dropped", func() float64 { return float64(spool.Dropped()) })

	client := provider.NewClient(registry)
	// Budget counters live in memory in Solo, rebuilt from the event ledger:
	// this month's and today's spend per key (OP-5).
	var counters store.Counters = limits.NewMemoryCounters()
	var rates limits.Limiter = limits.NewRates()
	var fc *limits.FallbackCounters
	var shared *limits.SharedRates
	if *countersURL != "" {
		vc, err := valkey.OpenCounters(*countersURL)
		if err != nil {
			return fmt.Errorf("counters: %w", err)
		}
		defer vc.Close()
		shared = &limits.SharedRates{C: vc, Local: limits.NewRates()}
		metrics.Gauge("kygate_rate_limit_local_fallbacks", func() float64 { return float64(shared.Fallbacks.Load()) })
		// Budgets go on from this gateway's last known figures when Valkey
		// cannot be reached, and catch up when it answers (architecture §5.4).
		fc = limits.NewFallbackCounters(vc)
		metrics.Gauge("kygate_budget_counters_degraded", func() float64 { return float64(fc.Degraded.Load()) })
		counters, rates = fc, shared
	}
	budgets := &limits.Budgets{C: counters}
	if err := budgets.Rebuild(context.Background(), db, time.Now(), hierarchyPlace(ctx, db)); err != nil {
		log.Printf("budgets: could not rebuild the counters from the events: %v", err)
	}
	gw := &pipeline.Gateway{
		Policies: holder, Keys: keys, Registry: registry, Client: client, Catalog: catalog,
		Cache: exact, Semantic: semantic, NearMiss: cache.NewNearMiss(), Router: router.NewRouter(catalog), Budgets: budgets, Rates: rates, IdP: idp, Flights: cache.NewFlights(), Guard: gd, Memo: memo, Spool: spool, Limit: limit, MasterKey: setup.MasterKey, Metrics: metrics,
		Logf: log.Printf, Version: Version, Feedback: db,
	}
	purger := &control.Purger{DB: db, Cache: exact, Semantic: semantic, MasterKey: setup.MasterKey, OrgID: setup.OrgID, Logf: log.Printf}
	if err := purger.Start(ctx); err != nil {
		return fmt.Errorf("cache purges: %w", err)
	}
	// The audit ledger and SIEM export (GV-3): the control process seals and
	// exports; gateways only sign their events.
	var auditor *control.Audit
	if controlRole {
		if auditor, err = control.NewAudit(db, setup.MasterKey, setup.OrgID, c.dataDir, log.Printf); err != nil {
			return err
		}
	}
	static, _ := fsSub(web.Static, "static")
	modelAPI := "http://" + displayAddr(*listen)
	// Single sign-on, when <data-dir>/sso.yaml exists (AC-3).
	sso, err := control.LoadSSO(c.dataDir, func() (string, error) {
		return control.StoredSSOSecret(ctx, db, setup.MasterKey, setup.OrgID)
	})
	if err != nil {
		return fmt.Errorf("single sign-on: %w", err)
	}
	console := &control.Console{
		Config: db, Events: db, Registry: registry, Policies: holder, Keys: keys, Cache: exact, Semantic: semantic, Guard: gd, Memo: memo, Spool: spool,
		Metrics: metrics, MasterKey: setup.MasterKey, OrgID: setup.OrgID, Version: Version, Started: time.Now(),
		Static: static, ModelAPI: modelAPI, Budgets: budgets, Logf: log.Printf, SSO: sso, Purger: purger, Audit: auditor,
		SCIM: db,
	}

	var gwLn, coLn net.Listener
	if gatewayRole {
		if gwLn, err = net.Listen("tcp", *listen); err != nil {
			return fmt.Errorf("model API: %w", err)
		}
	}
	if controlRole {
		if coLn, err = net.Listen("tcp", *consoleListen); err != nil {
			return fmt.Errorf("console: %w", err)
		}
	}

	profile, bannerListen, bannerConsole := "Solo", *listen, *consoleListen
	if c.databaseURL != "" {
		profile = "Team"
	}
	if !gatewayRole {
		bannerListen = ""
	}
	if !controlRole {
		bannerConsole = ""
	}
	printBanner(out, *logFile != "", c.dataDir, bannerListen, bannerConsole, profile, *role, setup, pol, registry, warnings, keys.Count(), cacheLine(pol, cachePath, cacheErr), semanticLine(pol, registry), guardLine(pol, gd), usersLine(ctx, db, pol))

	holder.OnLoad = func(p *policy.Policy) {
		configureIdP(p)
		if err := exact.Configure(cacheSettings(p)); err != nil {
			log.Printf("%s", cacheLine(p, cachePath, err))
		}
		log.Printf("semantic cache: %s", semanticLine(p, registry))
		log.Printf("policy reloaded: version %s, mode %s", p.Version, p.Mode)
		for _, w := range p.Warnings {
			log.Printf("policy: %s", w)
		}
	}
	holder.OnError = func(err error) { log.Printf("policy edit rejected, the previous version stays in force: %v", err) }
	stop := make(chan struct{})
	go holder.Watch(stop, 2*time.Second)
	go spool.Run(ctx, db, time.Second)
	// The fleet view's heartbeat: this process's own view, every 10 s,
	// in the background.
	heartbeatDone := make(chan struct{})
	hb := &control.Heartbeat{DB: db, Role: *role, Version: Version, Forget: controlRole, Logf: log.Printf, Collect: func() control.InstanceState {
		st := control.InstanceState{Gateway: gatewayRole, Control: controlRole, Profile: profile, InFlight: limit.InFlight(), Spool: spool.Health(),
			Guard: control.SummarizeGuard(gd), Counters: "memory", Cache: "memory"}
		if fc != nil {
			st.Counters, st.Degraded, st.Fallbacks = "valkey", fc.Degraded.Load(), shared.Fallbacks.Load()
		}
		ds := exact.Stats().Disk
		switch {
		case *cacheURL != "":
			st.Cache = "valkey"
		case ds.State == "on":
			st.Cache = "memory and file"
		}
		if ds.State == "unavailable" {
			st.Cache += ", unavailable"
		}
		st.CacheErr = ds.Errors
		for _, conn := range registry.All() {
			s := conn.Snapshot()
			st.Providers = append(st.Providers, control.ProviderBrief{Name: s.Name, Provider: s.Provider, State: s.State, LastStatus: s.LastStatus, Requests: s.Requests, Failures: s.Failures})
		}
		return st
	}}
	go func() { hb.Run(ctx); close(heartbeatDone) }()
	if controlRole {
		go control.Retain(ctx, db, holder.Current, log.Printf)
		auditor.Run(ctx)
	}
	go openaicompat.Watch(ctx, client.HTTP, registry, time.Minute)
	if gd != nil {
		go gd.Watch(ctx, 15*time.Second)
	}
	go control.WatchConfig(ctx, db, 2*time.Second, func() error {
		if err := keys.LoadFrom(ctx, db); err != nil {
			return err
		}
		// Cache purges made elsewhere: the control process, another
		// gateway's admin, or the command line (GV-4).
		if err := purger.ApplyRecorded(ctx); err != nil {
			log.Printf("cache purge: %v", err)
		}
		conns, warnings, err := control.Connections(ctx, db, setup.MasterKey, setup.OrgID, selfAddrs)
		if err != nil {
			return err
		}
		for _, w := range warnings {
			log.Printf("providers: %s", w)
		}
		registry.Replace(conns)
		openaicompat.Discover(ctx, client.HTTP, registry.All())
		return nil
	}, log.Printf)

	gwSrv := &http.Server{Handler: gw.Handler(), ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 2 * time.Minute}
	coSrv := &http.Server{Handler: console.Handler(), ReadHeaderTimeout: 15 * time.Second, ReadTimeout: time.Minute, WriteTimeout: time.Minute}
	errc := make(chan error, 2)
	if gwLn != nil {
		go func() { errc <- gwSrv.Serve(gwLn) }()
	}
	if coLn != nil {
		go func() { errc <- coSrv.Serve(coLn) }()
	}

	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server stopped: %v", err)
		}
	}
	log.Printf("shutting down: no new requests; open streams have 30 seconds to finish")
	close(stop)
	drain, cancelDrain := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelDrain()
	gwSrv.Shutdown(drain)
	coSrv.Shutdown(drain)
	cancel()
	<-heartbeatDone // leaves the fleet before the database closes
	// Deliver what is left in the spool.
	final, cancelFinal := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFinal()
	if err := spool.Deliver(final, db); err != nil {
		log.Printf("events stay in the spool and are delivered at the next start: %v", err)
	}
	return nil
}

func fsSub(f fs.FS, dir string) (fs.FS, error) { return fs.Sub(f, dir) }

func cacheSettings(p *policy.Policy) cache.Settings {
	return cache.Settings{
		MaxMemoryBytes: int64(p.Cache.Exact.MaxSizeMB) << 20,
		Persist:        p.CachePersist(),
		MaxDiskBytes:   int64(p.Cache.Exact.MaxDiskMB) << 20,
	}
}

// cacheLine says where the exact cache keeps its entries.
func cacheLine(p *policy.Policy, path string, err error) string {
	switch {
	case !p.CacheEnabled():
		return "off"
	case !p.CachePersist():
		return "in memory only (set cache.exact.persist: true in the policy to keep entries across a restart)"
	case err != nil && strings.HasPrefix(path, "Valkey"):
		return fmt.Sprintf("in memory only: %s cannot be used (%v); KyGate keeps serving without it", path, err)
	case err != nil:
		return fmt.Sprintf("in memory only: the cache file %s cannot be used (%v). Stop KyGate and delete it to start a new one", path, err)
	case strings.HasPrefix(path, "Valkey"):
		// Valkey's own maxmemory bounds the shared tier, not max_disk_mb.
		return fmt.Sprintf("in memory and shared in %s, answers kept %s", path, days(time.Duration(p.Cache.Exact.TTL)))
	}
	return fmt.Sprintf("in memory and on disk, %s (up to %d MB), answers kept %s", path, p.Cache.Exact.MaxDiskMB, days(time.Duration(p.Cache.Exact.TTL)))
}

// guardLine says whether the Guard is configured, ready, and needed.
func guardLine(p *policy.Policy, gd *guard.Client) string {
	needs := ""
	if p.NeedsGuard() {
		needs = "; the policy needs it for " + strings.Join(append(p.GuardEntities(), p.GuardThreats()...), ", ") + " (on_guard_unavailable: " + p.Data.OnGuardUnavailable + ")"
	}
	if gd == nil {
		if needs != "" {
			return "not configured" + needs + ". Start the Guard and pass --guard ADDR"
		}
		return "not configured (optional: needed only when the policy names an ML data type)"
	}
	st := gd.State()
	switch st.State {
	case "ready":
		if needs == "" {
			return fmt.Sprintf("%s, ready, version %s; not used: the policy names none of the types it finds (kygate policy enable --list)", st.Addr+" ("+guard.TransportDescription()+")", st.Version)
		}
		return fmt.Sprintf("%s, ready, version %s%s; levels: %s", st.Addr+" ("+guard.TransportDescription()+")", st.Version, needs, levelsLine(p, st))
	case "loading":
		return st.Addr + " (" + guard.TransportDescription() + ")" + ", loading its models" + needs
	}
	return st.Addr + " (" + guard.TransportDescription() + ")" + ", not answering yet" + needs
}

// levelsLine says, for each data type the policy needs the Guard for, which
// level finds it: "PERSON model", "EMPLOYEE_ID list (only what is listed)",
// or "not found".
func levelsLine(p *policy.Policy, st guard.State) string {
	level := map[string]string{}
	for _, cv := range st.Coverage {
		level[cv.EntityType] = cv.Level
	}
	var parts []string
	for _, t := range append(p.GuardEntities(), p.GuardThreats()...) {
		l := level[t]
		switch {
		case l == "":
			l = "NOT FOUND by this Guard"
		case l == "list":
			l = "list (only what is listed)"
		}
		if p.Data.Entities[t].Detection == "model" && level[t] != "model" {
			l += ", but the policy requires a model: requests follow on_guard_unavailable"
		}
		parts = append(parts, t+" "+l)
	}
	if len(parts) == 0 {
		return "the policy needs none"
	}
	return strings.Join(parts, "; ")
}

// semanticLine says what the semantic cache does.
func semanticLine(p *policy.Policy, reg *provider.Registry) string {
	s := p.Cache.Semantic
	switch {
	case !p.SemanticEnabled():
		return "off (cache.semantic.enabled in the policy; it needs an embeddings model, such as Ollama's nomic-embed-text)"
	case reg.ByName(s.Embeddings.Connection) == nil:
		hint := "add it with 'kygate provider add'"
		if local, ok := strings.CutPrefix(s.Embeddings.Connection, "local-"); ok {
			hint = "set KYGATE_LOCAL_" + strings.ToUpper(local) + "=http://localhost:11434/v1"
		}
		return fmt.Sprintf("waiting: no provider connection is named %q; %s, or change cache.semantic.embeddings.connection",
			s.Embeddings.Connection, hint)
	case s.Mode == "serve":
		return fmt.Sprintf("serving, per key, similarity %.2f, model %s on %s, answers kept %s", s.MinSimilarity, s.Embeddings.Model, s.Embeddings.Connection, days(time.Duration(s.TTL)))
	}
	return fmt.Sprintf("shadow mode: records the hits it would serve (console, Overview); model %s on %s", s.Embeddings.Model, s.Embeddings.Connection)
}

func days(d time.Duration) string {
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%d days", d/(24*time.Hour))
	}
	return d.String()
}

// redactURL hides a password in a URL, for messages.
func redactURL(u string) string {
	if i := strings.Index(u, "@"); i > 0 {
		if j := strings.Index(u, "://"); j > 0 && j < i {
			return u[:j+3] + "***" + u[i:]
		}
	}
	return u
}

// hierarchyPlace says where each key sits now: its team and project, for
// rebuilding the team and project budget counters.
func hierarchyPlace(ctx context.Context, cs store.ConfigStore) func(string) (string, string) {
	ks, err1 := cs.ListKeys(ctx)
	ps, err2 := cs.ListProjects(ctx)
	if err1 != nil || err2 != nil {
		return nil
	}
	team := map[string]string{}
	for _, p := range ps {
		team[p.ID] = p.TeamID
	}
	project := map[string]string{}
	for _, k := range ks {
		project[k.ID] = k.ProjectID
	}
	return func(keyID string) (string, string) {
		p := project[keyID]
		return team[p], p
	}
}

// budgetLine describes the budgets and rate limits (OP-5) for the start banner.
func budgetLine(p *policy.Policy) string {
	b, r := p.Budget, p.RateLimits
	if !b.On() && r.PerKey == (policy.RateLimit{}) && len(r.Keys) == 0 {
		return "none (budgets: and rate_limits: in the policy)"
	}
	var parts []string
	lim := func(name string, l policy.Limit) {
		switch {
		case l.Soft > 0 && l.Hard > 0:
			parts = append(parts, fmt.Sprintf("%s soft $%g, hard $%g", name, l.Soft, l.Hard))
		case l.Hard > 0:
			parts = append(parts, fmt.Sprintf("%s hard $%g", name, l.Hard))
		case l.Soft > 0:
			parts = append(parts, fmt.Sprintf("%s soft $%g", name, l.Soft))
		}
	}
	lim("org monthly", b.Org.Monthly)
	lim("org daily", b.Org.Daily)
	lim("per key monthly", b.PerKey.Monthly)
	lim("per key daily", b.PerKey.Daily)
	if len(b.Keys) > 0 {
		parts = append(parts, fmt.Sprintf("%d named keys", len(b.Keys)))
	}
	if r.PerKey.RequestsPerMinute > 0 {
		parts = append(parts, fmt.Sprintf("%d requests/min per key", r.PerKey.RequestsPerMinute))
	}
	if r.PerKey.TokensPerMinute > 0 {
		parts = append(parts, fmt.Sprintf("%d tokens/min per key", r.PerKey.TokensPerMinute))
	}
	if b.On() {
		parts = append(parts, "past a soft limit: "+strings.ReplaceAll(b.AtSoft, "_", " "))
	}
	return strings.Join(parts, "; ")
}

// outputLine describes output inspection (PR-6) for the start banner.
func outputLine(p *policy.Policy) string {
	if !p.OutputOn() {
		return "off (add an output: section to the policy; the starter policy has one)"
	}
	act := func(r policy.OutputRule) string {
		if r.Action == "" {
			return "off"
		}
		return string(r.Action)
	}
	o := p.Output
	known := "sites named in the request"
	if len(o.AllowedDomains) > 0 {
		known += " and " + strings.Join(o.AllowedDomains, ", ")
	}
	return fmt.Sprintf("secrets %s, images %s, protected addresses %s, links %s; known: %s", act(o.Secrets), act(o.Images), act(o.ProtectedURLs), act(o.Links), known)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func displayAddr(a string) string {
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return a
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}

// printBanner lists what this process serves: listen or consoleListen is
// empty when its role does not serve it.
func printBanner(out io.Writer, toLog bool, dataDir, listen, consoleListen, profile, role string, s *control.SetupResult, pol *policy.Policy, reg *provider.Registry, warnings []string, keyCount int, cacheState, semanticState, guardState, usersState string) {
	fmt.Fprintf(out, "\nKyGate %s %s  (%s profile)\n\n", Version, editionTitle(), profile)
	tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
	switch role {
	case "gateway":
		fmt.Fprintf(tw, "  Role\tgateway: the model API\n")
	case "control":
		fmt.Fprintf(tw, "  Role\tcontrol: the console, the admin API, setup, and retention\n")
	}
	fmt.Fprintf(tw, "  Data directory\t%s\n", dataDir)
	if listen != "" {
		fmt.Fprintf(tw, "  Model API\thttp://%s/v1\t(base URL for OpenAI SDKs)\n", displayAddr(listen))
		fmt.Fprintf(tw, "  \thttp://%s\t(base URL for Anthropic SDKs)\n", displayAddr(listen))
	}
	if consoleListen != "" {
		fmt.Fprintf(tw, "  Console\thttp://%s\n", displayAddr(consoleListen))
	}
	fmt.Fprintf(tw, "  Policy\t%s\t(%s mode, version %s)\n", pol.Path, pol.Mode, pol.Version)
	fmt.Fprintf(tw, "  Master key\t%s\n", s.MasterSource)
	fmt.Fprintf(tw, "  Virtual keys\t%d active\n", keyCount)
	fmt.Fprintf(tw, "  Exact cache\t%s\n", cacheState)
	fmt.Fprintf(tw, "  Semantic cache\t%s\n", semanticState)
	fmt.Fprintf(tw, "  Guard\t%s\n", guardState)
	fmt.Fprintf(tw, "  Output checks\t%s\n", outputLine(pol))
	fmt.Fprintf(tw, "  Budgets\t%s\n", budgetLine(pol))
	fmt.Fprintf(tw, "  User tokens\t%s\n", usersState)
	if pol.RoutingShadow() {
		fmt.Fprintf(tw, "  Router\tshadow mode: records the cheaper model it would use, and what that would save; changes nothing\n")
	} else {
		fmt.Fprintf(tw, "  Router\toff (routing: { mode: shadow } in the policy records what it would save)\n")
	}
	if ep := telemetry.TracingEndpoint(); ep != "" {
		fmt.Fprintf(tw, "  Traces\tOpenTelemetry, OTLP to %s\n", ep)
	} else {
		fmt.Fprintf(tw, "  Traces\toff (set OTEL_EXPORTER_OTLP_ENDPOINT to send them to a collector)\n")
	}
	tw.Flush()

	conns := reg.All()
	fmt.Fprintln(out, "\n  Providers")
	if len(conns) == 0 {
		fmt.Fprintln(out, "    none configured. KyGate cannot answer requests until you add one:")
		fmt.Fprintln(out, "      set ANTHROPIC_API_KEY or OPENAI_API_KEY and restart, or run 'kygate provider add'")
		fmt.Fprintln(out, "      a local model server: KYGATE_LOCAL_OLLAMA=http://localhost:11434/v1")
	}
	tw = tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
	for _, c := range conns {
		st := c.Snapshot()
		region := "region " + st.Region
		switch {
		case st.Region == "":
			region = "no region"
			if len(pol.Data.Regions) > 0 {
				region += ": not used, the policy pins requests to " + strings.Join(pol.Data.Regions, ", ")
			}
		case !pol.AllowsRegion(st.Region):
			region += ": not used, outside data.regions"
		}
		fmt.Fprintf(tw, "    %s\t%s\t%s\tfrom %s\t%s\t%s\n", st.Name, st.Provider, st.Hosting, st.Source, st.KeyHint, region)
	}
	tw.Flush()
	for _, w := range warnings {
		fmt.Fprintf(out, "    warning: %s\n", w)
	}
	for _, w := range pol.Warnings {
		fmt.Fprintf(out, "  policy: %s\n", w)
	}

	if toLog && (s.VirtualKey != "" || s.AdminToken != "") {
		// A log file is not a place for secrets (architecture §4.9).
		fmt.Fprintln(out, "\n  First start in the background: the virtual key and the admin token were not written to the log.")
		fmt.Fprintln(out, "  Run 'kygate key create NAME' and 'kygate admin-token reset' to get new ones.")
	} else if s.FirstStart || s.VirtualKey != "" || s.AdminToken != "" {
		fmt.Fprintln(out, "\n  First start. These secrets are shown once and cannot be shown again; store them now.")
		tw = tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
		if s.VirtualKey != "" {
			fmt.Fprintf(tw, "    Virtual key\t%s\t(use it in place of your provider key)\n", s.VirtualKey)
		}
		if s.AdminToken != "" {
			fmt.Fprintf(tw, "    Admin token\t%s\t(opens the console)\n", s.AdminToken)
		}
		tw.Flush()
	}
	if s.PolicyCreated {
		fmt.Fprintf(out, "\n  Starter policy written to %s:\n", s.PolicyPath)
		fmt.Fprintln(out, "    secrets are blocked; card numbers and IBANs are masked; email addresses are counted and allowed;")
		fmt.Fprintln(out, "    the exact cache is on and kept on disk for 30 days, so stored answers survive a restart;")
		fmt.Fprintln(out, "    the semantic cache is off until you name an embeddings model (see cache.semantic in the file);")
		fmt.Fprintln(out, "    images, files, and audio are local-only, so they are refused")
		fmt.Fprintln(out, "    while no local model server is configured. Edit the file to change any of this.")
	}
	fmt.Fprintln(out)
}

// ---------------- key ----------------

func keyCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kygate key create NAME [--project P] | key list | key revoke NAME|ID | key move NAME --project P\n" +
			"       kygate key user-secret NAME [--remove] | key require-user NAME [--off] | key user-token NAME --user ID [--ttl 1h]")
	}
	var c common
	fs := flag.NewFlagSet("key", flag.ExitOnError)
	c.register(fs)
	project := fs.String("project", "", "the project the key belongs to (AC-4); none: directly under the organization")
	remove := fs.Bool("remove", false, "user-secret: remove the key's signing secret")
	off := fs.Bool("off", false, "require-user: stop requiring a user token")
	user := fs.String("user", "", "user-token: the person's ID, such as an email address")
	ttl := fs.Duration("ttl", time.Hour, "user-token: how long the token is valid (at most 24h)")
	pos := parse(fs, args[1:])
	ctx := context.Background()
	db, err := c.openExisting()
	if err != nil {
		return err
	}
	defer db.Close()
	org, err := db.Meta(ctx, "org_id")
	if err != nil {
		return errors.New("this data directory is not set up yet: run 'kygate serve' once")
	}
	switch args[0] {
	case "create":
		if len(pos) != 1 {
			return errors.New("usage: kygate key create NAME")
		}
		pid := ""
		if *project != "" {
			p, err := findProject(ctx, db, *project)
			if err != nil {
				return err
			}
			pid = p.ID
		}
		secret, k, err := identity.CreateKey(ctx, db, pos[0], org)
		if err != nil {
			return err
		}
		if pid != "" {
			if _, err := db.SetKeyProject(ctx, k.ID, pid); err != nil {
				return err
			}
		}
		recordCLI(ctx, db, "key.create", k.Name, "project "+orNone(*project))
		fmt.Printf("Created virtual key %q (%s). It is shown once:\n\n  %s\n\n", k.Name, k.ID, secret)
		fmt.Println("A running KyGate accepts it within a few seconds.")
	case "list":
		ks, err := db.ListKeys(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		ps, _ := db.ListProjects(ctx)
		projects := map[string]string{}
		for _, p := range ps {
			projects[p.ID] = p.Name
		}
		fmt.Fprintln(tw, "NAME\tID\tPREFIX\tPROJECT\tCREATED\tSTATE\tUSER TOKENS")
		for _, k := range ks {
			state := "active"
			if k.RevokedAt != nil {
				state = "revoked " + k.RevokedAt.Format("2006-01-02 15:04")
			}
			users := "optional"
			if k.RequireUser {
				users = "required"
			}
			if k.HasSecret {
				users += ", signing secret set"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s…\t%s\t%s\t%s\t%s\n", k.Name, k.ID, k.Prefix, orNone(projects[k.ProjectID]), k.CreatedAt.Format("2006-01-02 15:04"), state, users)
		}
		tw.Flush()
	case "revoke":
		if len(pos) != 1 {
			return errors.New("usage: kygate key revoke NAME|ID")
		}
		ok, err := db.RevokeKey(ctx, pos[0])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no active key named or with ID %q", pos[0])
		}
		recordCLI(ctx, db, "key.revoke", pos[0], "")
		fmt.Println("Revoked. A running KyGate stops accepting it within a few seconds.")
	case "move":
		if len(pos) != 1 {
			return errors.New("usage: kygate key move NAME --project P (an empty --project takes the key out of its project)")
		}
		pid := ""
		if *project != "" {
			p, err := findProject(ctx, db, *project)
			if err != nil {
				return err
			}
			pid = p.ID
		}
		ok, err := db.SetKeyProject(ctx, pos[0], pid)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no key named or with ID %q", pos[0])
		}
		recordCLI(ctx, db, "key.move", pos[0], "project "+orNone(*project))
		fmt.Printf("Moved %q to project %s. A running KyGate applies it within a few seconds.\n", pos[0], orNone(*project))
	case "user-secret", "require-user", "user-token":
		if len(pos) != 1 {
			return fmt.Errorf("usage: kygate key %s NAME", args[0])
		}
		return keyUserCmd(ctx, c, db, org, args[0], pos[0], *remove, *off, *user, *ttl)
	default:
		return fmt.Errorf("unknown key command %q", args[0])
	}
	return nil
}

// ---------------- provider ----------------

func providerCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kygate provider add|list|remove|region")
	}
	var c common
	fs := flag.NewFlagSet("provider", flag.ExitOnError)
	c.register(fs)
	name := fs.String("name", "", "connection name, for example openai-team")
	kind := fs.String("provider", "", "openai | anthropic | local")
	baseURL := fs.String("base-url", "", "base URL (required for local; optional otherwise)")
	region := fs.String("region", "", "where the endpoint processes data, such as eu or us; policies can pin requests to regions (data.regions)")
	pos := parse(fs, args[1:])
	ctx := context.Background()
	db, err := c.openExisting()
	if err != nil {
		return err
	}
	defer db.Close()
	org, err := db.Meta(ctx, "org_id")
	if err != nil {
		return errors.New("this data directory is not set up yet: run 'kygate serve' once")
	}
	switch args[0] {
	case "add":
		if *name == "" || *kind == "" {
			return errors.New("usage: kygate provider add --name NAME --provider openai|anthropic|local [--base-url URL] [--region R]  (the key is read from standard input)")
		}
		master, _, _, err := control.LoadMasterKey(c.dataDir, false)
		if err != nil {
			return err
		}
		if err := control.VerifyMasterKey(ctx, db, master, org); err != nil {
			return err
		}
		secret := ""
		if *kind != provider.Local || !isTerminal() {
			secret, err = readSecret("Paste the " + *kind + " key and press Enter (it is not stored in your shell history): ")
			if err != nil {
				return err
			}
		}
		if err := control.AddCredential(ctx, db, master, org, *name, *kind, *baseURL, *region, secret); err != nil {
			return err
		}
		recordCLI(ctx, db, "provider.add", *name, strings.TrimSpace(*kind+" "+strings.ToLower(*region)))
		fmt.Printf("Stored %q, encrypted with the master key. A running KyGate uses it within a few seconds.\n", *name)
	case "list":
		creds, err := db.ListCredentials(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tPROVIDER\tREGION\tBASE URL\tADDED")
		for _, cr := range creds {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", cr.Name, cr.Provider, orNone(cr.Region), cr.BaseURL, cr.CreatedAt.Format("2006-01-02 15:04"))
		}
		tw.Flush()
		envConns, _ := provider.FromEnv(os.Environ(), nil)
		if len(envConns) > 0 {
			fmt.Println("\nFrom this shell's environment (used by 'kygate serve' started here):")
			for _, ec := range envConns {
				r := os.Getenv(control.RegionVariable(ec.Name))
				if r == "" {
					r = "none, set " + control.RegionVariable(ec.Name)
				}
				fmt.Printf("  %s (%s, region %s)\n", ec.Name, ec.Provider, r)
			}
		}
	case "remove":
		if len(pos) != 1 {
			return errors.New("usage: kygate provider remove NAME")
		}
		ok, err := db.DeleteCredential(ctx, pos[0])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no stored provider key named %q (keys from environment variables are removed by unsetting the variable)", pos[0])
		}
		fmt.Println("Removed.")
	case "region":
		if len(pos) < 1 || len(pos) > 2 {
			return errors.New("usage: kygate provider region NAME [REGION]   (no REGION clears it)")
		}
		r := ""
		if len(pos) == 2 {
			r = pos[1]
		}
		r, err := control.NormalizeRegion(r)
		if err != nil {
			return err
		}
		ok, err := db.SetCredentialRegion(ctx, pos[0], r)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no stored provider key named %q; a connection from an environment variable takes its region from %s", pos[0], control.RegionVariable(pos[0]))
		}
		recordCLI(ctx, db, "provider.region", pos[0], r)
		fmt.Printf("%s: region %s. A running KyGate uses it within a few seconds.\n", pos[0], orNone(r))
	default:
		return fmt.Errorf("unknown provider command %q", args[0])
	}
	return nil
}

func isTerminal() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func readSecret(prompt string) (string, error) {
	if isTerminal() {
		fmt.Fprint(os.Stderr, prompt)
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("no key on standard input")
	}
	return strings.TrimSpace(line), nil
}

// ---------------- admin-token ----------------

func adminTokenCmd(args []string) error {
	if len(args) == 0 || args[0] != "reset" {
		return errors.New("usage: kygate admin-token reset")
	}
	var c common
	fs := flag.NewFlagSet("admin-token", flag.ExitOnError)
	c.register(fs)
	parse(fs, args[1:])
	db, err := c.openExisting()
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Meta(context.Background(), "org_id"); err != nil {
		return errors.New("this data directory is not set up yet: run 'kygate serve' once")
	}
	tok, err := control.ResetAdminToken(context.Background(), db)
	if err != nil {
		return err
	}
	fmt.Printf("New admin token. It is shown once, and the old one no longer works:\n\n  %s\n\n", tok)
	return nil
}

// ---------------- policy ----------------

func policyCmd(args []string) error {
	if len(args) > 0 && args[0] == "enable" {
		return policyEnable(args[1:])
	}
	if len(args) > 0 && args[0] == "show" {
		return policyShow(args[1:])
	}
	if len(args) == 0 || args[0] != "check" {
		return errors.New("usage: kygate policy check [FILE] [--guard ADDR] | policy show --key NAME | policy enable TYPE... [--action alert|mask|...] [--require-model] | policy enable --list")
	}
	var c common
	fs := flag.NewFlagSet("policy", flag.ExitOnError)
	c.register(fs)
	guardAddr := fs.String("guard", env("KYGATE_GUARD", ""), "also ask this Guard which level finds each data type")
	pos := parse(fs, args[1:])
	path := c.policyPath()
	if len(pos) > 0 {
		path = pos[0]
	}
	var p *policy.Policy
	var err error
	if len(pos) == 0 && c.databaseURL != "" {
		// The organization's policy, from the database.
		docs, closeDocs, derr := c.cliPolicyDocs()
		if derr != nil {
			return derr
		}
		defer closeDocs()
		data, gerr := docs.Get(policy.OrgDoc)
		if gerr != nil {
			return gerr
		}
		path = docs.Where(policy.OrgDoc)
		p, err = policy.Parse(data, docs.Base())
	} else {
		p, err = policy.Load(path)
	}
	if err != nil {
		return err
	}
	fmt.Printf("%s is valid: %s mode, version %s\n", path, p.Mode, p.Version)
	for _, w := range p.Warnings {
		fmt.Printf("  note: %s\n", w)
	}
	if needs := append(p.GuardEntities(), p.GuardThreats()...); len(needs) == 0 && *guardAddr != "" {
		if levels, _, err := guardCoverage(*guardAddr); err == nil {
			fmt.Printf("  note: the Guard at %s finds %d data types, and the policy uses none of them: the Guard is not used.\n        See them with 'kygate policy enable --list --guard %s'; turn some on with 'kygate policy enable TYPE...'\n", *guardAddr, len(levels), *guardAddr)
		} else {
			fmt.Printf("  note: the Guard at %s does not answer (%v), and the policy does not need it\n", *guardAddr, err)
		}
	} else if len(needs) > 0 {
		if *guardAddr == "" {
			fmt.Printf("  note: the policy needs the Guard for %s; add --guard ADDR to see which level finds each type\n", strings.Join(needs, ", "))
			return nil
		}
		gd, err := guard.Dial(*guardAddr)
		if err != nil {
			return err
		}
		defer gd.Close()
		if _, err := gd.Info(context.Background()); err != nil {
			return fmt.Errorf("the Guard at %s does not answer: %w", *guardAddr, err)
		}
		st := gd.State()
		level := map[string]string{}
		for _, cv := range st.Coverage {
			level[cv.EntityType] = cv.Level
		}
		for _, t := range needs {
			if _, isThreat := p.ThreatRuleFor(t); isThreat {
				if level[t] == "" {
					fmt.Printf("  warning: %s: the Guard at %s has no detector for this threat; requests follow on_guard_unavailable (%s)\n", t, *guardAddr, p.Data.OnGuardUnavailable)
				} else {
					fmt.Printf("  ok: %s: detected by a model\n", t)
				}
				continue
			}
			switch l := level[t]; {
			case l == "":
				fmt.Printf("  warning: %s: the Guard at %s does not find this type; requests follow on_guard_unavailable (%s)\n", t, *guardAddr, p.Data.OnGuardUnavailable)
			case p.Data.Entities[t].Detection == "model" && l != "model":
				fmt.Printf("  warning: %s: the policy requires a model and the Guard has only a list; requests follow on_guard_unavailable (%s)\n", t, p.Data.OnGuardUnavailable)
			case l == "list":
				fmt.Printf("  warning: %s: found by a list only; a value that is not listed is not found. Install a model pack, or set detection: model to refuse instead\n", t)
			default:
				fmt.Printf("  ok: %s: found by a model\n", t)
			}
		}
	}
	return nil
}
