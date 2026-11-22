// Package policy holds the policy model: versioned YAML files with one action
// per data type, monitor and enforce modes, cache and audit settings
// (capabilities GV-1, PR-3, PR-7, PR-8).
//
// A policy file is one level of the organization → team → project → key
// hierarchy; levels.go merges them.
package policy

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Kytherion/KyGate/internal/detect"
)

// Action is what KyGate does with one data type (PR-3).
type Action string

const (
	Allow     Action = "allow"
	Mask      Action = "mask"       // reversible
	Redact    Action = "redact"     // permanent
	Block     Action = "block"      // refuse the request
	LocalOnly Action = "local_only" // only local targets may receive it
	Alert     Action = "alert"      // allow, and flag the event
	// Remove is an output-inspection action: the bad part of an answer is
	// replaced with a short note, and the rest arrives.
	Remove Action = "remove"
)

func (a Action) valid() bool {
	switch a {
	case Allow, Mask, Redact, Block, LocalOnly, Alert:
		return true
	}
	return false
}

// Severity orders actions for reporting and for picking the strongest one.
func (a Action) Severity() int {
	switch a {
	case Block:
		return 5
	case LocalOnly:
		return 4
	case Redact:
		return 3
	case Mask:
		return 2
	case Alert:
		return 1
	}
	return 0
}

// Mode is enforce, or monitor: record decisions and change nothing (principle 6).
type Mode string

const (
	Enforce Mode = "enforce"
	Monitor Mode = "monitor"
)

// Policy is one parsed policy file.
type Policy struct {
	Kind  string `yaml:"kind"`
	Scope string `yaml:"scope"`
	Mode  Mode   `yaml:"mode"`
	Data  struct {
		OnGuardUnavailable string                `yaml:"on_guard_unavailable"`
		Entities           map[string]EntityRule `yaml:"entities"`
		Dictionaries       map[string]DictRule   `yaml:"dictionaries"`
		UnreadableContent  Action                `yaml:"unreadable_content"`
		Embeddings         Action                `yaml:"embeddings"`
		// Regions pins requests to provider connections in these regions
		// (GV-4): a connection with another region, or none, is not used, and a
		// request with no connection left is refused. Empty: no pinning.
		Regions []string `yaml:"regions"`
	} `yaml:"data"`
	Cache struct {
		Exact struct {
			Enabled   *bool    `yaml:"enabled"`
			Scope     string   `yaml:"scope"`
			TTL       Duration `yaml:"ttl"`
			MaxSizeMB int      `yaml:"max_size_mb"` // memory budget of the in-process cache
			// RepeatWindow: the same key repeating the same request this soon
			// gets a fresh answer. 0s switches the rule off. A policy file that
			// does not name it keeps the earlier 30s.
			RepeatWindow *Duration `yaml:"repeat_window"`
			// Persist also keeps entries in <data-dir>/cache.db, so they survive
			// a restart. A policy file that does not name it keeps the cache in
			// memory only: an upgrade changes nothing (architecture §3.7, §4.5).
			Persist   *bool `yaml:"persist"`
			MaxDiskMB int   `yaml:"max_disk_mb"` // size limit of cache.db
		} `yaml:"exact"`
		Semantic Semantic `yaml:"semantic"`
		// ProviderMarkers adds Anthropic prompt-cache markers to requests
		// that have none (OP-2): off, instructions (the system prompt and
		// tools), or conversation (those and the latest message). A file that
		// does not name it means off.
		ProviderMarkers string `yaml:"provider_markers"`
	} `yaml:"cache"`
	Audit struct {
		CapturePayloads string `yaml:"capture_payloads"`
		OnSpoolFull     string `yaml:"on_spool_full"`
		RetentionDays   int    `yaml:"retention_days"`
		// PayloadRetentionDays deletes captured masked payloads sooner than
		// their events (GV-4). 0: the same as retention_days.
		PayloadRetentionDays int `yaml:"payload_retention_days"`
		// AdminRetentionDays deletes the administration trail after this many
		// days. 0: kept (an upgrade deletes nothing).
		AdminRetentionDays int `yaml:"admin_retention_days"`
	} `yaml:"audit"`

	// Threats in untrusted text, such as prompt_injection (PR-5). A threat the
	// policy names needs a Guard detector for it; without one, requests follow
	// data.on_guard_unavailable.
	Threats map[string]ThreatRule `yaml:"threats"`
	// Output is output inspection (PR-6). A policy file without it inspects
	// nothing: an upgrade changes nothing (architecture §3.7).
	Output Output `yaml:"output"`
	// Routing is read loosely, so that a file written for the design's
	// example still loads; Route holds what the router uses (OP-4).
	Routing yaml.Node `yaml:"routing"`
	Route   Routing   `yaml:"-"`
	Budgets yaml.Node `yaml:"budgets"`
	// Budget is the parsed budgets section (OP-5); RateLimits the per-key
	// limits per minute.
	Budget     Budgets    `yaml:"-"`
	RateLimits RateLimits `yaml:"rate_limits"`
	// Identity: user tokens from the company's identity provider (AC-3). The
	// organization's policy only. No section: such tokens are refused, and
	// applications' own tokens (signed with a key's secret) still work.
	Identity struct {
		UserTokens struct {
			Issuer    string   `yaml:"issuer"`
			Audiences []string `yaml:"audiences"`
			UserClaim string   `yaml:"user_claim"` // sub (default) or email
		} `yaml:"user_tokens"`
	} `yaml:"identity"`

	// Version is a digest of the file content. It is recorded in every event.
	Version string `yaml:"-"`
	// CacheVersion is a digest of the settings that can change a masked
	// request or its answer: the mode, the data rules, and the exact-cache
	// scope. It is part of every cache fingerprint, so an edit to a comment,
	// a TTL, a size, or the audit settings keeps every stored answer.
	CacheVersion string   `yaml:"-"`
	Warnings     []string `yaml:"-"`
	Path         string   `yaml:"-"`

	detectors *detect.Set
	dicts     []detect.Dictionary
}

// Semantic is the semantic cache (OP-3): a stored answer is reused for a
// look-alike last user message. It runs without the Guard, so it is
// narrow: one virtual key, short plain messages with no finding, everything
// before the last message identical, hard checks in Go, and a strict
// similarity threshold. It starts in shadow mode (architecture §3.4, §4.5).
type Semantic struct {
	// Enabled is off when the policy does not name it: an upgrade changes nothing.
	Enabled *bool `yaml:"enabled"`
	// Mode is shadow (record the hits it would serve, change nothing) or serve.
	Mode string `yaml:"mode"`
	// Scope is key. Wider scopes need the Guard's second check.
	Scope           string   `yaml:"scope"`
	TTL             Duration `yaml:"ttl"`
	MinSimilarity   float64  `yaml:"min_similarity"`
	MaxPromptTokens int      `yaml:"max_prompt_tokens"`
	MaxEntries      int      `yaml:"max_entries"`
	// Embeddings come from an OpenAI-compatible endpoint: a provider
	// connection by name, such as a local Ollama (KYGATE_LOCAL_OLLAMA gives the
	// connection "local-ollama"). The policy names the connection, never a key.
	Embeddings struct {
		Connection string `yaml:"connection"`
		Model      string `yaml:"model"`
	} `yaml:"embeddings"`
}

// Output is output inspection (PR-6): what KyGate checks in each answer
// before the caller gets it. It runs in the gateway, with no Guard.
type Output struct {
	Secrets       OutputRule `yaml:"secrets" json:"secrets"`               // credentials the model writes
	Images        OutputRule `yaml:"images" json:"images"`                 // images that load from an unknown site
	ProtectedURLs OutputRule `yaml:"protected_urls" json:"protected_urls"` // addresses that carry a placeholder
	Links         OutputRule `yaml:"links" json:"links"`                   // links to an unknown site
	// AllowedDomains are known sites, each with its subdomains. Sites that the
	// user's own turns or the system prompt name are known for that request.
	AllowedDomains []string `yaml:"allowed_domains" json:"allowed_domains"`
}

// OutputRule is the action of one output check: alert, remove, block, or allow.
// Empty means not checked.
type OutputRule struct {
	Action Action `yaml:"action" json:"action"`
}

// OutputOn reports whether any output check is on.
func (p *Policy) OutputOn() bool {
	for _, r := range []OutputRule{p.Output.Secrets, p.Output.Images, p.Output.ProtectedURLs, p.Output.Links} {
		if r.Action != "" && r.Action != Allow {
			return true
		}
	}
	return false
}

// Routing is the router's policy (OP-4). Policies name tiers, never models.
type Routing struct {
	// Mode is off or shadow. In shadow mode the router records the cheaper
	// model it would use and what that would save, and changes nothing.
	// Enforcement comes after the shadow figures and a quality check.
	Mode string `yaml:"mode" json:"mode"`
	// Tiers the router may use, cheapest first; all when empty.
	Tiers []string `yaml:"tiers" json:"tiers,omitempty"`
}

// RoutingShadow reports whether the router runs in shadow mode.
func (p *Policy) RoutingShadow() bool { return p.Route.Mode == "shadow" }

// ThreatRule is the rule for one threat.
type ThreatRule struct {
	// Action is alert (count it in the console, let the request go), block
	// (refuse the request), or allow (do not look for it).
	Action Action `yaml:"action" json:"action"`
	// MinScore is the detector score from which the text counts as the threat
	// (default 0.5, the default pack's threshold).
	MinScore float64 `yaml:"min_score" json:"min_score"`
	// Segments are the kinds of untrusted text to scan: user turns and tool
	// results (both by default). The operator's system prompt is instructions
	// by design and is never scanned (architecture §4.4).
	Segments []string `yaml:"segments" json:"segments"`
}

// EntityRule is the rule for one data type.
type EntityRule struct {
	// The JSON names are what the console reads (/api/v1/info).
	Action Action `yaml:"action" json:"action"`
	// Detection is "any" (a list or a model may find the type) or "model": the
	// Guard must have a model for it, or the request follows
	// on_guard_unavailable. A list never stands in for a model silently.
	Detection string `yaml:"detection" json:"detection"`
}

// DictRule is a company dictionary, referenced in entities as dict/<name>.
type DictRule struct {
	Terms         []string `yaml:"terms"`
	File          string   `yaml:"file"`
	CaseSensitive bool     `yaml:"case_sensitive"`
}

// Duration parses "24h", "30s", "7d".
type Duration time.Duration

// UnmarshalYAML accepts Go durations plus a "d" suffix for days.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	s := strings.TrimSpace(n.Value)
	if strings.HasSuffix(s, "d") {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err != nil {
			return fmt.Errorf("invalid duration %q", s)
		}
		*d = Duration(time.Duration(days) * 24 * time.Hour)
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q", s)
	}
	*d = Duration(v)
	return nil
}

// Parse reads and validates a policy.
func Parse(data []byte, path string) (*Policy, error) {
	p := &Policy{Path: path}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	p.Version = hex.EncodeToString(sum[:])[:12]
	if err := p.normalize(); err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	return p, nil
}

// Load reads a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, path)
}

func (p *Policy) normalize() error {
	if p.Kind != "" && p.Kind != "Policy" {
		return fmt.Errorf("kind must be Policy, not %q", p.Kind)
	}
	if p.Scope == "" {
		p.Scope = "org"
	}
	if p.Scope != "org" {
		p.Warnings = append(p.Warnings, fmt.Sprintf("scope %q is ignored: a policy file's level comes from where it lives (policy.yaml for the organization, policies/ for teams and projects)", p.Scope))
	}
	switch p.Mode {
	case "":
		p.Mode = Enforce
	case Enforce, Monitor:
	default:
		return fmt.Errorf("mode must be enforce or monitor, not %q", p.Mode)
	}
	if p.Data.Entities == nil {
		p.Data.Entities = map[string]EntityRule{}
	}
	for name, r := range p.Data.Entities {
		if !r.Action.valid() {
			return fmt.Errorf("data.entities.%s: unknown action %q", name, r.Action)
		}
		switch r.Detection {
		case "":
			r.Detection = "any"
			p.Data.Entities[name] = r
		case "any", "model":
		default:
			return fmt.Errorf("data.entities.%s: detection must be any or model, not %q", name, r.Detection)
		}
		if r.Detection == "model" && strings.HasPrefix(name, "dict/") {
			return fmt.Errorf("data.entities.%s: a dictionary is a list; detection: model does not apply to it", name)
		}
		if strings.HasPrefix(name, "dict/") {
			if _, ok := p.Data.Dictionaries[strings.TrimPrefix(name, "dict/")]; !ok {
				return fmt.Errorf("data.entities.%s: no dictionary named %q under data.dictionaries", name, strings.TrimPrefix(name, "dict/"))
			}
		} else if !knownEntity(name) {
			p.Warnings = append(p.Warnings, fmt.Sprintf("data.entities.%s: found by the Guard; while no Guard answers, or none has a detector for it, data.on_guard_unavailable applies (%s)", name, orDefault(string(p.Data.OnGuardUnavailable), "block")))
		}
	}
	for _, t := range p.GuardThreats() {
		p.Warnings = append(p.Warnings, fmt.Sprintf("threats.%s: detected by the Guard's models; while no Guard answers, or none has a detector for it, data.on_guard_unavailable applies (%s)", strings.ToLower(t), orDefault(string(p.Data.OnGuardUnavailable), "block")))
	}
	switch p.Data.UnreadableContent {
	case "":
		return fmt.Errorf("data.unreadable_content must be set to block, local_only, or allow: there is no silent default for images, files, and audio")
	case Block, LocalOnly, Allow:
	default:
		return fmt.Errorf("data.unreadable_content must be block, local_only, or allow")
	}
	switch p.Data.Embeddings {
	case "":
		p.Data.Embeddings = Block
	case Block, LocalOnly, Allow:
	default:
		return fmt.Errorf("data.embeddings must be block, local_only, or allow")
	}
	// Security fails closed (invariant 2): without a setting, a request that
	// needs the Guard is refused while the Guard is unavailable.
	switch p.Data.OnGuardUnavailable {
	case "":
		p.Data.OnGuardUnavailable = "block"
	case "block", "local_only", "fast_detectors_only":
	default:
		return fmt.Errorf("data.on_guard_unavailable must be block, local_only, or fast_detectors_only")
	}

	var dicts []detect.Dictionary
	for name, d := range p.Data.Dictionaries {
		terms := append([]string(nil), d.Terms...)
		if d.File != "" {
			b, err := os.ReadFile(d.File)
			if err != nil {
				return fmt.Errorf("data.dictionaries.%s: %w", name, err)
			}
			for _, line := range strings.Split(string(b), "\n") {
				if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
					terms = append(terms, t)
				}
			}
		}
		dicts = append(dicts, detect.Dictionary{Name: name, Terms: terms, CaseSensitive: d.CaseSensitive})
	}
	sort.Slice(dicts, func(i, j int) bool { return dicts[i].Name < dicts[j].Name })
	p.detectors = detect.NewSet(dicts)
	p.dicts = dicts

	e := &p.Cache.Exact
	if e.Enabled == nil {
		t := true
		e.Enabled = &t
	}
	switch e.Scope {
	case "":
		e.Scope = "org"
	case "org", "team", "project", "key":
	default:
		return fmt.Errorf("cache.exact.scope must be org, team, project, or key")
	}
	if e.TTL == 0 {
		e.TTL = Duration(24 * time.Hour)
	}
	if e.TTL < 0 {
		return fmt.Errorf("cache.exact.ttl must be positive")
	}
	switch {
	case e.MaxSizeMB < 0:
		return fmt.Errorf("cache.exact.max_size_mb must be positive")
	case e.MaxSizeMB == 0:
		e.MaxSizeMB = 256
	}
	if e.Persist == nil {
		f := false
		e.Persist = &f
	}
	switch {
	case e.MaxDiskMB < 0:
		return fmt.Errorf("cache.exact.max_disk_mb must be positive")
	case e.MaxDiskMB == 0:
		e.MaxDiskMB = 1024
	}
	if e.RepeatWindow == nil {
		d := Duration(30 * time.Second)
		e.RepeatWindow = &d
	}
	if *e.RepeatWindow < 0 {
		return fmt.Errorf("cache.exact.repeat_window must be 0s (off) or positive")
	}

	if err := p.Cache.Semantic.normalize(&p.Warnings); err != nil {
		return err
	}

	switch p.Audit.CapturePayloads {
	case "":
		p.Audit.CapturePayloads = "none"
	case "none", "masked":
	default:
		return fmt.Errorf("audit.capture_payloads must be none or masked")
	}
	switch p.Audit.OnSpoolFull {
	case "":
		p.Audit.OnSpoolFull = "block"
	case "block", "drop_and_alert":
	default:
		return fmt.Errorf("audit.on_spool_full must be block or drop_and_alert")
	}
	if p.Audit.RetentionDays == 0 {
		p.Audit.RetentionDays = 90
	}
	if p.Audit.RetentionDays < 0 || p.Audit.PayloadRetentionDays < 0 || p.Audit.AdminRetentionDays < 0 {
		return fmt.Errorf("audit: retention periods are a number of days, 1 or more (0 keeps the default)")
	}
	if p.Audit.PayloadRetentionDays == 0 || p.Audit.PayloadRetentionDays > p.Audit.RetentionDays {
		// A payload belongs to its event: it never outlives it.
		p.Audit.PayloadRetentionDays = p.Audit.RetentionDays
	}
	seen := map[string]bool{}
	var regions []string
	for _, r := range p.Data.Regions {
		r = strings.ToLower(strings.TrimSpace(r))
		if !ValidRegion(r) {
			return fmt.Errorf("data.regions: %q is not a region name: use letters, digits, and dashes, such as eu or us-east", r)
		}
		if !seen[r] {
			seen[r] = true
			regions = append(regions, r)
		}
	}
	if len(p.Data.Regions) > 0 && len(regions) == 0 {
		return fmt.Errorf("data.regions names no region")
	}
	p.Data.Regions = regions

	for name, r := range p.Threats {
		if strings.ToLower(name) != name || strings.TrimSpace(name) == "" {
			return fmt.Errorf("threats.%s: write threat names in lower case, such as prompt_injection", name)
		}
		switch r.Action {
		case "":
			return fmt.Errorf("threats.%s: an action is required: alert, block, or allow", name)
		case Alert, Block, Allow:
		default:
			return fmt.Errorf("threats.%s: action must be alert, block, or allow, not %q", name, r.Action)
		}
		switch {
		case r.MinScore == 0:
			r.MinScore = 0.5
		case r.MinScore < 0 || r.MinScore > 1:
			return fmt.Errorf("threats.%s: min_score must be between 0 and 1", name)
		}
		if len(r.Segments) == 0 {
			r.Segments = []string{"user", "tool_result"}
		}
		for _, sg := range r.Segments {
			if sg != "user" && sg != "tool_result" {
				return fmt.Errorf("threats.%s: segments may be user and tool_result, not %q (the system prompt is the operator's own instructions)", name, sg)
			}
		}
		p.Threats[name] = r
	}
	switch p.Cache.ProviderMarkers {
	case "":
		p.Cache.ProviderMarkers = "off"
	case "off", "instructions", "conversation":
	default:
		return fmt.Errorf("cache.provider_markers must be off, instructions, or conversation, not %q", p.Cache.ProviderMarkers)
	}
	for name, r := range map[string]OutputRule{"secrets": p.Output.Secrets, "images": p.Output.Images, "protected_urls": p.Output.ProtectedURLs, "links": p.Output.Links} {
		switch r.Action {
		case "", Alert, Remove, Block, Allow:
		default:
			return fmt.Errorf("output.%s: action must be alert, remove, block, or allow, not %q", name, r.Action)
		}
	}
	for i, d := range p.Output.AllowedDomains {
		c := strings.ToLower(strings.TrimSpace(d))
		c = strings.TrimPrefix(strings.TrimPrefix(c, "https://"), "http://")
		c = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(c, "*."), "."), "/")
		if c == "" || strings.ContainsAny(c, "/ :?#@") || !strings.Contains(c, ".") {
			return fmt.Errorf("output.allowed_domains: %q is not a domain name such as example.com", d)
		}
		p.Output.AllowedDomains[i] = c
	}
	if err := p.parseRouting(); err != nil {
		return err
	}
	if err := p.parseBudgets(); err != nil {
		return err
	}
	if err := p.checkIdentity(); err != nil {
		return err
	}
	if err := p.checkRateLimits(); err != nil {
		return err
	}
	sort.Strings(p.Warnings)
	p.CacheVersion = p.cacheVersion()
	return nil
}

func (s *Semantic) normalize(warnings *[]string) error {
	if s.Enabled == nil {
		f := false
		s.Enabled = &f
	}
	switch s.Mode {
	case "":
		s.Mode = "shadow"
	case "shadow", "serve":
	default:
		return fmt.Errorf("cache.semantic.mode must be shadow or serve")
	}
	switch s.Scope {
	case "", "key":
		s.Scope = "key"
	case "application":
		// The design's default. One key is the narrowest scope, so it stands
		// in for one application.
		s.Scope = "key"
		*warnings = append(*warnings, "cache.semantic.scope: application is not supported yet; key is used, which is narrower")
	default:
		return fmt.Errorf("cache.semantic.scope must be key (wider scopes need the Guard's second check)")
	}
	if s.TTL < 0 {
		return fmt.Errorf("cache.semantic.ttl must be positive")
	}
	if s.TTL == 0 {
		s.TTL = Duration(7 * 24 * time.Hour)
	}
	switch {
	case s.MinSimilarity == 0:
		s.MinSimilarity = 0.95
	case s.MinSimilarity < 0.8 || s.MinSimilarity > 1:
		return fmt.Errorf("cache.semantic.min_similarity must be between 0.80 and 1")
	}
	switch {
	case s.MaxPromptTokens < 0:
		return fmt.Errorf("cache.semantic.max_prompt_tokens must be positive")
	case s.MaxPromptTokens == 0:
		s.MaxPromptTokens = 256
	}
	switch {
	case s.MaxEntries < 0:
		return fmt.Errorf("cache.semantic.max_entries must be positive")
	case s.MaxEntries == 0:
		s.MaxEntries = 20000
	}
	if *s.Enabled && (s.Embeddings.Connection == "" || s.Embeddings.Model == "") {
		return fmt.Errorf("cache.semantic.embeddings.connection and model are required when the semantic cache is enabled: name a provider connection that serves embeddings, such as a local Ollama (KYGATE_LOCAL_OLLAMA gives the connection \"local-ollama\")")
	}
	return nil
}

// cacheVersion hashes what can change a masked request or its answer.
func (p *Policy) cacheVersion() string {
	h := sha256.New()
	w := func(parts ...string) {
		for _, s := range parts {
			fmt.Fprintf(h, "%d:%s;", len(s), s)
		}
	}
	w("v1", string(p.Mode), string(p.Data.UnreadableContent), string(p.Data.Embeddings), p.Cache.Exact.Scope)
	names := make([]string, 0, len(p.Data.Entities))
	for n := range p.Data.Entities {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w("entity", n, string(p.Data.Entities[n].Action), p.Data.Entities[n].Detection)
	}
	// The dictionaries as the detectors use them, file contents included.
	for _, d := range p.dicts {
		terms := append([]string(nil), d.Terms...)
		sort.Strings(terms)
		w("dict", d.Name, fmt.Sprint(d.CaseSensitive))
		w(terms...)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// RepeatWindow is the regenerate-click window; 0 means off.
func (p *Policy) RepeatWindow() time.Duration { return time.Duration(*p.Cache.Exact.RepeatWindow) }

// SemanticEnabled reports whether the semantic cache runs, in either mode.
func (p *Policy) SemanticEnabled() bool { return p.CacheEnabled() && *p.Cache.Semantic.Enabled }

// KnownEntities are the types the built-in fast detectors produce.
var KnownEntities = []string{"SECRET", "CREDIT_CARD", "IBAN", "EMAIL"}

func knownEntity(name string) bool {
	for _, k := range KnownEntities {
		if k == name {
			return true
		}
	}
	return false
}

// GuardEntities lists the data types the policy names that only the Guard's ML
// detectors find, sorted. Empty: the policy needs no Guard.
func (p *Policy) GuardEntities() []string {
	var out []string
	for name := range p.Data.Entities {
		if !strings.HasPrefix(name, "dict/") && (!knownEntity(name) || p.Data.Entities[name].Detection == "model") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ModelRequired lists the data types the policy requires a model for
// (detection: model), sorted.
func (p *Policy) ModelRequired() []string {
	var out []string
	for name, r := range p.Data.Entities {
		if r.Detection == "model" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// NeedsGuard reports whether the policy needs the Guard. A policy that names
// no ML data type and no threat runs on the fast detectors alone, with no
// Guard (architecture §3.7).
func (p *Policy) NeedsGuard() bool { return len(p.GuardEntities()) > 0 || len(p.GuardThreats()) > 0 }

// GuardThreats lists the threats the policy looks for (action alert or block),
// as the Guard names them (upper case), sorted.
func (p *Policy) GuardThreats() []string {
	var out []string
	for name, r := range p.Threats {
		if r.Action != Allow {
			out = append(out, strings.ToUpper(name))
		}
	}
	sort.Strings(out)
	return out
}

// ThreatRuleFor returns the rule of a threat named as the Guard names it.
func (p *Policy) ThreatRuleFor(guardName string) (ThreatRule, bool) {
	r, ok := p.Threats[strings.ToLower(guardName)]
	return r, ok
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// ActionFor returns the action for a data type. Types the policy does not
// name are allowed, and still counted in reports.
func (p *Policy) ActionFor(entity string) Action {
	if r, ok := p.Data.Entities[entity]; ok {
		return r.Action
	}
	return Allow
}

// Detectors returns the detector set built for this policy.
func (p *Policy) Detectors() *detect.Set { return p.detectors }

// CacheEnabled reports whether the exact cache is on.
func (p *Policy) CacheEnabled() bool { return *p.Cache.Exact.Enabled }

// CachePersist reports whether exact-cache entries are also kept on disk.
func (p *Policy) CachePersist() bool { return p.CacheEnabled() && *p.Cache.Exact.Persist }

// Holder keeps the current policy and reloads it when the file changes.
// An invalid edit keeps the last good policy in force. It also keeps the
// per-level files of policies/ (levels.go), with the same rule per file, and
// the effective policy of each team, project, and key, merged on first use.
type Holder struct {
	path    string
	docs    Docs
	current atomic.Pointer[Policy]
	mu      sync.Mutex
	sig     string
	OnError func(error)
	OnLoad  func(*Policy)

	lmu       sync.Mutex
	org       []byte
	levels    map[string]LevelFile // "kind-name" -> its last good file
	effective map[string]*Policy
}

// NewHolder loads the policy at path, and the per-level files next to it.
func NewHolder(path string) (*Holder, error) { return NewHolderFrom(FileDocs{Path: path}) }

// NewHolderFrom loads the policies of a document store.
func NewHolderFrom(d Docs) (*Holder, error) {
	path := d.Base()
	h := &Holder{path: path, docs: d}
	data, err := d.Get(OrgDoc)
	if err != nil {
		return nil, err
	}
	p, err := Parse(data, path)
	if err != nil {
		return nil, err
	}
	p.Path = d.Where(OrgDoc)
	h.current.Store(p)
	h.org = data
	h.levels, h.effective = map[string]LevelFile{}, map[string]*Policy{}
	if h.loadLevels() {
		h.sig = h.signature()
	} // else the first tick of Watch reads them again
	return h, nil
}

// Current returns the organization's policy in force.
func (h *Holder) Current() *Policy { return h.current.Load() }

// Path returns the organization's policy file (or its base path, when the
// policies live in the database).
func (h *Holder) Path() string { return h.path }

// Docs returns where the policies live.
func (h *Holder) Docs() Docs { return h.docs }

// Reload reloads the files now, when they changed.
func (h *Holder) Reload() { h.reloadIfChanged() }

// LevelsDir returns the folder of per-level files.
func (h *Holder) LevelsDir() string { return filepath.Join(filepath.Dir(h.path), LevelsDir) }

// Levels returns the per-level files in force, sorted by kind and name.
func (h *Holder) Levels() []LevelFile {
	h.lmu.Lock()
	defer h.lmu.Unlock()
	out := make([]LevelFile, 0, len(h.levels))
	for _, lf := range h.levels {
		out = append(out, lf)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind+out[i].Name < out[j].Kind+out[j].Name })
	return out
}

// For returns the effective policy of a caller: the organization's, merged
// with its team's, project's, and key's files when they exist.
func (h *Holder) For(team, project, key string) *Policy {
	h.lmu.Lock()
	defer h.lmu.Unlock()
	var files []LevelFile
	for _, kn := range [][2]string{{"team", team}, {"project", project}, {"key", key}} {
		if kn[1] == "" {
			continue
		}
		if lf, ok := h.levels[kn[0]+"-"+kn[1]]; ok {
			files = append(files, lf)
		}
	}
	org := h.current.Load()
	if len(files) == 0 {
		return org
	}
	memo := team + "|" + project + "|" + key
	if p, ok := h.effective[memo]; ok {
		return p
	}
	p, err := Effective(h.org, h.path, files)
	if err != nil {
		// Each file merges alone (checked at load); a combination that
		// does not is reported, and the organization's policy applies.
		if h.OnError != nil {
			h.OnError(fmt.Errorf("policies for team %q, project %q, key %q: %v; the organization's policy applies", team, project, key, err))
		}
		p = org
	}
	h.effective[memo] = p
	return p
}

// loadLevels reads policies/, keeping the last good version of a file that
// does not merge with the organization's policy. It reports false when the
// files cannot be read, so that the next tick reads them again.
func (h *Holder) loadLevels() bool {
	files, warnings, err := h.docs.Levels()
	if err != nil {
		if h.OnError != nil {
			h.OnError(err)
		}
		return false
	}
	for _, w := range warnings {
		if h.OnError != nil {
			h.OnError(fmt.Errorf("%s", w))
		}
	}
	h.lmu.Lock()
	defer h.lmu.Unlock()
	next := map[string]LevelFile{}
	for _, lf := range files {
		id := lf.Kind + "-" + lf.Name
		if _, err := Effective(h.org, h.path, []LevelFile{lf}); err != nil {
			if h.OnError != nil {
				h.OnError(fmt.Errorf("%s: %v; the last good version stays in force", lf.Path, err))
			}
			if old, ok := h.levels[id]; ok {
				next[id] = old
			}
			continue
		}
		next[id] = lf
	}
	h.levels = next
	h.effective = map[string]*Policy{}
	return true
}

// signature changes when the organization's policy or any level's changes.
func (h *Holder) signature() string { return h.docs.Signature() }

// Watch polls the files and reloads them on change, until stop is closed.
func (h *Holder) Watch(stop <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			h.reloadIfChanged()
		}
	}
}

func (h *Holder) reloadIfChanged() {
	h.mu.Lock()
	defer h.mu.Unlock()
	sig := h.signature()
	if sig == h.sig {
		return
	}
	data, err := h.docs.Get(OrgDoc)
	if err != nil {
		// A read error may pass, such as a database that does not answer for
		// a moment: the signature is not recorded, so the next tick reads again.
		if h.OnError != nil {
			h.OnError(err)
		}
		return
	}
	p, err := Parse(data, h.path)
	if err != nil {
		// An invalid edit stays rejected until the document changes again.
		h.sig = sig
		if h.OnError != nil {
			h.OnError(err)
		}
		return
	}
	p.Path = h.docs.Where(OrgDoc)
	changed := p.Version != h.Current().Version
	if changed {
		// The merged policies of teams, projects, and keys are dropped with
		// the organization's old policy, in the same step: none is ever served
		// from a merge with an organization policy that is no longer in force.
		h.lmu.Lock()
		h.org, h.effective = data, map[string]*Policy{}
		h.current.Store(p)
		h.lmu.Unlock()
	}
	if h.loadLevels() {
		h.sig = sig
	}
	if changed && h.OnLoad != nil {
		h.OnLoad(p)
	}
}

//go:embed starter.yaml
var starter []byte

// Starter returns the starter policy written at the first start (architecture §3.7).
func Starter() []byte { return append([]byte(nil), starter...) }

// parseRouting reads the routing section. Unknown keys are kept as warnings,
// so that an older file never stops loading.
func (p *Policy) parseRouting() error {
	p.Route = Routing{Mode: "off"}
	if p.Routing.Kind == 0 {
		return nil
	}
	var raw map[string]any
	if err := p.Routing.Decode(&raw); err != nil {
		return fmt.Errorf("routing: %v", err)
	}
	for k := range raw {
		if k != "mode" && k != "tiers" {
			p.Warnings = append(p.Warnings, fmt.Sprintf("routing.%s: accepted, and ignored until the slice that ships it", k))
		}
	}
	var r Routing
	if err := p.Routing.Decode(&r); err != nil {
		return fmt.Errorf("routing: %v", err)
	}
	switch r.Mode {
	case "", "off", "pinned":
		r.Mode = "off"
	case "shadow":
	case "auto", "enforce":
		p.Warnings = append(p.Warnings, "routing.mode: "+r.Mode+" arrives after the shadow figures and a quality check; the router runs in shadow mode, and changes nothing")
		r.Mode = "shadow"
	default:
		return fmt.Errorf("routing.mode must be off or shadow, not %q", r.Mode)
	}
	for _, t := range r.Tiers {
		switch t {
		case "local", "economy", "standard", "frontier":
		default:
			return fmt.Errorf("routing.tiers: %q is not a tier (local, economy, standard, frontier)", t)
		}
	}
	p.Route = r
	return nil
}

// NoRegion stands for "no region in common" when policy levels pin to
// regions that do not overlap: no connection may carry it, so every request
// is refused.
const NoRegion = "none-in-common"

// ValidConnectionRegion reports whether r can be a connection's region.
func ValidConnectionRegion(r string) bool { return ValidRegion(r) && r != NoRegion }

// ValidRegion reports whether r is a region name: 1 to 32 lower-case letters,
// digits, and dashes, such as eu, us-east, or on-prem.
func ValidRegion(r string) bool {
	if r == "" || len(r) > 32 || r[0] == '-' {
		return false
	}
	for _, c := range r {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// AllowsRegion reports whether a connection in region may receive requests:
// always without pinning; with pinning, only a listed region.
func (p *Policy) AllowsRegion(region string) bool {
	if len(p.Data.Regions) == 0 {
		return true
	}
	for _, r := range p.Data.Regions {
		if r == region {
			return true
		}
	}
	return false
}

func (p *Policy) checkIdentity() error {
	u := &p.Identity.UserTokens
	u.Issuer = strings.TrimSpace(u.Issuer)
	if u.Issuer == "" {
		if len(u.Audiences) > 0 {
			return fmt.Errorf("identity.user_tokens: name the issuer, the identity provider's address")
		}
		return nil
	}
	if !strings.HasPrefix(u.Issuer, "https://") && !strings.HasPrefix(u.Issuer, "http://localhost") && !strings.HasPrefix(u.Issuer, "http://127.0.0.1") {
		return fmt.Errorf("identity.user_tokens.issuer must be an https:// address")
	}
	if len(u.Audiences) == 0 {
		return fmt.Errorf("identity.user_tokens.audiences: name the audience the provider puts in tokens for KyGate, such as its client ID")
	}
	switch u.UserClaim {
	case "":
		u.UserClaim = "sub"
	case "sub", "email":
	default:
		return fmt.Errorf("identity.user_tokens.user_claim must be sub or email")
	}
	return nil
}
