package policy

// Policies per level of the hierarchy (AC-4, GV-1; architecture §3.6). The
// organization's policy is policy.yaml. Next to it, a policies/ folder may
// hold a file per team, project, or key:
//
//	policies/team-NAME.yaml
//	policies/project-NAME.yaml
//	policies/key-NAME.yaml
//
// A request's policy merges them, organization -> team -> project -> key:
//
//   - for security settings the strictest wins: the mode; each data type's
//     action and detection; on_guard_unavailable, unreadable_content, and
//     embeddings; each threat (action, lowest min_score, union of segments);
//     each output check, and the known sites, which intersect; data.regions,
//     which intersect too. A lower level
//     can only tighten them;
//   - for cache, routing, and rate_limits the most specific wins;
//   - a level's budgets are that level's own: a team file's monthly_usd is the
//     team's total, a project's the project's, a key's the key's; per_key and
//     at_soft follow the most specific level;
//   - audit and identity are the organization's only.
//
// The merge works on the YAML, then the result goes through Parse, so the
// same validation and defaults apply. Effective policies are kept in memory
// per team, project, and key, so the request path reads no file.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// LevelsDir is the folder of per-level policy files, next to policy.yaml.
const LevelsDir = "policies"

// Level kinds, as file name prefixes.
var levelKinds = []string{"team", "project", "key"}

// LevelFile is one per-level policy file.
type LevelFile struct {
	Kind, Name string // team | project | key, and its name
	Path       string
	Data       []byte
}

// ReadLevels lists the per-level files in dir. A file whose name does not
// follow KIND-NAME.yaml is reported, not used.
func ReadLevels(dir string) ([]LevelFile, []string, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var out []LevelFile
	var warnings []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !(strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml")) || strings.HasSuffix(n, ".bak") {
			continue
		}
		base := strings.TrimSuffix(strings.TrimSuffix(n, ".yaml"), ".yml")
		kind, name, ok := strings.Cut(base, "-")
		if !ok || name == "" || !contains(levelKinds, kind) {
			warnings = append(warnings, fmt.Sprintf("%s: not used; per-level files are named team-NAME.yaml, project-NAME.yaml, or key-NAME.yaml", filepath.Join(dir, n)))
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, nil, err
		}
		out = append(out, LevelFile{Kind: kind, Name: name, Path: filepath.Join(dir, n), Data: data})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, warnings, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// strictness lists each setting's values from the most lenient to the strictest.
var strictness = map[string][]string{
	"mode":                 {"monitor", "enforce"},
	"on_guard_unavailable": {"fast_detectors_only", "local_only", "block"},
	"unreadable_content":   {"allow", "local_only", "block"},
	"embeddings":           {"allow", "local_only", "block"},
	"entity":               {"allow", "alert", "mask", "redact", "local_only", "block"},
	"detection":            {"any", "model"},
	"threat":               {"allow", "alert", "block"},
	"output":               {"allow", "alert", "remove", "block"},
}

// stricter returns the stricter of two values; an unknown value is kept, so
// that Parse reports it.
func stricter(kind string, a, b any) any {
	order := strictness[kind]
	as, _ := a.(string)
	bs, _ := b.(string)
	ai, bi := indexOf(order, as), indexOf(order, bs)
	switch {
	case a == nil:
		return b
	case bi < 0 && bs != "":
		return b
	case bi > ai:
		return b
	}
	return a
}

func indexOf(list []string, s string) int {
	for i, x := range list {
		if x == s {
			return i
		}
	}
	return -1
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func ensure(m map[string]any, k string) map[string]any {
	if c := asMap(m[k]); c != nil {
		return c
	}
	c := map[string]any{}
	m[k] = c
	return c
}

// override copies src over dst, recursively: the most specific level wins.
func override(dst, src map[string]any) {
	for k, v := range src {
		if sm := asMap(v); sm != nil {
			if dm := asMap(dst[k]); dm != nil {
				override(dm, sm)
				continue
			}
		}
		dst[k] = v
	}
}

func asList(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, e := range l {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func toAny(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

// mergeLevel applies one level file to the merged policy.
func mergeLevel(base map[string]any, lf LevelFile, level map[string]any) []string {
	var warnings []string
	where := filepath.Base(lf.Path)
	keys := make([]string, 0, len(level))
	for k := range level {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := level[k]
		switch k {
		case "kind", "scope":
		case "audit", "identity":
			warnings = append(warnings, where+": "+k+" is set in the organization's policy only; ignored here")
		case "mode":
			base["mode"] = stricter("mode", base["mode"], v)
		case "data":
			mergeData(ensure(base, "data"), asMap(v))
		case "threats":
			th := ensure(base, "threats")
			for name, r := range asMap(v) {
				lr, br := asMap(r), asMap(th[name])
				if br == nil {
					th[name] = lr
					continue
				}
				br["action"] = stricter("threat", br["action"], lr["action"])
				if s, ok := lr["min_score"].(float64); ok {
					if b, ok := br["min_score"].(float64); !ok || s < b {
						br["min_score"] = s
					}
				}
				if segs := asList(lr["segments"]); segs != nil {
					all := asList(br["segments"])
					if br["segments"] == nil {
						all = []string{"user", "tool_result"}
					}
					for _, s := range segs {
						if !contains(all, s) {
							all = append(all, s)
						}
					}
					br["segments"] = toAny(all)
				}
			}
		case "output":
			out := ensure(base, "output")
			for check, r := range asMap(v) {
				if check == "allowed_domains" {
					lower := asList(r)
					if out["allowed_domains"] == nil {
						if len(lower) > 0 {
							warnings = append(warnings, where+": output.allowed_domains can only narrow the organization's list, which names none; ignored")
						}
						continue
					}
					var keep []string
					for _, d := range asList(out["allowed_domains"]) {
						if contains(lower, d) {
							keep = append(keep, d)
						}
					}
					out["allowed_domains"] = toAny(keep)
					continue
				}
				lr, br := asMap(r), asMap(out[check])
				if br == nil {
					out[check] = lr
					continue
				}
				br["action"] = stricter("output", br["action"], lr["action"])
			}
		case "budgets":
			mergeBudgets(ensure(base, "budgets"), lf, asMap(v))
		case "cache", "routing", "rate_limits":
			if vm := asMap(v); vm != nil {
				override(ensure(base, k), vm)
			}
		default:
			warnings = append(warnings, fmt.Sprintf("%s: %s is not a policy section; ignored", where, k))
		}
	}
	return warnings
}

func mergeData(base, level map[string]any) {
	for k, v := range level {
		switch k {
		case "entities":
			ents := ensure(base, "entities")
			for t, r := range asMap(v) {
				lr, br := asMap(r), asMap(ents[t])
				if br == nil {
					ents[t] = lr
					continue
				}
				br["action"] = stricter("entity", br["action"], lr["action"])
				if lr["detection"] != nil {
					br["detection"] = stricter("detection", br["detection"], lr["detection"])
				}
			}
		case "dictionaries":
			dicts := ensure(base, "dictionaries")
			for name, d := range asMap(v) {
				ld, bd := asMap(d), asMap(dicts[name])
				if bd == nil {
					dicts[name] = ld
					continue
				}
				terms := asList(bd["terms"])
				for _, t := range asList(ld["terms"]) {
					if !contains(terms, t) {
						terms = append(terms, t)
					}
				}
				bd["terms"] = toAny(terms)
			}
		case "on_guard_unavailable", "unreadable_content", "embeddings":
			base[k] = stricter(k, base[k], v)
		case "regions":
			// Strictest wins: a level can only narrow the regions. Two lists
			// with nothing in common leave none, and every request is refused.
			lower := lowerAll(asList(v))
			if base["regions"] == nil {
				base["regions"] = toAny(lower)
				continue
			}
			keep := []string{}
			for _, r := range lowerAll(asList(base["regions"])) {
				if contains(lower, r) {
					keep = append(keep, r)
				}
			}
			if len(keep) == 0 {
				keep = []string{NoRegion}
			}
			base["regions"] = toAny(keep)
		default:
			base[k] = v
		}
	}
}

// mergeBudgets turns a level's budgets into that level's own budget.
func mergeBudgets(base map[string]any, lf LevelFile, level map[string]any) {
	own := map[string]any{}
	for k, v := range level {
		switch k {
		case "monthly_usd", "daily_usd":
			own[k] = v
		case "per_key", "per_user", "at_soft", "at_hard", "on_counters_unavailable":
			base[k] = v
		case "keys":
			override(ensure(base, "keys"), asMap(v))
		}
	}
	if len(own) == 0 {
		return
	}
	switch lf.Kind {
	case "team", "project":
		base[lf.Kind] = own
	case "key":
		ensure(base, "keys")[lf.Name] = own
	}
}

// Effective merges the organization's policy with the files of a team, a
// project, and a key (any may be absent), and parses the result.
func Effective(org []byte, orgPath string, levels []LevelFile) (*Policy, error) {
	if len(levels) == 0 {
		return Parse(org, orgPath)
	}
	var base map[string]any
	if err := yaml.Unmarshal(org, &base); err != nil {
		return nil, fmt.Errorf("%s: %v", orgPath, err)
	}
	if base == nil {
		base = map[string]any{}
	}
	var warnings, names []string
	for _, lf := range levels {
		var lv map[string]any
		if err := yaml.Unmarshal(lf.Data, &lv); err != nil {
			return nil, fmt.Errorf("%s: %v", lf.Path, err)
		}
		warnings = append(warnings, mergeLevel(base, lf, lv)...)
		names = append(names, lf.Kind+"-"+lf.Name)
	}
	merged, err := yaml.Marshal(base)
	if err != nil {
		return nil, err
	}
	p, err := Parse(merged, orgPath+" + "+strings.Join(names, " + "))
	if err != nil {
		return nil, err
	}
	p.Warnings = append(warnings, p.Warnings...)
	sum := sha256.Sum256(merged)
	p.Version = hex.EncodeToString(sum[:])[:12]
	return p, nil
}

func lowerAll(list []string) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = strings.ToLower(strings.TrimSpace(s))
	}
	return out
}
