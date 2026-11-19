package policy

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// EntityChange adds a data type to data.entities, or changes its rule.
type EntityChange struct {
	Type      string
	Action    Action
	Detection string // "" keeps the current one ("any" for a new type), or any | model
	Note      string // a trailing comment for a new line
}

// EditResult says what EnableEntities changed, line by line.
type EditResult struct {
	Added, Changed, Unchanged []string // the new lines, the changed lines, the types already set so
}

var (
	reTopKey   = regexp.MustCompile(`^data:\s*(#.*)?$`)
	reEntities = regexp.MustCompile(`^(\s+)entities:\s*(#.*)?$`)
	// A one-line rule: "    PERSON: { action: mask }   # comment"
	reRuleLine = regexp.MustCompile(`^(\s+)([A-Za-z0-9_/.\-]+):(\s*)\{([^}]*)\}(\s*#.*)?$`)
)

// EnableEntities adds or changes rules in data.entities of a policy file, as
// text, so that every comment and the layout of the file stay as the owner
// wrote them. The result is checked with Parse; an edit that would not load is
// an error and nothing is changed.
func EnableEntities(src []byte, changes []EntityChange) ([]byte, EditResult, error) {
	var res EditResult
	text := strings.ReplaceAll(string(src), "\r\n", "\n")
	lines := strings.Split(text, "\n")

	dataAt := -1
	for i, l := range lines {
		if reTopKey.MatchString(l) {
			dataAt = i
			break
		}
	}
	if dataAt < 0 {
		return nil, res, fmt.Errorf("the policy has no data: section at the top level; add the rules by hand")
	}
	// The end of the data: section: the next top-level line.
	dataEnd := len(lines)
	for i := dataAt + 1; i < len(lines); i++ {
		if l := lines[i]; l != "" && l[0] != ' ' && l[0] != '#' {
			dataEnd = i
			break
		}
	}
	entAt, indent := -1, ""
	for i := dataAt + 1; i < dataEnd; i++ {
		if m := reEntities.FindStringSubmatch(lines[i]); m != nil {
			entAt, indent = i, m[1]
			break
		}
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "entities:") {
			return nil, res, fmt.Errorf("data.entities is written on one line; turn it into one rule per line, then run this command again")
		}
	}
	childIndent := indent + "  "
	if entAt < 0 {
		// No entities yet: open the block right under data:.
		lines = append(lines[:dataAt+1], append([]string{"  entities:"}, lines[dataAt+1:]...)...)
		entAt, indent, childIndent = dataAt+1, "  ", "    "
		dataEnd++
	}

	// The rules: lines indented deeper than entities:, up to the first line
	// that is not (blank lines and comments of the same depth stay inside).
	last := entAt
	rules := map[string]int{}
	for i := entAt + 1; i < dataEnd; i++ {
		l := lines[i]
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		lead := len(l) - len(strings.TrimLeft(l, " "))
		if lead <= len(indent) {
			break
		}
		if childIndent == indent+"  " && !strings.HasPrefix(t, "#") {
			childIndent = l[:lead] // follow the file's own indentation
		}
		last = i
		if m := reRuleLine.FindStringSubmatch(l); m != nil {
			rules[m[2]] = i
		} else if !strings.HasPrefix(t, "#") {
			name := strings.TrimSuffix(strings.Fields(t)[0], ":")
			rules[name] = -1 // a rule written on several lines
		}
	}

	var insert []string
	for _, c := range changes {
		name := strings.TrimSpace(c.Type)
		if !c.Action.valid() {
			return nil, res, fmt.Errorf("%s: unknown action %q", name, c.Action)
		}
		if c.Detection != "" && c.Detection != "any" && c.Detection != "model" {
			return nil, res, fmt.Errorf("%s: detection must be any or model", name)
		}
		at, exists := rules[name]
		switch {
		case exists && at < 0:
			return nil, res, fmt.Errorf("data.entities.%s is written on several lines; change it by hand", name)
		case exists:
			m := reRuleLine.FindStringSubmatch(lines[at])
			fields := parseFlow(m[4])
			before := renderFlow(fields)
			fields["action"] = string(c.Action)
			if c.Detection != "" {
				if c.Detection == "any" {
					delete(fields, "detection")
				} else {
					fields["detection"] = c.Detection
				}
			}
			if renderFlow(fields) == before {
				res.Unchanged = append(res.Unchanged, name) // the line is left exactly as it was
				continue
			}
			// The same spacing after the name and the same trailing comment.
			lines[at] = m[1] + name + ":" + m[3] + renderFlow(fields) + m[5]
			res.Changed = append(res.Changed, strings.TrimSpace(lines[at]))
		default:
			fields := map[string]string{"action": string(c.Action)}
			if c.Detection == "model" {
				fields["detection"] = "model"
			}
			line := fmt.Sprintf("%s%-12s %s", childIndent, name+":", renderFlow(fields))
			if c.Note != "" {
				line += "   # " + c.Note
			}
			insert = append(insert, line)
			res.Added = append(res.Added, strings.TrimSpace(line))
			rules[name] = 0
		}
	}
	if len(insert) > 0 {
		lines = append(lines[:last+1], append(insert, lines[last+1:]...)...)
	}
	out := strings.Join(lines, "\n")
	if bytes.Contains(src, []byte("\r\n")) {
		out = strings.ReplaceAll(out, "\n", "\r\n")
	}
	if _, err := Parse([]byte(out), "policy.yaml"); err != nil {
		return nil, res, fmt.Errorf("the edited policy would not load, so nothing was changed: %w", err)
	}
	return []byte(out), res, nil
}

// parseFlow reads "action: mask, detection: model" into a map.
func parseFlow(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(part, ":")
		if ok && strings.TrimSpace(k) != "" {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// renderFlow writes a rule as "{ action: mask, detection: model }", action first.
func renderFlow(f map[string]string) string {
	keys := make([]string, 0, len(f))
	for k := range f {
		if k != "action" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := []string{"action: " + f["action"]}
	for _, k := range keys {
		parts = append(parts, k+": "+f[k])
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

// ThreatChange adds a threat to the threats: section, or changes its action.
type ThreatChange struct {
	Name   string // as the policy names it, lower case: prompt_injection
	Action Action // alert | block | allow
	Note   string
}

var reTopThreats = regexp.MustCompile(`^threats:\s*(#.*)?$`)

// EnableThreats adds or changes rules in the top-level threats: section, as
// text, like EnableEntities. A missing section is opened before audit:, or at
// the end of the file.
func EnableThreats(src []byte, changes []ThreatChange) ([]byte, EditResult, error) {
	var res EditResult
	crlf := bytes.Contains(src, []byte("\r\n"))
	lines := strings.Split(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n")
	at := -1
	for i, l := range lines {
		if reTopThreats.MatchString(l) {
			at = i
			break
		}
		if strings.HasPrefix(l, "threats:") {
			return nil, res, fmt.Errorf("the threats: section is written on one line; turn it into one rule per line, then run this command again")
		}
	}
	if at < 0 {
		insertAt := len(lines)
		for len(lines) > 0 && insertAt == len(lines) && lines[len(lines)-1] == "" {
			break
		}
		for i, l := range lines {
			if strings.HasPrefix(l, "audit:") {
				insertAt = i
				break
			}
		}
		block := []string{"# Threats in untrusted text (user turns, tool results): alert | block | allow.", "threats:"}
		if insertAt == len(lines) {
			if insertAt > 0 && lines[insertAt-1] == "" {
				insertAt--
			}
			block = append([]string{""}, block...)
		} else {
			block = append(block, "")
		}
		lines = append(lines[:insertAt], append(block, lines[insertAt:]...)...)
		at = insertAt + len(block) - 1
		if block[len(block)-1] == "" {
			at--
		}
	}
	last, rules := at, map[string]int{}
	for i := at + 1; i < len(lines); i++ {
		l := lines[i]
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		if l[0] != ' ' {
			break
		}
		last = i
		if m := reRuleLine.FindStringSubmatch(l); m != nil {
			rules[m[2]] = i
		} else if !strings.HasPrefix(t, "#") && len(l)-len(strings.TrimLeft(l, " ")) == 2 {
			rules[strings.TrimSuffix(strings.Fields(t)[0], ":")] = -1
		}
	}
	var insert []string
	for _, c := range changes {
		name := strings.ToLower(strings.TrimSpace(c.Name))
		switch c.Action {
		case Alert, Block, Allow:
		default:
			return nil, res, fmt.Errorf("%s: a threat's action is alert, block, or allow, not %q", name, c.Action)
		}
		i, exists := rules[name]
		switch {
		case exists && i < 0:
			return nil, res, fmt.Errorf("threats.%s is written on several lines; change it by hand", name)
		case exists:
			m := reRuleLine.FindStringSubmatch(lines[i])
			fields := parseFlow(m[4])
			before := renderFlow(fields)
			fields["action"] = string(c.Action)
			if renderFlow(fields) == before {
				res.Unchanged = append(res.Unchanged, name)
				continue
			}
			lines[i] = m[1] + name + ":" + m[3] + renderFlow(fields) + m[5]
			res.Changed = append(res.Changed, strings.TrimSpace(lines[i]))
		default:
			line := "  " + name + ": " + renderFlow(map[string]string{"action": string(c.Action)})
			if c.Note != "" {
				line += "   # " + c.Note
			}
			insert = append(insert, line)
			res.Added = append(res.Added, strings.TrimSpace(line))
			rules[name] = 0
		}
	}
	if len(insert) > 0 {
		lines = append(lines[:last+1], append(insert, lines[last+1:]...)...)
	}
	out := strings.Join(lines, "\n")
	if crlf {
		out = strings.ReplaceAll(out, "\n", "\r\n")
	}
	if _, err := Parse([]byte(out), "policy.yaml"); err != nil {
		return nil, res, fmt.Errorf("the edited policy would not load, so nothing was changed: %w", err)
	}
	return []byte(out), res, nil
}
