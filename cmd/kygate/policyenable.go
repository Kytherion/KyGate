package main

// 'kygate policy enable' turns on data types in the policy file, with the
// owner's consent: it shows the exact lines, asks, keeps a backup, edits the
// file as text so every comment stays, and refuses an edit that would not load
//. Its default action is alert, which counts the
// values in the console and changes nothing in prompts: measure first, then
// switch to mask.
//
//	kygate policy enable --list
//	kygate policy enable PERSON ADDRESS PHONE                 # action alert
//	kygate policy enable PERSON ADDRESS PHONE --action mask
//	kygate policy enable PERSON --action mask --require-model
//	kygate policy enable PROMPT_INJECTION                       # a threat: alert, then --action block

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/Kytherion/KyGate/internal/detect/guard"
	"github.com/Kytherion/KyGate/internal/policy"
)

func policyEnable(args []string) error {
	var c common
	fs := flag.NewFlagSet("policy enable", flag.ExitOnError)
	c.register(fs)
	action := fs.String("action", "alert", "alert (count in the console, change nothing) | mask | redact | block | local_only | allow; for a threat: alert | block | allow")
	requireModel := fs.Bool("require-model", false, "require a model for these types (detection: model): a list never stands in for one")
	anyLevel := fs.Bool("any-level", false, "remove a model requirement (detection: any)")
	guardAddr := fs.String("guard", "", "the Guard to ask which level finds each type (default: KYGATE_GUARD, or the background service's Guard)")
	list := fs.Bool("list", false, "list the types the Guard finds and what the policy does with each")
	yes := fs.Bool("yes", false, "do not ask before writing")
	types := parse(fs, args)
	docs, closeDocs, err := c.cliPolicyDocs()
	if err != nil {
		return err
	}
	defer closeDocs()
	base, path := docs.Base(), docs.Where(policy.OrgDoc)
	src, err := docs.Get(policy.OrgDoc)
	if err != nil {
		return err
	}
	pol, err := policy.Parse(src, base)
	if err != nil {
		return fmt.Errorf("%w\n(fix the file first: 'kygate policy check')", err)
	}

	addr, from := *guardAddr, "--guard"
	if addr == "" {
		addr, from = os.Getenv("KYGATE_GUARD"), "KYGATE_GUARD"
	}
	if addr == "" {
		if dd, err := filepath.Abs(c.dataDir); err == nil {
			if cfg, err := loadServiceConfig(dd); err == nil && cfg.GuardAddr != "" {
				addr, from = cfg.GuardAddr, "the background service"
			}
		}
	}
	levels, threatSet, guardErr := guardCoverage(addr)

	if *list {
		return printEnableList(pol, addr, levels, threatSet, guardErr)
	}
	if len(types) == 0 {
		return errors.New("name the data types to turn on, such as: kygate policy enable PERSON ADDRESS PHONE\n(kygate policy enable --list shows the types the Guard finds)")
	}
	act := policy.Action(*action)
	detection := ""
	switch {
	case *requireModel && *anyLevel:
		return errors.New("--require-model and --any-level contradict each other")
	case *requireModel:
		detection = "model"
	case *anyLevel:
		detection = "any"
	}

	var changes []policy.EntityChange
	var threatChanges []policy.ThreatChange
	var warnings []string
	for _, t := range types {
		t = strings.ToUpper(strings.TrimSpace(t))
		if strings.HasPrefix(strings.ToLower(t), "dict/") {
			t = "dict/" + t[5:] // dictionary names keep their case
		}
		if threatSet[t] || knownThreats[t] {
			switch act {
			case policy.Alert, policy.Block, policy.Allow:
			default:
				return fmt.Errorf("%s is a threat: its action is alert, block, or allow, not %s", t, act)
			}
			if detection != "" {
				return fmt.Errorf("%s is a threat: --require-model and --any-level apply to data types only", t)
			}
			threatChanges = append(threatChanges, policy.ThreatChange{Name: strings.ToLower(t), Action: act, Note: "added by 'kygate policy enable'"})
			if guardErr == nil && levels[t] == "" {
				warnings = append(warnings, fmt.Sprintf("%s: the Guard at %s has no detector for this threat; requests will follow on_guard_unavailable (%s) until one is installed ('kygate-guard models pull prompt-injection')", t, addr, pol.Data.OnGuardUnavailable))
			}
			continue
		}
		changes = append(changes, policy.EntityChange{Type: t, Action: act, Detection: detection, Note: "added by 'kygate policy enable'"})
		fast := false
		for _, k := range policy.KnownEntities {
			fast = fast || k == t
		}
		switch {
		case fast && detection != "model", strings.HasPrefix(t, "dict/"):
		case guardErr != nil:
		case levels[t] == "":
			warnings = append(warnings, fmt.Sprintf("%s: the Guard at %s does not find this type; while it does not, requests follow on_guard_unavailable (%s)", t, addr, pol.Data.OnGuardUnavailable))
		case detection == "model" && levels[t] != "model":
			warnings = append(warnings, fmt.Sprintf("%s: the Guard has only a list for this type, and you require a model: requests will be refused until a model pack finds it", t))
		case levels[t] == "list":
			warnings = append(warnings, fmt.Sprintf("%s: the Guard finds it with a list only: values that are not listed are not found", t))
		}
	}
	out, res := src, policy.EditResult{}
	if len(changes) > 0 {
		if out, res, err = policy.EnableEntities(src, changes); err != nil {
			return err
		}
	}
	if len(threatChanges) > 0 {
		var tres policy.EditResult
		if out, tres, err = policy.EnableThreats(out, threatChanges); err != nil {
			return err
		}
		res.Added = append(res.Added, tres.Added...)
		res.Changed = append(res.Changed, tres.Changed...)
		res.Unchanged = append(res.Unchanged, tres.Unchanged...)
	}
	next, _ := policy.Parse(out, base)

	fmt.Printf("Policy: %s\n", path)
	for _, l := range res.Added {
		fmt.Printf("  + %s\n", l)
	}
	for _, l := range res.Changed {
		fmt.Printf("  ~ %s\n", l)
	}
	for _, t := range res.Unchanged {
		fmt.Printf("  = %s is already set so\n", t)
	}
	if len(res.Added)+len(res.Changed) == 0 {
		fmt.Println("Nothing to change.")
		return nil
	}
	if next.NeedsGuard() {
		switch {
		case addr == "":
			warnings = append(warnings, fmt.Sprintf("the policy will need the Guard for %s, and no Guard is configured here. Until KyGate runs with one (--guard, or 'kygate service install --guard-exe'), requests follow on_guard_unavailable: %s", strings.Join(append(next.GuardEntities(), next.GuardThreats()...), ", "), describeOnUnavailable(next.Data.OnGuardUnavailable)))
		case guardErr != nil:
			warnings = append(warnings, fmt.Sprintf("the Guard at %s (from %s) does not answer now (%v). While it does not, requests that need it follow on_guard_unavailable: %s", addr, from, guardErr, describeOnUnavailable(next.Data.OnGuardUnavailable)))
		}
	}
	for _, w := range warnings {
		fmt.Printf("  warning: %s\n", w)
	}
	switch act {
	case policy.Alert:
		if len(changes) > 0 {
			fmt.Println("\nWith action alert, these values are counted in the console and sent unchanged: nothing in your prompts changes.")
		}
		if len(threatChanges) > 0 {
			fmt.Println("\nWith action alert, a request that looks like this threat is counted in the console and still sent to the model; its answer is never cached.")
		}
	case policy.Mask:
		fmt.Println("\nWith action mask, the model sees a placeholder such as [PERSON_1] instead of each value, and your answer gets the real value back.")
	case policy.Block:
		if len(threatChanges) > 0 {
			fmt.Println("\nWith action block, a request whose user turn or tool result looks like this threat is refused (403) before it reaches the model.")
		}
	}
	if !*yes {
		fmt.Print("Write these changes? [y/N] ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" && a != "o" && a != "oui" {
			return errors.New("nothing was changed")
		}
	}
	if err := docs.Put(policy.OrgDoc, out, "command line"); err != nil {
		return err
	}
	fmt.Println("Written; the previous version is kept (a .bak file, or the database's history). A running KyGate uses the new policy within a few seconds.")
	if act == policy.Alert {
		var names []string
		for _, ch := range changes {
			names = append(names, ch.Type)
		}
		for _, ch := range threatChanges {
			names = append(names, strings.ToUpper(ch.Name))
		}
		var entityNames, threatNames []string
		for _, n := range names {
			if threatSet[n] || knownThreats[n] {
				threatNames = append(threatNames, n)
			} else {
				entityNames = append(entityNames, n)
			}
		}
		fmt.Println("Next: watch the console (Protection page, and Alerts on Overview). When the counts look right:")
		if len(entityNames) > 0 {
			fmt.Printf("  kygate policy enable %s --action mask\n", strings.Join(entityNames, " "))
		}
		if len(threatNames) > 0 {
			fmt.Printf("  kygate policy enable %s --action block\n", strings.Join(threatNames, " "))
		}
	}
	return nil
}

// knownThreats are the threats KyGate knows by name, even without a Guard to ask.
var knownThreats = map[string]bool{"PROMPT_INJECTION": true}

// guardCoverage asks a Guard which level finds each data type and threat, and
// which of them are threats.
func guardCoverage(addr string) (map[string]string, map[string]bool, error) {
	if addr == "" {
		return nil, nil, errors.New("no Guard is configured")
	}
	gd, err := guard.Dial(addr)
	if err != nil {
		return nil, nil, err
	}
	defer gd.Close()
	if _, err := gd.Info(context.Background()); err != nil {
		return nil, nil, err
	}
	levels, _ := gd.Levels()
	threats := map[string]bool{}
	for _, t := range gd.State().ThreatTypes {
		threats[t] = true
	}
	return levels, threats, nil
}

func printEnableList(pol *policy.Policy, addr string, levels map[string]string, threats map[string]bool, guardErr error) error {
	if guardErr != nil {
		if addr == "" {
			return errors.New("no Guard is configured: pass --guard ADDR, set KYGATE_GUARD, or run the Guard with the background service")
		}
		return fmt.Errorf("the Guard at %s does not answer: %w", addr, guardErr)
	}
	names := make([]string, 0, len(levels))
	var threatNames []string
	for t := range levels {
		if threats[t] {
			threatNames = append(threatNames, t)
		} else {
			names = append(names, t)
		}
	}
	sort.Strings(names)
	sort.Strings(threatNames)
	if len(threatNames) > 0 {
		fmt.Printf("Threats the Guard at %s detects, in user turns and tool results:\n", addr)
		tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		for _, t := range threatNames {
			rule := "not in the policy"
			if r, ok := pol.ThreatRuleFor(t); ok {
				rule = fmt.Sprintf("%s from score %.2f, in %s", r.Action, r.MinScore, strings.Join(r.Segments, " and "))
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", t, levels[t], rule)
		}
		tw.Flush()
		fmt.Println()
	}
	fmt.Printf("Types the Guard at %s finds, and what the policy does with each:\n", addr)
	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	for _, t := range names {
		rule := "not in the policy"
		if r, ok := pol.Data.Entities[t]; ok {
			rule = string(r.Action)
			if r.Detection == "model" {
				rule += ", requires a model"
			}
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", t, levels[t], rule)
	}
	tw.Flush()
	fmt.Println("\nTurn types on with: kygate policy enable TYPE... (action alert first, then --action mask; for a threat, --action block)")
	return nil
}

func describeOnUnavailable(v string) string {
	switch v {
	case "local_only":
		return "local_only, so they may go to local models only"
	case "fast_detectors_only":
		return "fast_detectors_only, so they go out with the fast detectors' masking alone, flagged"
	}
	return "block, so they are refused"
}
