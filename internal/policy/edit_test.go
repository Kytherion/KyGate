package policy

import (
	"strings"
	"testing"
)

// The data: block exactly as a user has it today (from the starter policy).
const userData = `kind: Policy
scope: org
mode: enforce

data:
  # One action per data type: allow | mask | redact | block | local_only | alert
  entities:
    SECRET:      { action: block }   # API keys, tokens, private keys
    CREDIT_CARD: { action: mask }    # payment card numbers that pass the Luhn check
    IBAN:        { action: mask }    # bank account numbers that pass the mod-97 check
    EMAIL:       { action: allow }   # counted in the console, sent unchanged

  # Company dictionaries. Uncomment, then reference them in entities as dict/<name>.
  # dictionaries:
  #   project-codenames:
  #     terms: [Apollo, Hyperion]
  unreadable_content: local_only
  embeddings: block

cache:
  exact:
    enabled: true
`

func TestEnableAddsAfterTheLastRuleAndKeepsEverythingElse(t *testing.T) {
	out, res, err := EnableEntities([]byte(userData), []EntityChange{
		{Type: "PERSON", Action: Alert, Note: "added by kygate policy enable"},
		{Type: "ADDRESS", Action: Alert},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(userData, "    EMAIL:       { action: allow }   # counted in the console, sent unchanged\n",
		"    EMAIL:       { action: allow }   # counted in the console, sent unchanged\n"+
			"    PERSON:      { action: alert }   # added by kygate policy enable\n"+
			"    ADDRESS:     { action: alert }\n", 1)
	if string(out) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
	if len(res.Added) != 2 || len(res.Changed) != 0 {
		t.Fatalf("%+v", res)
	}
	p, err := Parse(out, "x.yaml")
	if err != nil || p.Data.Entities["PERSON"].Action != Alert {
		t.Fatalf("%v %+v", err, p.Data.Entities)
	}
}

func TestEnableChangesARuleInPlace(t *testing.T) {
	first, _, _ := EnableEntities([]byte(userData), []EntityChange{{Type: "PERSON", Action: Alert}})
	out, res, err := EnableEntities(first, []EntityChange{{Type: "PERSON", Action: Mask, Detection: "model"}, {Type: "IBAN", Action: Mask}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "    PERSON:      { action: mask, detection: model }\n") {
		t.Fatalf("%s", out)
	}
	if len(res.Changed) != 1 || len(res.Unchanged) != 1 || res.Unchanged[0] != "IBAN" {
		t.Fatalf("%+v", res)
	}
	// The comment of a changed line stays.
	out, _, _ = EnableEntities(out, []EntityChange{{Type: "EMAIL", Action: Mask}})
	if !strings.Contains(string(out), "    EMAIL:       { action: mask }   # counted in the console, sent unchanged\n") {
		t.Fatalf("%s", out)
	}
	// detection: any removes the requirement.
	out, _, _ = EnableEntities(out, []EntityChange{{Type: "PERSON", Action: Mask, Detection: "any"}})
	if !strings.Contains(string(out), "    PERSON:      { action: mask }\n") {
		t.Fatalf("%s", out)
	}
}

func TestEnableKeepsWindowsLineEnds(t *testing.T) {
	crlf := strings.ReplaceAll(userData, "\n", "\r\n")
	out, _, err := EnableEntities([]byte(crlf), []EntityChange{{Type: "PHONE", Action: Alert}})
	if err != nil || strings.Count(string(out), "\r\n") != strings.Count(crlf, "\r\n")+1 || strings.Contains(strings.ReplaceAll(string(out), "\r\n", ""), "\n") {
		t.Fatalf("%v\n%q", err, out)
	}
}

func TestEnableOpensAnEntitiesBlock(t *testing.T) {
	src := "data:\n  unreadable_content: block\n"
	out, _, err := EnableEntities([]byte(src), []EntityChange{{Type: "PERSON", Action: Mask}})
	if err != nil || string(out) != "data:\n  entities:\n    PERSON:      { action: mask }\n  unreadable_content: block\n" {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestEnableRefusesWhatItCannotDoSafely(t *testing.T) {
	multi := strings.Replace(userData, "    EMAIL:       { action: allow }   # counted in the console, sent unchanged\n", "    EMAIL:\n      action: allow\n", 1)
	if _, _, err := EnableEntities([]byte(multi), []EntityChange{{Type: "EMAIL", Action: Mask}}); err == nil || !strings.Contains(err.Error(), "several lines") {
		t.Fatalf("a rule on several lines must be left to the owner: %v", err)
	}
	if _, _, err := EnableEntities([]byte(userData), []EntityChange{{Type: "PERSON", Action: "erase"}}); err == nil {
		t.Fatal("an unknown action is an error")
	}
	// An edit that would not load is refused: detection: model on a dictionary.
	if _, _, err := EnableEntities([]byte(userData), []EntityChange{{Type: "dict/x", Action: Mask, Detection: "model"}}); err == nil || !strings.Contains(err.Error(), "would not load") {
		t.Fatalf("got %v", err)
	}
	if _, _, err := EnableEntities([]byte("kind: Policy\n"), []EntityChange{{Type: "PERSON", Action: Mask}}); err == nil {
		t.Fatal("no data: section")
	}
}

func TestEnableTwiceChangesNothing(t *testing.T) {
	once, _, _ := EnableEntities([]byte(userData), []EntityChange{{Type: "PERSON", Action: Alert}})
	twice, res, err := EnableEntities(once, []EntityChange{{Type: "PERSON", Action: Alert}})
	if err != nil || string(once) != string(twice) || len(res.Unchanged) != 1 {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestEnableThreats(t *testing.T) {
	out, res, err := EnableThreats([]byte(userData+"\naudit:\n  retention_days: 90\n"), []ThreatChange{{Name: "prompt_injection", Action: Alert}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "    enabled: true\n\n# Threats in untrusted text (user turns, tool results): alert | block | allow.\nthreats:\n  prompt_injection: { action: alert }\n\naudit:\n") {
		t.Fatalf("the section goes right before audit:\n%s", out)
	}
	if len(res.Added) != 1 {
		t.Fatalf("%+v", res)
	}
	p, err := Parse(out, "x.yaml")
	if err != nil || strings.Join(p.GuardThreats(), ",") != "PROMPT_INJECTION" {
		t.Fatalf("%v %v", err, p.GuardThreats())
	}
	out2, res, err := EnableThreats(out, []ThreatChange{{Name: "prompt_injection", Action: Block}})
	if err != nil || !strings.Contains(string(out2), "\n  prompt_injection: { action: block }\n") || len(res.Changed) != 1 {
		t.Fatalf("%v %+v\n%s", err, res, out2)
	}
	if again, res, _ := EnableThreats(out2, []ThreatChange{{Name: "prompt_injection", Action: Block}}); string(again) != string(out2) || len(res.Unchanged) != 1 {
		t.Fatal("the same change twice changes nothing")
	}
	// No audit: section: at the end of the file.
	end, _, err := EnableThreats([]byte("data:\n  unreadable_content: block\n"), []ThreatChange{{Name: "prompt_injection", Action: Alert}})
	if err != nil || !strings.HasSuffix(string(end), "\nthreats:\n  prompt_injection: { action: alert }\n") {
		t.Fatalf("%v\n%q", err, end)
	}
	if _, _, err := EnableThreats([]byte(userData), []ThreatChange{{Name: "prompt_injection", Action: Mask}}); err == nil {
		t.Fatal("mask is not a threat action")
	}
}
