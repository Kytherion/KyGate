package detect

import "testing"

func types(fs []Finding, text string) map[string][]string {
	out := map[string][]string{}
	for _, f := range fs {
		out[f.Type] = append(out[f.Type], text[f.Start:f.End])
	}
	return out
}

func TestScan(t *testing.T) {
	s := NewSet([]Dictionary{{Name: "codenames", Terms: []string{"Apollo", "Project Hyperion"}}})
	cases := []struct {
		text string
		want map[string]string // type -> first match
		none []string
	}{
		{"pay with 4111 1111 1111 1111 today", map[string]string{"CREDIT_CARD": "4111 1111 1111 1111"}, nil},
		{"card 4111-1111-1111-1112 fails luhn", nil, []string{"CREDIT_CARD"}},
		{"order 1234567890123 is not a card", nil, []string{"CREDIT_CARD"}},
		{"IBAN DE89 3704 0044 0532 0130 00 please", map[string]string{"IBAN": "DE89 3704 0044 0532 0130 00"}, nil},
		{"GB82WEST12345698765432", map[string]string{"IBAN": "GB82WEST12345698765432"}, nil},
		{"DE00370400440532013000 bad checksum", nil, []string{"IBAN"}},
		{"key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789", map[string]string{"SECRET": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"}, nil},
		{"aws AKIAIOSFODNN7EXAMPLE x", map[string]string{"SECRET": "AKIAIOSFODNN7EXAMPLE"}, nil},
		{"mail alice.martin@example.com now", map[string]string{"EMAIL": "alice.martin@example.com"}, nil},
		{"the apollo launch and Project Hyperion", map[string]string{"dict/codenames": "apollo"}, nil},
		{"Apollonia is a name", nil, []string{"dict/codenames"}},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----", map[string]string{"SECRET": "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"}, nil},
	}
	for _, c := range cases {
		got := types(s.Scan(0, c.text), c.text)
		for typ, first := range c.want {
			if len(got[typ]) == 0 || got[typ][0] != first {
				t.Errorf("%q: want %s %q, got %v", c.text, typ, first, got)
			}
		}
		for _, typ := range c.none {
			if len(got[typ]) > 0 {
				t.Errorf("%q: want no %s, got %v", c.text, typ, got[typ])
			}
		}
	}
}

func TestMergeOverlap(t *testing.T) {
	// An API key inside an email-like string: the secret wins.
	in := []Finding{
		{Type: "EMAIL", Start: 0, End: 30},
		{Type: "SECRET", Start: 5, End: 25},
	}
	out := Merge(in)
	if len(out) != 1 || out[0].Type != "SECRET" {
		t.Fatalf("got %+v", out)
	}
}
