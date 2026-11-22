package policy

import (
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"testing"
)

// docsWithErrors stands for a document store that fails now and then, such
// as a database that does not answer for a moment.
type docsWithErrors struct {
	org            []byte
	levels         []LevelFile
	failOrg, failL bool
	sig            int
}

func (d *docsWithErrors) Base() string                     { return "policy.yaml" }
func (d *docsWithErrors) Where(id string) string           { return id }
func (d *docsWithErrors) Put(string, []byte, string) error { return nil }
func (d *docsWithErrors) Delete(string, string) error      { return nil }
func (d *docsWithErrors) Signature() string                { return strconv.Itoa(d.sig) }
func (d *docsWithErrors) Get(id string) ([]byte, error) {
	if id != OrgDoc {
		return nil, fs.ErrNotExist
	}
	if d.failOrg {
		return nil, errors.New("no answer")
	}
	return d.org, nil
}
func (d *docsWithErrors) Levels() ([]LevelFile, []string, error) {
	if d.failL {
		return nil, nil, errors.New("no answer")
	}
	return d.levels, nil, nil
}

// A read error during a reload is tried again at the next tick, and a team's
// effective policy never stays merged with an organization policy that is no
// longer in force.
func TestReloadAfterAReadError(t *testing.T) {
	d := &docsWithErrors{org: []byte(orgPolicy), levels: []LevelFile{level("team", "finance", "audit:\n  retention_days: 7\n")}}
	h, err := NewHolderFrom(d)
	if err != nil {
		t.Fatal(err)
	}
	h.OnError = func(error) {}
	if h.For("finance", "", "").ActionFor("EMAIL") != Allow {
		t.Fatal("setup")
	}
	tightened := []byte(strings.Replace(orgPolicy, "EMAIL:       { action: allow }", "EMAIL:       { action: block }", 1))

	// The organization's policy cannot be read once: the next tick reads it.
	d.org, d.failOrg, d.sig = tightened, true, d.sig+1
	h.Reload()
	d.failOrg = false
	h.Reload()
	if h.Current().ActionFor("EMAIL") != Block || h.For("finance", "", "").ActionFor("EMAIL") != Block {
		t.Fatalf("org %s, team %s", h.Current().ActionFor("EMAIL"), h.For("finance", "", "").ActionFor("EMAIL"))
	}

	// The level files cannot be read: the team's policy follows the
	// organization's new one at once, and the files are read again later.
	d.org, d.failL, d.sig = []byte(orgPolicy), true, d.sig+1
	h.Reload()
	if h.For("finance", "", "").ActionFor("EMAIL") != Allow {
		t.Fatalf("team %s", h.For("finance", "", "").ActionFor("EMAIL"))
	}
	d.failL = false
	d.levels = []LevelFile{level("team", "finance", "data:\n  entities:\n    EMAIL: { action: block }\n")}
	h.Reload()
	if h.For("finance", "", "").ActionFor("EMAIL") != Block {
		t.Fatal("the level files were not read again")
	}

	// An invalid edit is rejected once and not read again until it changes.
	errs := 0
	h.OnError = func(error) { errs++ }
	d.org, d.sig = []byte("mode: sometimes\n"), d.sig+1
	h.Reload()
	h.Reload()
	if errs != 1 || h.Current().ActionFor("EMAIL") != Allow {
		t.Fatalf("%d errors", errs)
	}
}

func TestExactCacheScopes(t *testing.T) {
	for _, s := range []string{"org", "team", "project", "key"} {
		if _, err := Parse([]byte(strings.Replace(orgPolicy, "exact: { enabled: true, ttl: 30d }", "exact: { enabled: true, ttl: 30d, scope: "+s+" }", 1)), "p.yaml"); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if _, err := Parse([]byte(strings.Replace(orgPolicy, "exact: { enabled: true, ttl: 30d }", "exact: { scope: department }", 1)), "p.yaml"); err == nil {
		t.Fatal("an unknown scope must be refused")
	}
}
