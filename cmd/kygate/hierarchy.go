package main

// The hierarchy on the command line (AC-4): teams, projects, and
// where keys sit, plus the effective policy of a key. Like the other
// management commands, these work on an existing data directory, and a running
// KyGate picks the change up within a few seconds. Each change is recorded in
// the audit trail of administration.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Kytherion/KyGate/internal/identity"
	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store"
)

var hierNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func checkName(kind, name string) error {
	if !hierNameRe.MatchString(name) {
		return fmt.Errorf("a %s name is 1 to 64 letters, digits, dots, dashes, or underscores, starting with a letter or digit", kind)
	}
	return nil
}

func recordCLI(ctx context.Context, db store.ConfigStore, action, target, detail string) {
	db.RecordAdmin(ctx, store.AdminAction{Time: time.Now(), Actor: "command line", Action: action, Target: target, Detail: detail})
}

func openOrg(c *common) (store.Database, string, error) {
	db, err := c.openExisting()
	if err != nil {
		return nil, "", err
	}
	org, err := db.Meta(context.Background(), "org_id")
	if err != nil {
		db.Close()
		return nil, "", errors.New("this data directory is not set up yet: run 'kygate serve' once")
	}
	return db, org, nil
}

func findTeam(ctx context.Context, db store.ConfigStore, name string) (store.Team, error) {
	ts, err := db.ListTeams(ctx)
	if err != nil {
		return store.Team{}, err
	}
	for _, t := range ts {
		if t.Name == name {
			return t, nil
		}
	}
	return store.Team{}, fmt.Errorf("no team named %q ('kygate team list')", name)
}

func findProject(ctx context.Context, db store.ConfigStore, name string) (store.Project, error) {
	ps, err := db.ListProjects(ctx)
	if err != nil {
		return store.Project{}, err
	}
	for _, p := range ps {
		if p.Name == name {
			return p, nil
		}
	}
	return store.Project{}, fmt.Errorf("no project named %q ('kygate project list')", name)
}

func teamCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kygate team create NAME | team list | team delete NAME")
	}
	var c common
	fs := flag.NewFlagSet("team", flag.ExitOnError)
	c.register(fs)
	pos := parse(fs, args[1:])
	ctx := context.Background()
	db, org, err := openOrg(&c)
	if err != nil {
		return err
	}
	defer db.Close()
	switch args[0] {
	case "create":
		if len(pos) != 1 {
			return errors.New("usage: kygate team create NAME")
		}
		if err := checkName("team", pos[0]); err != nil {
			return err
		}
		if err := db.CreateTeam(ctx, store.Team{ID: identity.NewID("team_"), Name: pos[0], OrgID: org, CreatedAt: time.Now()}); err != nil {
			return err
		}
		recordCLI(ctx, db, "team.create", pos[0], "")
		fmt.Printf("Created team %q. Its policy, if any, goes in %s.\n", pos[0], filepath.Join(c.dataDir, policy.LevelsDir, "team-"+pos[0]+".yaml"))
	case "list":
		ts, err := db.ListTeams(ctx)
		if err != nil {
			return err
		}
		ps, _ := db.ListProjects(ctx)
		tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "TEAM\tPROJECTS\tCREATED")
		for _, t := range ts {
			var names []string
			for _, p := range ps {
				if p.TeamID == t.ID {
					names = append(names, p.Name)
				}
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", t.Name, strings.Join(names, ", "), t.CreatedAt.Format("2006-01-02 15:04"))
		}
		tw.Flush()
	case "delete":
		if len(pos) != 1 {
			return errors.New("usage: kygate team delete NAME")
		}
		ok, err := db.DeleteTeam(ctx, pos[0])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no team named %q", pos[0])
		}
		recordCLI(ctx, db, "team.delete", pos[0], "")
		fmt.Println("Deleted.")
	default:
		return fmt.Errorf("unknown team command %q", args[0])
	}
	return nil
}

func projectCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kygate project create NAME [--team TEAM] | project list | project delete NAME")
	}
	var c common
	fs := flag.NewFlagSet("project", flag.ExitOnError)
	c.register(fs)
	team := fs.String("team", "", "the team the project belongs to; none: directly under the organization")
	pos := parse(fs, args[1:])
	ctx := context.Background()
	db, org, err := openOrg(&c)
	if err != nil {
		return err
	}
	defer db.Close()
	switch args[0] {
	case "create":
		if len(pos) != 1 {
			return errors.New("usage: kygate project create NAME [--team TEAM]")
		}
		if err := checkName("project", pos[0]); err != nil {
			return err
		}
		p := store.Project{ID: identity.NewID("proj_"), Name: pos[0], OrgID: org, CreatedAt: time.Now()}
		if *team != "" {
			t, err := findTeam(ctx, db, *team)
			if err != nil {
				return err
			}
			p.TeamID = t.ID
		}
		if err := db.CreateProject(ctx, p); err != nil {
			return err
		}
		recordCLI(ctx, db, "project.create", pos[0], "team "+orNone(*team))
		fmt.Printf("Created project %q. Put keys in it with 'kygate key create NAME --project %s' or 'kygate key move NAME --project %s'.\n", pos[0], pos[0], pos[0])
	case "list":
		ps, err := db.ListProjects(ctx)
		if err != nil {
			return err
		}
		ts, _ := db.ListTeams(ctx)
		ks, _ := db.ListKeys(ctx)
		teams := map[string]string{}
		for _, t := range ts {
			teams[t.ID] = t.Name
		}
		tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "PROJECT\tTEAM\tACTIVE KEYS")
		for _, p := range ps {
			var names []string
			for _, k := range ks {
				if k.ProjectID == p.ID && k.RevokedAt == nil {
					names = append(names, k.Name)
				}
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", p.Name, orNone(teams[p.TeamID]), strings.Join(names, ", "))
		}
		tw.Flush()
	case "delete":
		if len(pos) != 1 {
			return errors.New("usage: kygate project delete NAME")
		}
		ok, err := db.DeleteProject(ctx, pos[0])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no project named %q", pos[0])
		}
		recordCLI(ctx, db, "project.delete", pos[0], "")
		fmt.Println("Deleted.")
	default:
		return fmt.Errorf("unknown project command %q", args[0])
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// policyShow prints the effective policy of a key: the organization's merged
// with its team's, project's, and key's files.
func policyShow(args []string) error {
	var c common
	fs := flag.NewFlagSet("policy show", flag.ExitOnError)
	c.register(fs)
	keyName := fs.String("key", "", "the virtual key whose effective policy to show")
	parse(fs, args)
	if *keyName == "" {
		return errors.New("usage: kygate policy show --key NAME")
	}
	ctx := context.Background()
	db, _, err := openOrg(&c)
	if err != nil {
		return err
	}
	defer db.Close()
	ks, err := db.ListKeys(ctx)
	if err != nil {
		return err
	}
	var key *store.VirtualKey
	for i := range ks {
		if ks[i].Name == *keyName {
			key = &ks[i]
		}
	}
	if key == nil {
		return fmt.Errorf("no key named %q", *keyName)
	}
	team, project := "", ""
	if key.ProjectID != "" {
		ps, _ := db.ListProjects(ctx)
		ts, _ := db.ListTeams(ctx)
		for _, p := range ps {
			if p.ID == key.ProjectID {
				project = p.Name
				for _, t := range ts {
					if t.ID == p.TeamID {
						team = t.Name
					}
				}
			}
		}
	}
	path := c.policyDocs(db).Where(policy.OrgDoc)
	h, err := policy.NewHolderFrom(c.policyDocs(db))
	if err != nil {
		return err
	}
	var errs []string
	h.OnError = func(e error) { errs = append(errs, e.Error()) }
	h.Reload()
	p := h.For(team, project, *keyName)
	fmt.Printf("Key %q: team %s, project %s\n", *keyName, orNone(team), orNone(project))
	var used []string
	for _, lf := range h.Levels() {
		if (lf.Kind == "team" && lf.Name == team) || (lf.Kind == "project" && lf.Name == project) || (lf.Kind == "key" && lf.Name == *keyName) {
			used = append(used, filepath.Base(lf.Path))
		}
	}
	fmt.Printf("Policy files: %s%s\n", path, strings.Join(append([]string{""}, used...), " + "))
	fmt.Printf("Effective version %s, %s mode\n", p.Version, p.Mode)
	for _, w := range append(errs, p.Warnings...) {
		fmt.Println("  note:", w)
	}
	summary := map[string]any{
		"data":        map[string]any{"on_guard_unavailable": p.Data.OnGuardUnavailable, "entities": p.Data.Entities, "unreadable_content": p.Data.UnreadableContent, "embeddings": p.Data.Embeddings},
		"threats":     p.Threats,
		"output":      p.Output,
		"routing":     p.Route,
		"budgets":     p.Budget,
		"rate_limits": p.RateLimits,
	}
	out, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Println()
	fmt.Println(string(out))
	return nil
}
