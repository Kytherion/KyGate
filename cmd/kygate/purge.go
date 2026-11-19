package main

// kygate purge (GV-4): deletes events, captured payloads, or cache
// entries. It shows what it will delete and asks first (--yes skips the
// question). Each purge is recorded in the administration trail. A cache
// purge is also recorded for running KyGate processes, which apply it to
// their own memory within seconds.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Kytherion/KyGate/internal/control"
	"github.com/Kytherion/KyGate/internal/store"
	"github.com/Kytherion/KyGate/internal/store/sqlite"
	"github.com/Kytherion/KyGate/internal/store/valkey"
)

func purgeCmd(args []string) error {
	if len(args) == 0 || (args[0] != "events" && args[0] != "cache") {
		return errors.New("usage: kygate purge events [--key K] [--team T] [--project P] [--user ID] [--from DATE] [--to DATE] [--payloads-only] [--yes]\n" +
			"       kygate purge cache --key K | --tag T | --all [--cache-url URL] [--yes]")
	}
	var c common
	fs := flag.NewFlagSet("purge", flag.ExitOnError)
	c.register(fs)
	key := fs.String("key", "", "a virtual key, by name")
	yes := fs.Bool("yes", false, "do not ask before deleting")
	if args[0] == "events" {
		team := fs.String("team", "", "a team, by name")
		project := fs.String("project", "", "a project, by name")
		user := fs.String("user", "", "a person, by the ID their user tokens carry (such as an email address) or by pseudonym (u_...)")
		from := fs.String("from", "", "from this date (YYYY-MM-DD, UTC) or time (RFC 3339)")
		to := fs.String("to", "", "before this date or time")
		payloads := fs.Bool("payloads-only", false, "delete the captured masked payloads only, and keep the events (reports stay whole)")
		parse(fs, args[1:])
		e := control.EventPurge{Key: *key, Team: *team, Project: *project, User: *user, PayloadsOnly: *payloads}
		var err error
		if e.From, err = parseWhen(*from); err != nil {
			return err
		}
		if e.To, err = parseWhen(*to); err != nil {
			return err
		}
		return purgeEvents(c, e, *yes)
	}
	tag := fs.String("tag", "", "an application's cache tag (X-KyGate-Cache-Tags)")
	all := fs.Bool("all", false, "every cache entry")
	cacheURL := fs.String("cache-url", env("KYGATE_CACHE_URL", ""), "Valkey URL of the shared exact cache (Team)")
	parse(fs, args[1:])
	return purgeCache(c, *key, *tag, *all, *cacheURL, *yes)
}

func parseWhen(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return t, fmt.Errorf("%q is not a date (YYYY-MM-DD) or a time (RFC 3339)", s)
	}
	return t, nil
}

func askYes(question string) bool {
	fmt.Print(question + " [y/N] ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes" || a == "o" || a == "oui"
}

func purgeEvents(c common, e control.EventPurge, yes bool) error {
	ctx := context.Background()
	db, err := c.openExisting()
	if err != nil {
		return err
	}
	defer db.Close()
	pseudonym := func(id string) string { return "" }
	if e.User != "" {
		org, err := db.Meta(ctx, "org_id")
		if err != nil {
			return err
		}
		master, _, _, err := control.LoadMasterKey(c.dataDir, false)
		if err != nil {
			return err
		}
		if err := control.VerifyMasterKey(ctx, db, master, org); err != nil {
			return err
		}
		pseudonym = func(id string) string { return control.Pseudonym(master, org, id) }
	}
	f, err := e.Filter(ctx, db, pseudonym)
	if err != nil {
		return err
	}
	n, err := db.CountEvents(ctx, f)
	if err != nil {
		return err
	}
	what := "events"
	if e.PayloadsOnly {
		what = "captured payloads (the events stay)"
	}
	fmt.Printf("%s\n%d %s match.\n", e.Describe(), n, what)
	if n == 0 {
		return nil
	}
	if !e.PayloadsOnly {
		fmt.Println("Deleted events leave the reports, and the budget counters rebuilt at the next start no longer count their spend.")
	}
	if !yes && !askYes("Delete them? This cannot be undone.") {
		return errors.New("nothing was deleted")
	}
	del, err := db.PurgeEvents(ctx, f)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(f)
	db.RecordAdmin(ctx, store.AdminAction{Time: time.Now(), Actor: "command line", Action: "purge.events", Target: e.Describe(), Detail: fmt.Sprintf("%d deleted", del), Data: string(data)})
	fmt.Printf("Deleted %d.\n", del)
	return nil
}

func purgeCache(c common, key, tag string, all bool, cacheURL string, yes bool) error {
	ctx := context.Background()
	db, err := c.openExisting()
	if err != nil {
		return err
	}
	defer db.Close()
	org, err := db.Meta(ctx, "org_id")
	if err != nil {
		return errors.New("this installation is not set up yet: run 'kygate serve' once")
	}
	master, _, _, err := control.LoadMasterKey(c.dataDir, false)
	if err != nil {
		return err
	}
	if err := control.VerifyMasterKey(ctx, db, master, org); err != nil {
		return err
	}
	p := &control.Purger{DB: db, MasterKey: master, OrgID: org}
	label, target, err := p.Resolve(ctx, key, tag, all)
	if err != nil {
		return err
	}
	fmt.Printf("Purge the cache: %s, exact and semantic, in every KyGate process.\n", target)
	if !yes && !askYes("Delete them? This cannot be undone.") {
		return errors.New("nothing was deleted")
	}

	// The stores: cache.db (Solo) or Valkey, and the semantic entries.
	var exact store.CacheStore
	var sem store.SemanticStore
	if cacheURL != "" {
		vc, err := valkey.OpenCache(cacheURL)
		if err != nil {
			return err
		}
		defer vc.Close()
		exact = vc
	} else if path := filepath.Join(c.dataDir, control.CacheFile); fileExists(path) {
		cd, err := sqlite.OpenCache(path)
		if err != nil {
			return err
		}
		defer cd.Close()
		exact, sem = cd, cd
	}
	if s, ok := db.(store.SemanticStore); ok && c.databaseURL != "" {
		sem = s
	}
	var res control.CachePurgeResult
	if exact != nil {
		if res.Exact, err = exact.Purge(ctx, label); err != nil {
			return err
		}
	}
	if sem != nil {
		if res.Semantic, err = sem.PurgeSemantic(ctx, label); err != nil {
			return err
		}
	}
	// Running processes apply it to their memory, and once more to the
	// stores after the writes they had queued.
	if _, err := db.RecordCachePurge(ctx, label, time.Now()); err != nil {
		return err
	}
	recordCLI(ctx, db, "purge.cache", target, fmt.Sprintf("%d exact, %d semantic entries deleted", res.Exact, res.Semantic))
	fmt.Printf("Deleted %d exact and %d semantic entries. Running KyGate processes apply the purge within a few seconds.\n", res.Exact, res.Semantic)
	return nil
}
