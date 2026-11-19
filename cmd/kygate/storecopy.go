package main

// kygate store copy: moves a Solo installation from SQLite to
// PostgreSQL, the Team profile's database. It copies the organization's
// settings, keys (as hashes), the hierarchy, people, encrypted provider keys,
// usage and audit events, and the audit trail of administration. It does not
// copy sessions (people sign in again) or caches (they refill). The master key
// must stay the same: it seals the provider keys.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
	"github.com/Kytherion/KyGate/internal/store/postgres"
)

// copiedMeta are the settings an installation keeps in its meta table.
var copiedMeta = []string{"org_id", "created_at", "master_check", "admin_token_hash", "sso_client_secret", "scim_token_hash"}

func storeCmd(args []string) error {
	if len(args) == 0 || args[0] != "copy" {
		return errors.New("usage: kygate store copy --to postgres://USER:PASSWORD@HOST/DB [--data-dir DIR]")
	}
	var c common
	fs := flag.NewFlagSet("store copy", flag.ExitOnError)
	c.register(fs)
	to := fs.String("to", "", "the PostgreSQL URL to copy into; it must hold no installation yet")
	parse(fs, args[1:])
	if *to == "" {
		return errors.New("--to postgres://... is required")
	}
	if c.databaseURL != "" {
		return errors.New("the source is the SQLite database of --data-dir: leave --database-url unset")
	}
	src, err := c.openExisting()
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := postgres.Open(*to)
	if err != nil {
		return err
	}
	defer dst.Close()
	n, err := copyStore(context.Background(), src, dst)
	if err != nil {
		return err
	}
	fmt.Printf("Copied into PostgreSQL: %d keys, %d teams, %d projects, %d people, %d provider keys, %d events, %d administration records.\n",
		n.keys, n.teams, n.projects, n.users, n.creds, n.events, n.admin)
	fmt.Println("Start KyGate with --database-url (or KYGATE_DATABASE_URL) and the same master key. People sign in again; the caches refill.")
	return nil
}

type copied struct{ keys, teams, projects, users, creds, events, admin int }

func copyStore(ctx context.Context, src, dst store.Database) (copied, error) {
	var n copied
	if _, err := dst.Meta(ctx, "org_id"); err == nil {
		return n, errors.New("the destination already holds an installation: copy into an empty database")
	}
	for _, k := range copiedMeta {
		v, err := src.Meta(ctx, k)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return n, err
		}
		if err := dst.SetMeta(ctx, k, v); err != nil {
			return n, err
		}
	}
	ts, err := src.ListTeams(ctx)
	if err != nil {
		return n, err
	}
	for _, t := range ts {
		if err := dst.CreateTeam(ctx, t); err != nil {
			return n, err
		}
		n.teams++
	}
	ps, err := src.ListProjects(ctx)
	if err != nil {
		return n, err
	}
	for _, p := range ps {
		if err := dst.CreateProject(ctx, p); err != nil {
			return n, err
		}
		n.projects++
	}
	ks, err := src.ListKeys(ctx)
	if err != nil {
		return n, err
	}
	for _, k := range ks {
		if err := dst.CreateKey(ctx, k); err != nil {
			return n, err
		}
		if k.RevokedAt != nil {
			if _, err := dst.RevokeKey(ctx, k.ID); err != nil {
				return n, err
			}
		}
		n.keys++
	}
	us, err := src.ListUsers(ctx)
	if err != nil {
		return n, err
	}
	for _, u := range us {
		if err := dst.PutUser(ctx, u); err != nil {
			return n, err
		}
		n.users++
	}
	// Provisioned people, then their groups (members refer to people).
	for _, kind := range []string{store.SCIMUser, store.SCIMGroup} {
		rs, err := src.ListSCIM(ctx, kind)
		if err != nil {
			return n, err
		}
		for _, r := range rs {
			if err := dst.CreateSCIM(ctx, r); err != nil {
				return n, err
			}
			if kind == store.SCIMUser {
				n.users++
			}
		}
	}
	cs, err := src.ListCredentials(ctx)
	if err != nil {
		return n, err
	}
	for _, cr := range cs {
		if err := dst.PutCredential(ctx, cr); err != nil {
			return n, err
		}
		n.creds++
	}
	// Events, newest first, page by page; each read whole, with any captured
	// (masked, encrypted) payload.
	all := store.Range{From: time.Unix(0, 0), To: time.Now().Add(24 * time.Hour)}
	before := time.Time{}
	for {
		page, err := src.ListEvents(ctx, store.EventFilter{Range: all, Before: before, Limit: 500})
		if err != nil {
			return n, err
		}
		if len(page) == 0 {
			break
		}
		batch := make([]store.Event, 0, len(page))
		for _, e := range page {
			full, err := src.GetEvent(ctx, e.ID)
			if err != nil {
				return n, err
			}
			batch = append(batch, *full)
		}
		if err := dst.InsertEvents(ctx, batch); err != nil {
			return n, err
		}
		n.events += len(batch)
		next := page[len(page)-1].Time
		if !before.IsZero() && !next.Before(before) {
			break
		}
		before = next
		if len(page) < 500 {
			break
		}
	}
	as, err := src.ListAdmin(ctx, 1000000)
	if err != nil {
		return n, err
	}
	for i := len(as) - 1; i >= 0; i-- {
		if err := dst.RecordAdmin(ctx, as[i]); err != nil {
			return n, err
		}
		n.admin++
	}
	dst.RecordAdmin(ctx, store.AdminAction{Time: time.Now(), Actor: "command line", Action: "store.copy", Target: "postgres",
		Detail: fmt.Sprintf("%d keys, %d events copied from SQLite", n.keys, n.events)})
	return n, nil
}
