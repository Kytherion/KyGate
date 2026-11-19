package control

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/cache"
	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store"
	"github.com/Kytherion/KyGate/internal/store/sqlite"
)

func exactOn(t *testing.T, path string) *cache.Exact {
	e := cache.New(1 << 20)
	e.UseDisk(func() (store.CacheStore, error) { return sqlite.OpenCache(path) }, t.Logf)
	if err := e.Configure(cache.Settings{MaxMemoryBytes: 1 << 20, Persist: true}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

// A purge made in one process reaches another one's memory: the control
// process purges, a gateway applies the recorded purge (GV-4).
func TestPurgeReachesOtherProcesses(t *testing.T) {
	a := newAdminRig(t)
	ctx := context.Background()
	cachePath := filepath.Join(a.dir, CacheFile)
	ctrl, gw := exactOn(t, cachePath), exactOn(t, cachePath)
	pc := &Purger{DB: a.db, Cache: ctrl, MasterKey: a.console.MasterKey, OrgID: a.console.OrgID, Logf: t.Logf}
	pg := &Purger{DB: a.db, Cache: gw, MasterKey: a.console.MasterKey, OrgID: a.console.OrgID, Logf: t.Logf}
	if err := pc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	pg.Start(ctx)
	ok := store.DeriveKey(a.console.MasterKey, "cache", a.console.OrgID)
	label := pc.CacheLabel(cache.LabelTag, "docs-v3")
	gw.Put(ok, a.console.OrgID, "fp", &cache.Entry{Model: "m"}, time.Hour, label)
	time.Sleep(300 * time.Millisecond) // the gateway's writer flushes
	res, err := pc.PurgeCache(ctx, label)
	if err != nil || res.Exact != 1 {
		t.Fatalf("the control process deletes it from the shared store: %+v %v", res, err)
	}
	if _, hit := gw.Get(ctx, ok, a.console.OrgID, "fp"); !hit {
		t.Fatal("before the gateway applies the purge, its memory still holds the entry")
	}
	if err := pg.ApplyRecorded(ctx); err != nil {
		t.Fatal(err)
	}
	if _, hit := gw.Get(ctx, ok, a.console.OrgID, "fp"); hit {
		t.Fatal("after it, the gateway no longer serves it")
	}
	// A purge applied once is not applied again.
	gw.Put(ok, a.console.OrgID, "fp", &cache.Entry{Model: "m"}, time.Hour, label)
	pg.ApplyRecorded(ctx)
	if _, hit := gw.Get(ctx, ok, a.console.OrgID, "fp"); !hit {
		t.Fatal("a new answer after the purge is kept")
	}
}

func TestRetainOnce(t *testing.T) {
	a := newAdminRig(t)
	ctx := context.Background()
	now := time.Now()
	day := 24 * time.Hour
	ev := func(id string, age time.Duration) store.Event {
		return store.Event{ID: id, Time: now.Add(-age), OrgID: "o", Family: "openai", Endpoint: "chat", Outcome: "ok", Cache: "miss", Mode: "enforce", Payload: []byte{1}}
	}
	a.db.InsertEvents(ctx, []store.Event{ev("new", time.Hour), ev("mid", 40*day), ev("old", 100*day)})
	a.db.RecordAdmin(ctx, store.AdminAction{Time: now.Add(-400 * day), Actor: "x", Action: "team.create", Target: "t"})
	p, err := policy.Parse(policy.Starter(), "")
	if err != nil {
		t.Fatal(err)
	}
	RetainOnce(ctx, a.db, p, now, t.Logf)
	if _, err := a.db.GetEvent(ctx, "old"); err == nil {
		t.Fatal("events past 90 days are deleted")
	}
	if e, err := a.db.GetEvent(ctx, "mid"); err != nil || e.Payload != nil {
		t.Fatalf("a 40-day-old event stays, its payload goes after 30 days: %+v %v", e, err)
	}
	if e, _ := a.db.GetEvent(ctx, "new"); e == nil || e.Payload == nil {
		t.Fatal("a recent payload stays")
	}
	log, _ := a.db.ListAdmin(ctx, 10)
	if len(log) != 1 || log[0].Actor != "retention" || !strings.Contains(log[0].Detail, "1 events") {
		t.Fatalf("the trail keeps a year, and records what retention deleted: %+v", log)
	}
}
