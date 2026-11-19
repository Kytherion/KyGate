// Package storetest is a conformance suite for store.Database drivers: SQLite
// (Solo) and PostgreSQL (Team) must answer every call alike.
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
)

// Run checks a driver. open returns an empty database.
func Run(t *testing.T, open func(t *testing.T) store.Database) {
	t.Run("config", func(t *testing.T) { config(t, open(t)) })
	t.Run("events and reports", func(t *testing.T) { events(t, open(t)) })
	t.Run("data handling", func(t *testing.T) { dataHandling(t, open(t)) })
	t.Run("end users", func(t *testing.T) { endUsers(t, open(t)) })
	t.Run("audit ledger", func(t *testing.T) { ledger(t, open(t)) })
	t.Run("policy documents", func(t *testing.T) { policies(t, open(t)) })
	t.Run("scim", func(t *testing.T) { scim(t, open(t)) })
	t.Run("fleet", func(t *testing.T) { fleet(t, open(t)) })
	t.Run("quality", func(t *testing.T) { quality(t, open(t)) })
}

func quality(t *testing.T, db store.Database) {
	now := time.UnixMilli(time.Now().UnixMilli())
	db.SetMeta(ctx, "org_id", "org_1")
	evs := []store.Event{
		{ID: "e1", Time: now, OrgID: "org_1", KeyID: "k1", Family: "openai", Endpoint: "chat", ModelServed: "m", Status: 200, Outcome: "ok", Cache: "miss", RouteModel: "cheap"},
		{ID: "e2", Time: now, OrgID: "org_1", KeyID: "k1", Family: "openai", Endpoint: "chat", ModelServed: "m", Status: 200, Outcome: "ok", Cache: "miss", Semantic: "hit"},
		{ID: "e3", Time: now, OrgID: "org_1", KeyID: "k2", Family: "openai", Endpoint: "chat", ModelServed: "m", Status: 200, Outcome: "ok", Cache: "hit"},
	}
	if err := db.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	for _, f := range []store.Feedback{
		{RequestID: "e1", KeyID: "k1", Time: now, Rating: "good"},
		{RequestID: "e1", KeyID: "k1", Time: now, Rating: "bad", Reason: "wrong"}, // replaces
		{RequestID: "e2", KeyID: "k1", Time: now, Rating: "bad", Reason: "outdated"},
		{RequestID: "e3", KeyID: "k1", Time: now, Rating: "bad"}, // not k1's request: not counted
		{RequestID: "e3", KeyID: "k2", Time: now.Add(-48 * time.Hour), Rating: "good"},
	} {
		if err := db.PutFeedback(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.Quality(ctx, store.Range{From: now.Add(-time.Hour), To: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, r := range rows {
		got[r.Served+"/"+r.Rating+"/"+r.Reason+"/"+map[bool]string{true: "routable", false: "-"}[r.Routable]] += r.Count
	}
	want := map[string]int64{"model/bad/wrong/routable": 1, "semantic/bad/outdated/-": 1, "exact/good//-": 1}
	if len(got) != len(want) {
		t.Fatalf("quality rows %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("quality rows %v, want %v", got, want)
		}
	}
	if n, err := db.DeleteFeedbackBefore(ctx, now.Add(-24*time.Hour)); n != 1 || err != nil {
		t.Fatalf("retention: %d %v", n, err)
	}
}

func fleet(t *testing.T, db store.Database) {
	now := time.UnixMilli(time.Now().UnixMilli())
	a := store.Instance{ID: "a", Role: "gateway", Host: "h1", Version: "v1", Started: now.Add(-time.Hour), Seen: now, State: []byte(`{"in_flight":3}`)}
	b := store.Instance{ID: "b", Role: "control", Host: "h2", Version: "v1", Started: now.Add(-time.Hour), Seen: now.Add(-48 * time.Hour)}
	for _, in := range []store.Instance{a, b} {
		if err := db.PutInstance(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	a.Seen, a.State = now.Add(time.Second), []byte(`{"in_flight":5}`)
	if err := db.PutInstance(ctx, a); err != nil {
		t.Fatal(err)
	}
	ins, err := db.ListInstances(ctx)
	if err != nil || len(ins) != 2 {
		t.Fatalf("%v %v", ins, err)
	}
	var got store.Instance
	for _, in := range ins {
		if in.ID == "a" {
			got = in
		}
	}
	if !got.Seen.Equal(a.Seen) || string(got.State) != `{"in_flight":5}` || !got.Started.Equal(a.Started) {
		t.Fatalf("an upsert keeps the start and updates the rest: %+v", got)
	}
	if n, err := db.DeleteInstancesBefore(ctx, now.Add(-24*time.Hour)); n != 1 || err != nil {
		t.Fatalf("forget: %d %v", n, err)
	}
}

func scim(t *testing.T, db store.Database) {
	now := time.UnixMilli(time.Now().UnixMilli())
	ana := store.SCIMResource{ID: "u1", Kind: store.SCIMUser, Name: "ana@example.com", ExternalID: "ext-1", Active: true, Data: []byte(`{"displayName":"Ana"}`), Created: now, Updated: now}
	sam := store.SCIMResource{ID: "u2", Kind: store.SCIMUser, Name: "sam@example.com", Active: true, Created: now, Updated: now}
	for _, u := range []store.SCIMResource{ana, sam} {
		if err := db.CreateSCIM(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	dup := ana
	dup.ID, dup.Name = "u3", "ANA@example.com"
	if err := db.CreateSCIM(ctx, dup); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a second user with the same name, ignoring case: %v, want ErrConflict", err)
	}
	// A group may share a user's name: names are unique per kind.
	g := store.SCIMResource{ID: "g1", Kind: store.SCIMGroup, Name: "kygate-admins", Active: true, Members: []string{"u1", "u2", "u1"}, Created: now, Updated: now}
	if err := db.CreateSCIM(ctx, g); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetSCIM(ctx, store.SCIMGroup, "g1")
	if err != nil || len(got.Members) != 2 || got.Members[0] != "u1" || got.Members[1] != "u2" {
		t.Fatalf("group members %v, %v", got.Members, err)
	}
	if _, err := db.GetSCIM(ctx, store.SCIMUser, "g1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a group read as a user: %v", err)
	}
	u, err := db.GetSCIM(ctx, store.SCIMUser, "u1")
	if err != nil || u.Name != "ana@example.com" || u.ExternalID != "ext-1" || !u.Active || string(u.Data) != `{"displayName":"Ana"}` || !u.Created.Equal(now) {
		t.Fatalf("user %+v, %v", u, err)
	}
	// Replace: deactivate a user; change a group's members.
	u.Active, u.Updated = false, now.Add(time.Second)
	if err := db.ReplaceSCIM(ctx, u); err != nil {
		t.Fatal(err)
	}
	g.Members = []string{"u2"}
	if err := db.ReplaceSCIM(ctx, g); err != nil {
		t.Fatal(err)
	}
	if u2, _ := db.GetSCIM(ctx, store.SCIMUser, "u1"); u2.Active {
		t.Error("the user is still active")
	}
	if g2, _ := db.GetSCIM(ctx, store.SCIMGroup, "g1"); len(g2.Members) != 1 || g2.Members[0] != "u2" {
		t.Errorf("members after replace %v", g2.Members)
	}
	sam.Name = "ana@example.com"
	if err := db.ReplaceSCIM(ctx, sam); !errors.Is(err, store.ErrConflict) {
		t.Errorf("renaming onto a taken name: %v, want ErrConflict", err)
	}
	if err := db.ReplaceSCIM(ctx, store.SCIMResource{ID: "nope", Kind: store.SCIMUser, Name: "x@example.com"}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("replacing a missing user: %v", err)
	}
	// Deleting a user takes it out of its groups.
	if ok, err := db.DeleteSCIM(ctx, store.SCIMUser, "u2"); !ok || err != nil {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if g3, _ := db.GetSCIM(ctx, store.SCIMGroup, "g1"); len(g3.Members) != 0 {
		t.Errorf("a deleted user is still a member: %v", g3.Members)
	}
	if ok, _ := db.DeleteSCIM(ctx, store.SCIMUser, "u2"); ok {
		t.Error("deleted twice")
	}
	users, _ := db.ListSCIM(ctx, store.SCIMUser)
	groups, _ := db.ListSCIM(ctx, store.SCIMGroup)
	if len(users) != 1 || len(groups) != 1 {
		t.Errorf("%d users and %d groups left, want 1 and 1", len(users), len(groups))
	}
}

var ctx = context.Background()

func config(t *testing.T, db store.Database) {
	if _, err := db.Meta(ctx, "org_id"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an empty database has no org: %v", err)
	}
	db.SetMeta(ctx, "org_id", "org_1")
	db.SetMeta(ctx, "org_id", "org_1") // twice: an update
	if v, _ := db.Meta(ctx, "org_id"); v != "org_1" {
		t.Fatal(v)
	}
	v0, _ := db.ConfigVersion(ctx)
	now := time.Now().Truncate(time.Millisecond)
	if err := db.CreateTeam(ctx, store.Team{ID: "t1", Name: "finance", OrgID: "org_1", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateTeam(ctx, store.Team{ID: "t2", Name: "finance", OrgID: "org_1", CreatedAt: now}); err == nil {
		t.Fatal("team names are unique")
	}
	db.CreateProject(ctx, store.Project{ID: "p1", Name: "ledger", TeamID: "t1", OrgID: "org_1", CreatedAt: now})
	if err := db.CreateKey(ctx, store.VirtualKey{ID: "k1", Name: "app", Hash: "h1", Prefix: "kg-abc", OrgID: "org_1", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateKey(ctx, store.VirtualKey{ID: "k2", Name: "app", Hash: "h2", Prefix: "kg-def", OrgID: "org_1", CreatedAt: now}); err == nil {
		t.Fatal("key names are unique")
	}
	if ok, err := db.SetKeyProject(ctx, "app", "p1"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if v1, _ := db.ConfigVersion(ctx); v1 <= v0 {
		t.Fatalf("the config version moves on: %d -> %d", v0, v1)
	}
	if _, err := db.DeleteProject(ctx, "ledger"); err == nil {
		t.Fatal("a project with active keys stays")
	}
	if _, err := db.DeleteTeam(ctx, "finance"); err == nil {
		t.Fatal("a team with projects stays")
	}
	ks, _ := db.ListKeys(ctx)
	if len(ks) != 1 || ks[0].ProjectID != "p1" || !ks[0].CreatedAt.Equal(now) || ks[0].RevokedAt != nil {
		t.Fatalf("%+v", ks)
	}
	if ok, _ := db.RevokeKey(ctx, "k1"); !ok {
		t.Fatal("revoke")
	}
	if ok, _ := db.RevokeKey(ctx, "k1"); ok {
		t.Fatal("a revoked key is not revoked twice")
	}
	if ok, err := db.DeleteProject(ctx, "ledger"); !ok || err != nil {
		t.Fatal(ok, err)
	}

	db.PutUser(ctx, store.User{Email: "Ana@Example.com", Role: "team_lead", TeamID: "t1", CreatedAt: now})
	db.PutUser(ctx, store.User{Email: "ana@example.com", Role: "viewer", CreatedAt: now})
	u, err := db.GetUser(ctx, "ANA@example.com")
	if err != nil || u.Role != "viewer" || u.TeamID != "" || u.Email != "ana@example.com" {
		t.Fatalf("%+v %v", u, err)
	}
	db.TouchUser(ctx, "ana@example.com", now)
	if us, _ := db.ListUsers(ctx); len(us) != 1 || us[0].LastLogin == nil {
		t.Fatalf("%+v", us)
	}
	if _, err := db.GetUser(ctx, "nobody@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	db.CreateSession(ctx, store.Session{Hash: "s1", Email: "ana@example.com", Role: "viewer", CSRF: "c", Created: now, Expires: now.Add(time.Hour)})
	db.CreateSession(ctx, store.Session{Hash: "s2", Email: "ana@example.com", Role: "viewer", CSRF: "c", Created: now, Expires: now.Add(-time.Second)})
	if s, err := db.GetSession(ctx, "s1"); err != nil || s.CSRF != "c" {
		t.Fatal(s, err)
	}
	if _, err := db.GetSession(ctx, "s2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("an expired session is not found")
	}
	db.DeleteSessionsOf(ctx, "ana@example.com")
	if _, err := db.GetSession(ctx, "s1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("sessions of a removed person end")
	}

	db.RecordAdmin(ctx, store.AdminAction{Time: now, Actor: "a", Action: "x.y", Target: "t"})
	if as, _ := db.ListAdmin(ctx, 10); len(as) != 1 || as[0].Detail != "" {
		t.Fatalf("%+v", as)
	}
	if err := db.PutCredential(ctx, store.Credential{Name: "openai", Provider: "openai", WrappedDEK: []byte{1, 2}, Ciphertext: []byte{0, 255, 3}, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if cs, _ := db.ListCredentials(ctx); len(cs) != 1 || string(cs[0].Ciphertext) != string([]byte{0, 255, 3}) {
		t.Fatalf("%+v", cs)
	}
}

func events(t *testing.T, db store.Database) {
	now := time.Now().Truncate(time.Millisecond)
	evs := []store.Event{
		{ID: "e1", Time: now, OrgID: "o", KeyID: "k1", KeyName: "app", TeamName: "finance", Family: "openai", Endpoint: "chat", ModelRequested: "gpt-5",
			ModelServed: "gpt-5", Status: 200, Outcome: "ok", Cache: "miss", Mode: "enforce", InputTokens: 10, OutputTokens: 3, CostUSD: 0.5,
			Findings: []store.FindingCount{{Type: "CREDIT_CARD", Action: "mask", Count: 2, Applied: true}, {Type: "OUTPUT_IMAGE", Action: "remove", Count: 1, Applied: true}},
			NearMiss: []string{"system:date"}, RouteModel: "o4-mini", RouteReason: "short", RouteSavingUSD: 0.2, Stages: map[string]int{"cache": 3}, Payload: []byte{9, 8}},
		{ID: "e2", Time: now, OrgID: "o", KeyID: "k2", KeyName: "bot", Family: "anthropic", Endpoint: "messages", ModelRequested: "claude-opus-5-5",
			Status: 403, Outcome: "blocked", Cache: "off", Mode: "enforce", Alert: true, CostUSD: 0, Guard: "unavailable",
			Findings: []store.FindingCount{{Type: "PROMPT_INJECTION", Action: "block", Count: 1, Applied: true}}},
		{ID: "e3", Time: now, OrgID: "o", KeyID: "k1", KeyName: "app", TeamName: "finance", Family: "openai", Endpoint: "chat", ModelRequested: "gpt-5",
			Status: 200, Outcome: "ok", Cache: "hit", Mode: "enforce", CostAvoidedUSD: 0.5},
	}
	if err := db.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertEvents(ctx, evs[:1]); err != nil {
		t.Fatal("an event delivered twice is skipped:", err)
	}
	r := store.Range{From: now.Add(-time.Hour), To: now.Add(time.Hour)}
	tot, err := db.Totals(ctx, r)
	if err != nil || tot.Requests != 3 || tot.CacheHits != 1 || tot.CacheMisses != 1 || tot.Blocked != 1 || tot.Alerts != 1 || tot.CostUSD != 0.5 || tot.CostAvoidedUSD != 0.5 || tot.InputTokens != 10 {
		t.Fatalf("%v %+v", err, tot)
	}
	scoped := r
	scoped.Team = "finance"
	if tot, _ := db.Totals(ctx, scoped); tot.Requests != 2 {
		t.Fatalf("team scope: %+v", tot)
	}
	for _, by := range []string{"day", "hour", "model", "key", "team", "project", "connection", "endpoint"} {
		g, err := db.GroupBy(ctx, r, by)
		if err != nil || len(g) == 0 {
			t.Fatalf("group by %s: %v %+v", by, err, g)
		}
	}
	if g, _ := db.GroupBy(ctx, r, "key"); g[0].Key != "app" || g[0].Requests != 2 {
		t.Fatalf("%+v", g)
	}
	f, err := db.Findings(ctx, r)
	if err != nil || len(f) != 3 || f[0].Type != "CREDIT_CARD" || f[0].Count != 2 || !f[0].Applied {
		t.Fatalf("%v %+v", err, f)
	}
	sec, err := db.Security(ctx, r, "key")
	if err != nil || len(sec) != 2 {
		t.Fatalf("%v %+v", err, sec)
	}
	byKey := map[string]store.SecurityRow{}
	for _, s := range sec {
		byKey[s.Key] = s
	}
	if a := byKey["app"]; a.WithData != 1 || a.AnswersChanged != 1 || a.Threats != 0 {
		t.Fatalf("%+v", a)
	}
	if b := byKey["bot"]; b.Threats != 1 || b.Blocked != 1 || b.GuardDown != 1 || b.Alerts != 1 {
		t.Fatalf("%+v", b)
	}
	if s, err := db.Security(ctx, r, "hour"); err != nil || len(s) != 1 {
		t.Fatalf("%v %+v", err, s)
	}
	if nm, err := db.NearMisses(ctx, r); err != nil || len(nm) != 1 || nm[0].Label != "system:date" || nm[0].CostUSD != 0.5 {
		t.Fatalf("%v %+v", err, nm)
	}
	if rr, err := db.Routing(ctx, r); err != nil || len(rr) != 1 || rr[0].Would != "o4-mini" || rr[0].SavingUSD != 0.2 {
		t.Fatalf("%v %+v", err, rr)
	}
	if sp, err := db.Spend(ctx, now.Add(-time.Hour)); err != nil || len(sp) != 2 {
		t.Fatalf("%v %+v", err, sp)
	}
	list, err := db.ListEvents(ctx, store.EventFilter{Range: r, Outcome: "ok"})
	if err != nil || len(list) != 2 || list[0].Payload != nil {
		t.Fatalf("%v %+v", err, list)
	}
	e, err := db.GetEvent(ctx, "e1")
	if err != nil || len(e.Findings) != 2 || e.NearMiss[0] != "system:date" || e.Stages["cache"] != 3 || string(e.Payload) != string([]byte{9, 8}) || !e.Time.Equal(now) || e.TeamName != "finance" {
		t.Fatalf("%v %+v", err, e)
	}
	if _, err := db.GetEvent(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if n, err := db.DeleteEventsBefore(ctx, now.Add(time.Minute)); err != nil || n != 3 {
		t.Fatal(n, err)
	}
}

// dataHandling: purges, retention, and recorded cache purges (GV-4).
func dataHandling(t *testing.T, db store.Database) {
	now := time.Now().Truncate(time.Millisecond)
	old := now.Add(-48 * time.Hour)
	ev := func(id, key, team, project string, at time.Time, payload bool) store.Event {
		e := store.Event{ID: id, Time: at, OrgID: "o", KeyID: key, TeamName: team, ProjectName: project, Family: "openai", Endpoint: "chat", Status: 200, Outcome: "ok", Cache: "miss", Mode: "enforce", CostUSD: 1}
		if payload {
			e.Payload = []byte{1, 2, 3}
		}
		return e
	}
	if err := db.InsertEvents(ctx, []store.Event{
		ev("a1", "k1", "finance", "ledger", now, true), ev("a2", "k1", "finance", "ledger", old, true),
		ev("a3", "k2", "finance", "", now, false), ev("a4", "k3", "", "", now, true), ev("a5", "k3", "", "", old, false),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CountEvents(ctx, store.PurgeFilter{}); !errors.Is(err, store.ErrEmptyPurge) {
		t.Fatal("a purge that names nothing is refused")
	}
	if _, err := db.PurgeEvents(ctx, store.PurgeFilter{PayloadsOnly: true}); !errors.Is(err, store.ErrEmptyPurge) {
		t.Fatal("a payload purge that names nothing is refused")
	}
	count := func(f store.PurgeFilter) int64 {
		t.Helper()
		n, err := db.CountEvents(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count(store.PurgeFilter{Team: "finance"}) != 3 || count(store.PurgeFilter{Project: "ledger"}) != 2 || count(store.PurgeFilter{KeyID: "k3"}) != 2 ||
		count(store.PurgeFilter{To: now.Add(-time.Hour)}) != 2 || count(store.PurgeFilter{KeyID: "k1", From: now}) != 1 ||
		count(store.PurgeFilter{Team: "finance", PayloadsOnly: true}) != 2 {
		t.Fatal("the filter selects by key, team, project, and time")
	}
	// Payloads only: the events stay, so the reports do not change.
	if n, err := db.PurgeEvents(ctx, store.PurgeFilter{To: now.Add(-time.Hour), PayloadsOnly: true}); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if e, err := db.GetEvent(ctx, "a2"); err != nil || e.Payload != nil {
		t.Fatalf("the payload is gone, the event stays: %+v %v", e, err)
	}
	if e, _ := db.GetEvent(ctx, "a1"); e == nil || e.Payload == nil {
		t.Fatal("a newer payload stays")
	}
	if n, err := db.PurgeEvents(ctx, store.PurgeFilter{Team: "finance"}); err != nil || n != 3 {
		t.Fatal(n, err)
	}
	if count(store.PurgeFilter{KeyID: "k3"}) != 2 || count(store.PurgeFilter{Team: "finance"}) != 0 {
		t.Fatal("only the team's events are gone")
	}

	// The administration trail and sessions.
	db.RecordAdmin(ctx, store.AdminAction{Time: old, Actor: "a", Action: "team.create", Target: "x"})
	db.RecordAdmin(ctx, store.AdminAction{Time: now, Actor: "a", Action: "team.create", Target: "y"})
	if n, err := db.DeleteAdminBefore(ctx, now.Add(-time.Hour)); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if l, _ := db.ListAdmin(ctx, 10); len(l) != 1 || l[0].Target != "y" {
		t.Fatalf("%+v", l)
	}
	// Creating a session also sweeps expired ones: create the expired one last.
	db.CreateSession(ctx, store.Session{Hash: "s2", Email: "a@x", Role: "admin", CSRF: "c", Created: now, Expires: now.Add(time.Hour)})
	db.CreateSession(ctx, store.Session{Hash: "s1", Email: "a@x", Role: "admin", CSRF: "c", Created: old, Expires: now.Add(-time.Minute)})
	if n, err := db.DeleteExpiredSessions(ctx, now); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if _, err := db.GetSession(ctx, "s2"); err != nil {
		t.Fatal("a live session stays")
	}

	// Cache purges are recorded in order, and change the configuration version.
	v0, _ := db.ConfigVersion(ctx)
	s1, err := db.RecordCachePurge(ctx, "label-a", now)
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := db.RecordCachePurge(ctx, "", now)
	if v1, _ := db.ConfigVersion(ctx); v1 <= v0 || s2 <= s1 {
		t.Fatal("a cache purge is announced to the gateways")
	}
	if ps, err := db.CachePurgesSince(ctx, 0); err != nil || len(ps) != 2 || ps[0].Label != "label-a" || ps[1].Label != "" || !ps[0].Time.Equal(now) {
		t.Fatalf("%+v %v", ps, err)
	}
	if ps, _ := db.CachePurgesSince(ctx, s1); len(ps) != 1 || ps[0].Seq != s2 {
		t.Fatalf("%+v", ps)
	}
}

// endUsers: keys' signing secrets and user requirement, and events by person (AC-3).
func endUsers(t *testing.T, db store.Database) {
	now := time.Now().Truncate(time.Millisecond)
	if err := db.CreateKey(ctx, store.VirtualKey{ID: "key_1", Name: "app", Hash: "h1", Prefix: "kg-abc", OrgID: "o", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	v0, _ := db.ConfigVersion(ctx)
	if ok, err := db.SetKeyUserSecret(ctx, "app", []byte{1, 2, 3}); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, _ := db.SetKeyRequireUser(ctx, "key_1", true); !ok {
		t.Fatal("by ID too")
	}
	if ok, _ := db.SetKeyRequireUser(ctx, "nope", true); ok {
		t.Fatal("an unknown key")
	}
	if v1, _ := db.ConfigVersion(ctx); v1 <= v0 {
		t.Fatal("gateways reload")
	}
	ks, _ := db.ListKeys(ctx)
	if len(ks) != 1 || !ks[0].RequireUser || !ks[0].HasSecret || string(ks[0].UserSecret) != string([]byte{1, 2, 3}) {
		t.Fatalf("%+v", ks)
	}
	db.SetKeyUserSecret(ctx, "app", nil)
	if ks, _ := db.ListKeys(ctx); ks[0].HasSecret {
		t.Fatal("removed")
	}
	ev := func(id, user string, cost float64) store.Event {
		return store.Event{ID: id, Time: now, OrgID: "o", KeyID: "key_1", User: user, Family: "openai", Endpoint: "chat", Outcome: "ok", Cache: "miss", Mode: "enforce", CostUSD: cost}
	}
	db.InsertEvents(ctx, []store.Event{ev("a", "u_aaaaaaaaaaaaaaaaaaaa", 1), ev("b", "u_aaaaaaaaaaaaaaaaaaaa", 2), ev("c", "u_bbbbbbbbbbbbbbbbbbbb", 4), ev("d", "", 8)})
	r := store.Range{From: now.Add(-time.Hour), To: now.Add(time.Hour)}
	g, err := db.GroupBy(ctx, r, "user")
	if err != nil || len(g) != 3 || g[0].Key != "(no user)" || g[1].Key != "u_bbbbbbbbbbbbbbbbbbbb" || g[2].CostUSD != 3 {
		t.Fatalf("by user, by cost: %v %+v", err, g)
	}
	if l, _ := db.ListEvents(ctx, store.EventFilter{Range: r, User: "u_aaaaaaaaaaaaaaaaaaaa", Limit: 10}); len(l) != 2 || l[0].User != "u_aaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("%+v", l)
	}
	rows, _ := db.Spend(ctx, now.Add(-time.Hour))
	spent := map[string]float64{}
	for _, x := range rows {
		spent[x.User] += x.CostUSD
	}
	if spent["u_aaaaaaaaaaaaaaaaaaaa"] != 3 || spent[""] != 8 {
		t.Fatalf("spend per person, for the budget counters: %+v", rows)
	}
	if n, err := db.PurgeEvents(ctx, store.PurgeFilter{User: "u_aaaaaaaaaaaaaaaaaaaa"}); err != nil || n != 2 {
		t.Fatal(n, err)
	}
}

// ledger: the store side of the audit ledger (GV-3).
func ledger(t *testing.T, db store.Database) {
	now := time.Now().Truncate(time.Millisecond)
	if _, err := db.LedgerHead(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an empty ledger: %v", err)
	}
	ev := func(id string, at time.Time) store.Event {
		return store.Event{ID: id, Time: at, OrgID: "o", KeyID: "k", Family: "openai", Endpoint: "chat", Outcome: "ok", Cache: "miss", Mode: "enforce", MAC: "sig-" + id}
	}
	db.InsertEvents(ctx, []store.Event{ev("b", now), ev("a", now.Add(-time.Minute)), ev("c", now.Add(time.Minute))})
	db.RecordAdmin(ctx, store.AdminAction{Time: now, Actor: "x", Action: "purge.events", Target: "t", Detail: "d", Data: `{"key_id":"k"}`})
	evs, err := db.UnsealedEvents(ctx, 2)
	if err != nil || len(evs) != 2 || evs[0].ID != "a" || evs[1].ID != "b" || evs[0].MAC != "sig-a" {
		t.Fatalf("oldest first, with signatures: %v %+v", err, evs)
	}
	ads, _ := db.UnsealedAdmin(ctx, 10)
	if len(ads) != 1 || ads[0].ID == "" || ads[0].Data != `{"key_id":"k"}` {
		t.Fatalf("records get an ID and keep their data: %+v", ads)
	}
	if l, _ := db.ListAdmin(ctx, 10); l[0].ID != ads[0].ID {
		t.Fatal("the same ID in the trail")
	}
	entries := []store.LedgerEntry{
		{Seq: 1, Time: now, Kind: store.LedgerEvent, Ref: "a", Digest: "d1", Scope: `{"k":"k"}`, Prev: "genesis", Hash: "h1"},
		{Seq: 2, Time: now, Kind: store.LedgerPurge, Ref: ads[0].ID, Digest: "d2", Scope: ads[0].Data, Prev: "h1", Hash: "h2"},
	}
	if err := db.Seal(ctx, entries, []string{"a"}, []string{ads[0].ID}); err != nil {
		t.Fatal(err)
	}
	if err := db.Seal(ctx, entries[:1], nil, nil); err == nil {
		t.Fatal("a sequence number is never written twice")
	}
	head, err := db.LedgerHead(ctx)
	if err != nil || head.Seq != 2 || head.Hash != "h2" || !head.Time.Equal(now) {
		t.Fatalf("%+v %v", head, err)
	}
	after, _ := db.LedgerAfter(ctx, 1, 10)
	if len(after) != 1 || after[0].Kind != store.LedgerPurge || after[0].Scope != `{"key_id":"k"}` {
		t.Fatalf("%+v", after)
	}
	if evs, _ := db.UnsealedEvents(ctx, 10); len(evs) != 2 {
		t.Fatal("a is sealed now")
	}
	got, _ := db.GetEvents(ctx, []string{"a", "c", "nope"})
	if len(got) != 2 || got["c"].MAC != "sig-c" {
		t.Fatalf("%+v", got)
	}
	if ga, _ := db.GetAdmin(ctx, []string{ads[0].ID}); len(ga) != 1 {
		t.Fatal("by ID")
	}
	se, sa, _ := db.CountSealed(ctx)
	ue, ua, _ := db.CountUnsealed(ctx)
	if se != 1 || sa != 1 || ue != 2 || ua != 0 {
		t.Fatal(se, sa, ue, ua)
	}
}

// policies: policy documents with their history.
func policies(t *testing.T, db store.Database) {
	if _, err := db.GetPolicy(ctx, "org"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	v0, _ := db.ConfigVersion(ctx)
	one, two := "kind: Policy\n# one\n", "kind: Policy\n# two\n"
	if err := db.PutPolicy(ctx, store.PolicyDoc{ID: "org", Body: []byte(one), UpdatedBy: "a"}); err != nil {
		t.Fatal(err)
	}
	db.PutPolicy(ctx, store.PolicyDoc{ID: "org", Body: []byte(two), UpdatedBy: "b"})
	db.PutPolicy(ctx, store.PolicyDoc{ID: "team-finance", Body: []byte("mode: enforce\n"), UpdatedBy: "a"})
	if v1, _ := db.ConfigVersion(ctx); v1 <= v0 {
		t.Fatal("a write makes the gateways reload")
	}
	d, err := db.GetPolicy(ctx, "org")
	if err != nil || string(d.Body) != two || d.UpdatedBy != "b" || d.Updated.IsZero() {
		t.Fatalf("%+v %v", d, err)
	}
	all, _ := db.ListPolicies(ctx)
	if len(all) != 2 || all[0].ID != "org" || all[1].ID != "team-finance" {
		t.Fatalf("%+v", all)
	}
	if ok, err := db.DeletePolicy(ctx, "team-finance", "a"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, _ := db.DeletePolicy(ctx, "team-finance", "a"); ok {
		t.Fatal("gone")
	}
	if all, _ := db.ListPolicies(ctx); len(all) != 1 {
		t.Fatal(all)
	}
}
