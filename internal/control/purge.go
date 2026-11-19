package control

// Data handling (GV-4): purges and retention.
//
// A cache purge deletes the entries with one label (a key, or an
// application's tag) or every entry, in the cache store and in this
// process's memory, then records the purge in the database. Every other
// process (the gateways of the Team profile, or a running Solo KyGate when
// the command line purged) sees the record within seconds and applies the
// purge itself: to its memory, and to the store after the writes it had
// queued, so that no answer written just before the purge survives it.
//
// Retention runs in the control process, once an hour: events, captured
// payloads, and the administration trail each have their own period.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Kytherion/KyGate/internal/audit"
	"github.com/Kytherion/KyGate/internal/cache"
	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store"
)

// Purger purges the caches and events of one organization.
type Purger struct {
	DB        store.Database
	Cache     *cache.Exact    // nil: no exact cache in this process
	Semantic  *cache.Semantic // nil: no semantic cache
	MasterKey []byte
	OrgID     string
	Logf      func(format string, a ...any)

	mu   sync.Mutex
	seen int64 // the last recorded purge this process applied
}

// CachePurgeResult says what a cache purge deleted from the stores.
type CachePurgeResult struct {
	Exact    int64 `json:"exact"`
	Semantic int64 `json:"semantic"`
}

// CacheLabel is the label of a key (by ID) or a tag, as the gateways store it.
func (p *Purger) CacheLabel(kind, value string) string {
	return cache.Label(store.DeriveKey(p.MasterKey, "cache-label", p.OrgID), kind, value)
}

// Start remembers the purges recorded so far: they were applied before
// this process started.
func (p *Purger) Start(ctx context.Context) error {
	last, err := p.latest(ctx)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.seen = last
	p.mu.Unlock()
	return nil
}

func (p *Purger) latest(ctx context.Context) (int64, error) {
	var last int64
	for {
		ps, err := p.DB.CachePurgesSince(ctx, last)
		if err != nil {
			return 0, err
		}
		if len(ps) == 0 {
			return last, nil
		}
		last = ps[len(ps)-1].Seq
	}
}

// PurgeCache purges by label ("" for every entry) and records the purge for
// the other processes.
func (p *Purger) PurgeCache(ctx context.Context, label string) (CachePurgeResult, error) {
	r, err := p.apply(ctx, label)
	if err != nil {
		return r, err
	}
	seq, err := p.DB.RecordCachePurge(ctx, label, time.Now())
	if err != nil {
		return r, fmt.Errorf("the cache was purged here, but the purge could not be recorded for the other processes: %w", err)
	}
	p.mu.Lock()
	if seq == p.seen+1 {
		p.seen = seq
	}
	p.mu.Unlock()
	return r, nil
}

func (p *Purger) apply(ctx context.Context, label string) (CachePurgeResult, error) {
	var r CachePurgeResult
	var errs []error
	if p.Cache != nil {
		n, err := p.Cache.Purge(ctx, label)
		r.Exact = n
		errs = append(errs, err)
	}
	if p.Semantic != nil {
		n, err := p.Semantic.Purge(ctx, label)
		r.Semantic = n
		errs = append(errs, err)
	}
	return r, errors.Join(errs...)
}

// ApplyRecorded applies the purges other processes recorded since the last
// call. The gateways call it when the configuration version changes.
func (p *Purger) ApplyRecorded(ctx context.Context) error {
	p.mu.Lock()
	since := p.seen
	p.mu.Unlock()
	ps, err := p.DB.CachePurgesSince(ctx, since)
	if err != nil {
		return err
	}
	for _, x := range ps {
		r, err := p.apply(ctx, x.Label)
		if err != nil {
			return err
		}
		if p.Logf != nil {
			what := "every entry"
			if x.Label != "" {
				what = "the entries of one key or tag"
			}
			p.Logf("cache purge %d applied here: %s (%d exact, %d semantic entries deleted by this process)", x.Seq, what, r.Exact, r.Semantic)
		}
		p.mu.Lock()
		p.seen = x.Seq
		p.mu.Unlock()
	}
	return nil
}

// EventPurge is a purge of events as the admin API and the command line take
// it: by key name, team, project, and time.
type EventPurge struct {
	Key          string    `json:"key,omitempty"` // name or ID
	Team         string    `json:"team,omitempty"`
	Project      string    `json:"project,omitempty"`
	User         string    `json:"user,omitempty"` // the person's ID, or their pseudonym (u_...)
	From         time.Time `json:"from,omitempty"`
	To           time.Time `json:"to,omitempty"`
	PayloadsOnly bool      `json:"payloads_only,omitempty"`
}

// Filter resolves the key name to its ID, and a person's ID to its
// pseudonym (pseudonym may be nil when no user is named).
func (e EventPurge) Filter(ctx context.Context, cs store.ConfigStore, pseudonym func(id string) string) (store.PurgeFilter, error) {
	f := store.PurgeFilter{Team: strings.TrimSpace(e.Team), Project: strings.TrimSpace(e.Project), From: e.From, To: e.To, PayloadsOnly: e.PayloadsOnly}
	if u := strings.TrimSpace(e.User); u != "" {
		switch {
		case isPseudonym(u):
			f.User = u
		case pseudonym != nil:
			f.User = pseudonym(u)
		default:
			return f, errors.New("a purge by user needs the master key")
		}
	}
	if !e.From.IsZero() && !e.To.IsZero() && !e.From.Before(e.To) {
		return f, errors.New("from must be before to")
	}
	if k := strings.TrimSpace(e.Key); k != "" {
		keys, err := cs.ListKeys(ctx)
		if err != nil {
			return f, err
		}
		for _, vk := range keys {
			if vk.Name == k || vk.ID == k {
				f.KeyID = vk.ID
			}
		}
		if f.KeyID == "" {
			return f, fmt.Errorf("no key named %q", k)
		}
	}
	if f.Empty() {
		return f, store.ErrEmptyPurge
	}
	return f, nil
}

// Describe says what an event purge selects, for the administration trail. It
// names scopes and dates, never a value.
func (e EventPurge) Describe() string {
	var parts []string
	what := "events"
	if e.PayloadsOnly {
		what = "captured payloads"
	}
	user := ""
	if u := strings.TrimSpace(e.User); u != "" {
		// The trail names the pseudonym, never the person's ID.
		user = u
		if !isPseudonym(u) {
			user = "(by ID)"
		}
	}
	for _, kv := range [][2]string{{"key", e.Key}, {"team", e.Team}, {"project", e.Project}, {"user", user}} {
		if strings.TrimSpace(kv[1]) != "" {
			parts = append(parts, kv[0]+" "+strings.TrimSpace(kv[1]))
		}
	}
	if !e.From.IsZero() {
		parts = append(parts, "from "+e.From.UTC().Format(time.RFC3339))
	}
	if !e.To.IsZero() {
		parts = append(parts, "before "+e.To.UTC().Format(time.RFC3339))
	}
	return what + ": " + strings.Join(parts, ", ")
}

// Retain applies the policy's retention periods once an hour, and at start.
// It runs in the control process only.
func Retain(ctx context.Context, db store.Database, pol func() *policy.Policy, logf func(string, ...any)) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		RetainOnce(ctx, db, pol(), time.Now(), logf)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RetainOnce applies the retention periods at now.
func RetainOnce(ctx context.Context, db store.Database, p *policy.Policy, now time.Time, logf func(string, ...any)) {
	day := 24 * time.Hour
	var done []string
	var cut audit.RetentionData // what the ledger records (GV-3)
	report := func(what string, n int64, err error) {
		if err != nil {
			logf("retention: %s: %v", what, err)
		} else if n > 0 {
			done = append(done, fmt.Sprintf("%d %s", n, what))
		}
	}
	if d := p.Audit.RetentionDays; d > 0 {
		t := now.Add(-time.Duration(d) * day)
		n, err := db.DeleteEventsBefore(ctx, t)
		report(fmt.Sprintf("events older than %d days", d), n, err)
		if n > 0 {
			cut.EventsBefore = t.UnixMilli()
		}
		// Ratings of answers (OB-4) go with their events.
		n, err = db.DeleteFeedbackBefore(ctx, t)
		report(fmt.Sprintf("answer ratings older than %d days", d), n, err)
	}
	if d := p.Audit.PayloadRetentionDays; d > 0 && d < p.Audit.RetentionDays {
		t := now.Add(-time.Duration(d) * day)
		n, err := db.PurgeEvents(ctx, store.PurgeFilter{To: t, PayloadsOnly: true})
		report(fmt.Sprintf("captured payloads older than %d days", d), n, err)
		if n > 0 {
			cut.PayloadsBefore = t.UnixMilli()
		}
	}
	if d := p.Audit.AdminRetentionDays; d > 0 {
		t := now.Add(-time.Duration(d) * day)
		n, err := db.DeleteAdminBefore(ctx, t)
		report(fmt.Sprintf("administration records older than %d days", d), n, err)
		if n > 0 {
			cut.AdminBefore = t.UnixMilli()
		}
	}
	n, err := db.DeleteExpiredSessions(ctx, now)
	report("expired sessions", n, err)
	if len(done) > 0 {
		msg := strings.Join(done, ", ")
		logf("retention: deleted %s", msg)
		data, _ := json.Marshal(cut)
		db.RecordAdmin(ctx, store.AdminAction{Time: now, Actor: "retention", Action: audit.ActionRetention, Target: "data", Detail: msg, Data: string(data)})
	}
}

func isPseudonym(s string) bool {
	if len(s) != 22 || !strings.HasPrefix(s, "u_") {
		return false
	}
	for _, c := range s[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
