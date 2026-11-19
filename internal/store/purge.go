package store

// Data handling (GV-4): purges and retention. A purge deletes
// usage and audit events, or only the masked payloads captured with them,
// for one scope and time range; or cache entries, by label. Cache purges are
// recorded, so that every gateway applies them to its own memory too.

import (
	"errors"
	"strings"
	"time"
)

// PurgeFilter selects events to purge. Empty fields do not narrow; at least
// one field must be set, so that no purge deletes everything by accident.
type PurgeFilter struct {
	KeyID   string    `json:"key_id,omitempty"`
	Team    string    `json:"team,omitempty"`    // by name, as events record it
	Project string    `json:"project,omitempty"` // by name
	User    string    `json:"user,omitempty"`    // pseudonym
	From    time.Time `json:"from,omitempty"`    // inclusive
	To      time.Time `json:"to,omitempty"`      // exclusive
	// PayloadsOnly deletes the captured masked payloads and keeps the
	// events, so that usage and cost reports stay whole.
	PayloadsOnly bool `json:"payloads_only,omitempty"`
}

// ErrEmptyPurge refuses a purge that names nothing.
var ErrEmptyPurge = errors.New("name a key, project, team, user, or time range to purge")

// Empty reports whether the filter names nothing.
func (f PurgeFilter) Empty() bool {
	return f.KeyID == "" && f.Team == "" && f.Project == "" && f.User == "" && f.From.IsZero() && f.To.IsZero()
}

// Where is the SQL condition for the filter, with ? placeholders, shared by
// the SQLite and PostgreSQL drivers.
func (f PurgeFilter) Where() (string, []any) {
	var conds []string
	var args []any
	add := func(c string, v any) {
		conds = append(conds, c)
		args = append(args, v)
	}
	if f.KeyID != "" {
		add("key_id = ?", f.KeyID)
	}
	if f.Team != "" {
		add("team_name = ?", f.Team)
	}
	if f.Project != "" {
		add("project_name = ?", f.Project)
	}
	if f.User != "" {
		add("user_id = ?", f.User)
	}
	if !f.From.IsZero() {
		add("ts >= ?", f.From.UnixMilli())
	}
	if !f.To.IsZero() {
		add("ts < ?", f.To.UnixMilli())
	}
	if f.PayloadsOnly {
		conds = append(conds, "payload IS NOT NULL")
	}
	return strings.Join(conds, " AND "), args
}

// CachePurge is one recorded cache purge. Label is a keyed hash, never a tag
// or a key in clear; empty means every entry.
type CachePurge struct {
	Seq   int64
	Time  time.Time
	Label string
}
