package store

import (
	"context"
	"database/sql"
	"time"
)

// The fleet: every KyGate process writes a heartbeat with its own view of
// its dependencies, in the background, never on the request path. The console
// reads them to show the state of every gateway, the Guard, and the stores.

// Instance is one running KyGate process.
type Instance struct {
	ID      string    `json:"id"`   // random, per start
	Role    string    `json:"role"` // all | gateway | control
	Host    string    `json:"host"`
	Version string    `json:"version"`
	Started time.Time `json:"started"`
	Seen    time.Time `json:"seen"`
	State   []byte    `json:"-"` // the process's own view, as JSON: never a value, a key, or text
}

// FleetStore keeps the heartbeats.
type FleetStore interface {
	PutInstance(ctx context.Context, in Instance) error
	ListInstances(ctx context.Context) ([]Instance, error)
	// DeleteInstancesBefore forgets processes not heard from since t.
	DeleteInstancesBefore(ctx context.Context, t time.Time) (int64, error)
}

// SQLFleet implements FleetStore over database/sql for both drivers.
type SQLFleet struct {
	DB     *sql.DB
	Rebind func(string) string
}

func (s SQLFleet) q(query string) string {
	if s.Rebind == nil {
		return query
	}
	return s.Rebind(query)
}

func (s SQLFleet) PutInstance(ctx context.Context, in Instance) error {
	_, err := s.DB.ExecContext(ctx, s.q(`INSERT INTO instances(id, role, host, version, started_at, seen_at, state) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET role = excluded.role, host = excluded.host, version = excluded.version, seen_at = excluded.seen_at, state = excluded.state`),
		in.ID, in.Role, in.Host, in.Version, in.Started.UnixMilli(), in.Seen.UnixMilli(), in.State)
	return err
}

func (s SQLFleet) ListInstances(ctx context.Context) ([]Instance, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(`SELECT id, role, host, version, started_at, seen_at, state FROM instances ORDER BY role, host, started_at`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Instance
	for rows.Next() {
		var in Instance
		var started, seen int64
		if err := rows.Scan(&in.ID, &in.Role, &in.Host, &in.Version, &started, &seen, &in.State); err != nil {
			return nil, err
		}
		in.Started, in.Seen = time.UnixMilli(started), time.UnixMilli(seen)
		out = append(out, in)
	}
	return out, rows.Err()
}

func (s SQLFleet) DeleteInstancesBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx, s.q(`DELETE FROM instances WHERE seen_at < ?`), t.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
