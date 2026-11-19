// Package sqlite is the embedded store driver for the Solo profile. It holds
// configuration, key hashes, encrypted provider credentials, and usage and
// audit events in one file (DB), and the exact cache in a file of its own
// (CacheDB, cache.go).
package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Kytherion/KyGate/internal/store"
)

// DB implements store.ConfigStore and store.EventStore.
type DB struct {
	db *sql.DB
}

var (
	_ store.ConfigStore = (*DB)(nil)
	_ store.EventStore  = (*DB)(nil)
)

// migrations run in order. Each one runs once; an upgrade adds to the end.
var migrations = []string{
	`CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
	 CREATE TABLE virtual_keys (
	   id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, hash TEXT NOT NULL UNIQUE,
	   prefix TEXT NOT NULL, org_id TEXT NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER);
	 CREATE TABLE provider_credentials (
	   name TEXT PRIMARY KEY, provider TEXT NOT NULL, base_url TEXT NOT NULL DEFAULT '',
	   wrapped_dek BLOB NOT NULL, ciphertext BLOB NOT NULL, created_at INTEGER NOT NULL);
	 CREATE TABLE events (
	   id TEXT PRIMARY KEY, ts INTEGER NOT NULL, org_id TEXT NOT NULL,
	   key_id TEXT, key_name TEXT, family TEXT, endpoint TEXT,
	   model_requested TEXT, model_served TEXT, connection TEXT, hosting TEXT,
	   stream INTEGER, status INTEGER, outcome TEXT, reason TEXT,
	   cache TEXT, cache_reason TEXT, mode TEXT, policy_version TEXT,
	   input_tokens INTEGER, cached_tokens INTEGER, cache_write_tokens INTEGER, output_tokens INTEGER,
	   cost_usd REAL, cost_avoided_usd REAL, unpriced INTEGER, alert INTEGER,
	   findings TEXT, unreadable TEXT, stages TEXT, total_ms INTEGER, ttfb_ms INTEGER, attempts INTEGER,
	   payload BLOB);
	 CREATE INDEX events_ts ON events(ts);
	 INSERT INTO meta(k, v) VALUES ('config_version', '1');`,
	// The semantic cache's result per request.
	`ALTER TABLE events ADD COLUMN semantic TEXT;
	 ALTER TABLE events ADD COLUMN semantic_check TEXT;
	 ALTER TABLE events ADD COLUMN similarity REAL;`,
	// The Guard's result per request.
	`ALTER TABLE events ADD COLUMN guard TEXT;`,
	// why an exact-cache miss missed (labels, never values).
	`ALTER TABLE events ADD COLUMN near_miss TEXT;`,
	// the router's shadow decision.
	`ALTER TABLE events ADD COLUMN route_model TEXT;
	 ALTER TABLE events ADD COLUMN route_reason TEXT;
	 ALTER TABLE events ADD COLUMN route_saving_usd REAL;`,
	// budgets, and a route that was applied.
	`ALTER TABLE events ADD COLUMN route_applied INTEGER;
	 ALTER TABLE events ADD COLUMN budget TEXT;`,
	// the hierarchy organization -> team -> project -> key.
	`CREATE TABLE teams (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, org_id TEXT NOT NULL, created_at INTEGER NOT NULL);
	 CREATE TABLE projects (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, team_id TEXT, org_id TEXT NOT NULL, created_at INTEGER NOT NULL);
	 ALTER TABLE virtual_keys ADD COLUMN project_id TEXT;
	 ALTER TABLE events ADD COLUMN team_name TEXT;
	 ALTER TABLE events ADD COLUMN project_name TEXT;`,
	// the audit trail of administration.
	`CREATE TABLE admin_actions (ts INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, detail TEXT);
	 CREATE INDEX admin_actions_ts ON admin_actions(ts);`,
	// people who sign in, and their sessions.
	`CREATE TABLE users (email TEXT PRIMARY KEY, role TEXT NOT NULL, team_id TEXT, created_at INTEGER NOT NULL, last_login INTEGER);
	 CREATE TABLE sessions (hash TEXT PRIMARY KEY, email TEXT NOT NULL, role TEXT NOT NULL, team_id TEXT, csrf TEXT NOT NULL,
	   created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
	 CREATE INDEX sessions_email ON sessions(email);`,
	// the region of a stored provider connection (GV-4).
	`ALTER TABLE provider_credentials ADD COLUMN region TEXT NOT NULL DEFAULT '';
	 CREATE TABLE cache_purges (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, label TEXT NOT NULL);
	 CREATE INDEX events_key ON events(key_id, ts);
	 CREATE INDEX sessions_expires ON sessions(expires_at);`,
	// end-user identity (AC-3).
	`ALTER TABLE virtual_keys ADD COLUMN require_user INTEGER NOT NULL DEFAULT 0;
	 ALTER TABLE virtual_keys ADD COLUMN user_secret BLOB;
	 ALTER TABLE events ADD COLUMN user_id TEXT;
	 CREATE INDEX events_user ON events(user_id, ts);`,
	// the audit ledger (GV-3).
	`ALTER TABLE events ADD COLUMN mac TEXT;
	 ALTER TABLE events ADD COLUMN sealed INTEGER NOT NULL DEFAULT 0;
	 CREATE INDEX events_unsealed ON events(ts) WHERE sealed = 0;
	 ALTER TABLE admin_actions ADD COLUMN id TEXT;
	 ALTER TABLE admin_actions ADD COLUMN data TEXT;
	 ALTER TABLE admin_actions ADD COLUMN sealed INTEGER NOT NULL DEFAULT 0;
	 UPDATE admin_actions SET id = lower(hex(randomblob(8))) WHERE id IS NULL;
	 CREATE UNIQUE INDEX admin_actions_id ON admin_actions(id);
	 CREATE TABLE audit_ledger (seq INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, ref TEXT NOT NULL,
	   digest TEXT NOT NULL, scope TEXT NOT NULL DEFAULT '', prev TEXT NOT NULL, hash TEXT NOT NULL);`,
	// policy documents in the database (used with PostgreSQL;
	// SQLite keeps the table for store copy and tests).
	`CREATE TABLE policies (id TEXT PRIMARY KEY, body BLOB NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL DEFAULT '');
	 CREATE TABLE policy_history (id TEXT NOT NULL, body BLOB NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL DEFAULT '',
	   replaced_at INTEGER NOT NULL, replaced_by TEXT NOT NULL DEFAULT '');
	 CREATE INDEX policy_history_id ON policy_history(id, replaced_at);`,
	// SCIM provisioning (GV-2).
	`CREATE TABLE scim_resources (id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, name_key TEXT NOT NULL,
	   external_id TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1, data BLOB, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
	 CREATE UNIQUE INDEX scim_resources_name ON scim_resources(kind, name_key);
	 CREATE TABLE scim_members (group_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (group_id, user_id));
	 CREATE INDEX scim_members_user ON scim_members(user_id);`,
	// the fleet's heartbeats.
	`CREATE TABLE instances (id TEXT PRIMARY KEY, role TEXT NOT NULL, host TEXT NOT NULL, version TEXT NOT NULL,
	   started_at INTEGER NOT NULL, seen_at INTEGER NOT NULL, state BLOB);`,
	// quality signals (OB-4).
	`CREATE TABLE feedback (request_id TEXT NOT NULL, key_id TEXT NOT NULL, ts INTEGER NOT NULL, rating TEXT NOT NULL,
	   reason TEXT NOT NULL DEFAULT '', PRIMARY KEY (request_id, key_id));
	 CREATE INDEX feedback_ts ON feedback(ts);`,
}

// Open opens or creates the database and applies pending migrations.
func Open(path string) (*DB, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	d := &DB{db: db}
	if err := migrate(db, migrations); err != nil {
		db.Close()
		return nil, err
	}
	return d, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.db.Close() }

// migrate applies the migrations a database has not run yet.
func migrate(db *sql.DB, migrations []string) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (v INTEGER NOT NULL)`); err != nil {
		return err
	}
	var v int
	err := db.QueryRow(`SELECT v FROM schema_version`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := db.Exec(`INSERT INTO schema_version(v) VALUES (0)`); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if v > len(migrations) {
		return fmt.Errorf("the database was written by a newer KyGate (schema %d); upgrade KyGate", v)
	}
	for i := v; i < len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(`UPDATE schema_version SET v = ?`, i+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ---- ConfigStore ----

func (d *DB) Meta(ctx context.Context, key string) (string, error) {
	var v string
	err := d.db.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", store.ErrNotFound
	}
	return v, err
}

func (d *DB) SetMeta(ctx context.Context, key, value string) error {
	_, err := d.db.ExecContext(ctx, `INSERT INTO meta(k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, key, value)
	return err
}

func (d *DB) ConfigVersion(ctx context.Context) (int64, error) {
	v, err := d.Meta(ctx, "config_version")
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(v, 10, 64)
}

func (d *DB) BumpConfigVersion(ctx context.Context) error {
	_, err := d.db.ExecContext(ctx, `UPDATE meta SET v = CAST(CAST(v AS INTEGER) + 1 AS TEXT) WHERE k = 'config_version'`)
	return err
}

func (d *DB) CreateKey(ctx context.Context, k store.VirtualKey) error {
	_, err := d.db.ExecContext(ctx, `INSERT INTO virtual_keys(id, name, hash, prefix, org_id, created_at, project_id, require_user, user_secret) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.Name, k.Hash, k.Prefix, k.OrgID, k.CreatedAt.UnixMilli(), nullable(k.ProjectID), b2i(k.RequireUser), k.UserSecret)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("a key named %q already exists", k.Name)
		}
		return err
	}
	return d.BumpConfigVersion(ctx)
}

func (d *DB) ListKeys(ctx context.Context) ([]store.VirtualKey, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT id, name, hash, prefix, org_id, created_at, revoked_at, COALESCE(project_id, ''), require_user, user_secret FROM virtual_keys ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.VirtualKey
	for rows.Next() {
		var k store.VirtualKey
		var created int64
		var revoked sql.NullInt64
		var requireUser int
		if err := rows.Scan(&k.ID, &k.Name, &k.Hash, &k.Prefix, &k.OrgID, &created, &revoked, &k.ProjectID, &requireUser, &k.UserSecret); err != nil {
			return nil, err
		}
		k.RequireUser, k.HasSecret = requireUser != 0, len(k.UserSecret) > 0
		k.CreatedAt = time.UnixMilli(created)
		if revoked.Valid {
			t := time.UnixMilli(revoked.Int64)
			k.RevokedAt = &t
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (d *DB) RevokeKey(ctx context.Context, idOrName string) (bool, error) {
	res, err := d.db.ExecContext(ctx, `UPDATE virtual_keys SET revoked_at = ? WHERE (id = ? OR name = ?) AND revoked_at IS NULL`,
		time.Now().UnixMilli(), idOrName, idOrName)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		return true, d.BumpConfigVersion(ctx)
	}
	return false, nil
}

func (d *DB) PutUser(ctx context.Context, u store.User) error {
	_, err := d.db.ExecContext(ctx, `INSERT INTO users(email, role, team_id, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(email) DO UPDATE SET role = excluded.role, team_id = excluded.team_id`,
		strings.ToLower(u.Email), u.Role, nullable(u.TeamID), u.CreatedAt.UnixMilli())
	return err
}

func scanUser(sc interface{ Scan(...any) error }) (store.User, error) {
	var u store.User
	var created int64
	var last sql.NullInt64
	if err := sc.Scan(&u.Email, &u.Role, &u.TeamID, &created, &last); err != nil {
		return u, err
	}
	u.CreatedAt = time.UnixMilli(created)
	if last.Valid {
		t := time.UnixMilli(last.Int64)
		u.LastLogin = &t
	}
	return u, nil
}

func (d *DB) GetUser(ctx context.Context, email string) (store.User, error) {
	u, err := scanUser(d.db.QueryRowContext(ctx, `SELECT email, role, COALESCE(team_id, ''), created_at, last_login FROM users WHERE email = ?`, strings.ToLower(email)))
	if errors.Is(err, sql.ErrNoRows) {
		return u, store.ErrNotFound
	}
	return u, err
}

func (d *DB) ListUsers(ctx context.Context) ([]store.User, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT email, role, COALESCE(team_id, ''), created_at, last_login FROM users ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (d *DB) DeleteUser(ctx context.Context, email string) (bool, error) {
	res, err := d.db.ExecContext(ctx, `DELETE FROM users WHERE email = ?`, strings.ToLower(email))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (d *DB) TouchUser(ctx context.Context, email string, at time.Time) error {
	_, err := d.db.ExecContext(ctx, `UPDATE users SET last_login = ? WHERE email = ?`, at.UnixMilli(), strings.ToLower(email))
	return err
}

func (d *DB) CreateSession(ctx context.Context, s store.Session) error {
	d.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, time.Now().UnixMilli())
	_, err := d.db.ExecContext(ctx, `INSERT INTO sessions(hash, email, role, team_id, csrf, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		s.Hash, s.Email, s.Role, nullable(s.TeamID), s.CSRF, s.Created.UnixMilli(), s.Expires.UnixMilli())
	return err
}

func (d *DB) GetSession(ctx context.Context, hash string) (store.Session, error) {
	var s store.Session
	var created, expires int64
	err := d.db.QueryRowContext(ctx, `SELECT hash, email, role, COALESCE(team_id, ''), csrf, created_at, expires_at FROM sessions WHERE hash = ? AND expires_at > ?`,
		hash, time.Now().UnixMilli()).Scan(&s.Hash, &s.Email, &s.Role, &s.TeamID, &s.CSRF, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return s, store.ErrNotFound
	}
	s.Created, s.Expires = time.UnixMilli(created), time.UnixMilli(expires)
	return s, err
}

func (d *DB) DeleteSession(ctx context.Context, hash string) error {
	_, err := d.db.ExecContext(ctx, `DELETE FROM sessions WHERE hash = ?`, hash)
	return err
}

func (d *DB) DeleteSessionsOf(ctx context.Context, email string) error {
	_, err := d.db.ExecContext(ctx, `DELETE FROM sessions WHERE email = ?`, strings.ToLower(email))
	return err
}

func (d *DB) RecordAdmin(ctx context.Context, a store.AdminAction) error {
	_, err := d.db.ExecContext(ctx, `INSERT INTO admin_actions(id, ts, actor, action, target, detail, data) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		adminID(a.ID), a.Time.UnixMilli(), a.Actor, a.Action, a.Target, nullable(a.Detail), nullable(a.Data))
	return err
}

func (d *DB) ListAdmin(ctx context.Context, limit int) ([]store.AdminAction, error) {
	if limit <= 0 || limit > 1000000 {
		limit = 200
	}
	rows, err := d.db.QueryContext(ctx, `SELECT COALESCE(id, ''), ts, actor, action, target, COALESCE(detail, ''), COALESCE(data, '') FROM admin_actions ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.AdminAction
	for rows.Next() {
		var a store.AdminAction
		var ts int64
		if err := rows.Scan(&a.ID, &ts, &a.Actor, &a.Action, &a.Target, &a.Detail, &a.Data); err != nil {
			return nil, err
		}
		a.Time = time.UnixMilli(ts)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) CreateTeam(ctx context.Context, t store.Team) error {
	if _, err := d.db.ExecContext(ctx, `INSERT INTO teams(id, name, org_id, created_at) VALUES (?, ?, ?, ?)`, t.ID, t.Name, t.OrgID, t.CreatedAt.UnixMilli()); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("a team named %q already exists", t.Name)
		}
		return err
	}
	return d.BumpConfigVersion(ctx)
}

func (d *DB) ListTeams(ctx context.Context) ([]store.Team, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT id, name, org_id, created_at FROM teams ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Team
	for rows.Next() {
		var t store.Team
		var created int64
		if err := rows.Scan(&t.ID, &t.Name, &t.OrgID, &created); err != nil {
			return nil, err
		}
		t.CreatedAt = time.UnixMilli(created)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (d *DB) DeleteTeam(ctx context.Context, name string) (bool, error) {
	var n int
	if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects p JOIN teams t ON p.team_id = t.id WHERE t.name = ?`, name).Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return false, fmt.Errorf("team %q still has %d projects: move or delete them first", name, n)
	}
	res, err := d.db.ExecContext(ctx, `DELETE FROM teams WHERE name = ?`, name)
	if err != nil {
		return false, err
	}
	if k, _ := res.RowsAffected(); k > 0 {
		return true, d.BumpConfigVersion(ctx)
	}
	return false, nil
}

func (d *DB) CreateProject(ctx context.Context, p store.Project) error {
	if _, err := d.db.ExecContext(ctx, `INSERT INTO projects(id, name, team_id, org_id, created_at) VALUES (?, ?, ?, ?, ?)`,
		p.ID, p.Name, nullable(p.TeamID), p.OrgID, p.CreatedAt.UnixMilli()); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("a project named %q already exists", p.Name)
		}
		return err
	}
	return d.BumpConfigVersion(ctx)
}

func (d *DB) ListProjects(ctx context.Context) ([]store.Project, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT id, name, COALESCE(team_id, ''), org_id, created_at FROM projects ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Project
	for rows.Next() {
		var p store.Project
		var created int64
		if err := rows.Scan(&p.ID, &p.Name, &p.TeamID, &p.OrgID, &created); err != nil {
			return nil, err
		}
		p.CreatedAt = time.UnixMilli(created)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (d *DB) DeleteProject(ctx context.Context, name string) (bool, error) {
	var n int
	if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM virtual_keys k JOIN projects p ON k.project_id = p.id WHERE p.name = ? AND k.revoked_at IS NULL`, name).Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return false, fmt.Errorf("project %q still has %d active keys: move or revoke them first", name, n)
	}
	res, err := d.db.ExecContext(ctx, `DELETE FROM projects WHERE name = ?`, name)
	if err != nil {
		return false, err
	}
	if k, _ := res.RowsAffected(); k > 0 {
		return true, d.BumpConfigVersion(ctx)
	}
	return false, nil
}

func (d *DB) SetKeyProject(ctx context.Context, idOrName, projectID string) (bool, error) {
	res, err := d.db.ExecContext(ctx, `UPDATE virtual_keys SET project_id = ? WHERE id = ? OR name = ?`, nullable(projectID), idOrName, idOrName)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, d.BumpConfigVersion(ctx)
	}
	return false, nil
}

func (d *DB) PutCredential(ctx context.Context, c store.Credential) error {
	_, err := d.db.ExecContext(ctx, `INSERT INTO provider_credentials(name, provider, base_url, wrapped_dek, ciphertext, created_at, region)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET provider = excluded.provider, base_url = excluded.base_url,
		  wrapped_dek = excluded.wrapped_dek, ciphertext = excluded.ciphertext, region = excluded.region`,
		c.Name, c.Provider, c.BaseURL, c.WrappedDEK, c.Ciphertext, c.CreatedAt.UnixMilli(), c.Region)
	if err != nil {
		return err
	}
	return d.BumpConfigVersion(ctx)
}

func (d *DB) ListCredentials(ctx context.Context) ([]store.Credential, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT name, provider, base_url, wrapped_dek, ciphertext, created_at, region FROM provider_credentials ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Credential
	for rows.Next() {
		var c store.Credential
		var created int64
		if err := rows.Scan(&c.Name, &c.Provider, &c.BaseURL, &c.WrappedDEK, &c.Ciphertext, &created, &c.Region); err != nil {
			return nil, err
		}
		c.CreatedAt = time.UnixMilli(created)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (d *DB) DeleteCredential(ctx context.Context, name string) (bool, error) {
	res, err := d.db.ExecContext(ctx, `DELETE FROM provider_credentials WHERE name = ?`, name)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		return true, d.BumpConfigVersion(ctx)
	}
	return false, nil
}

// ---- EventStore ----

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func jsonText(v any) any {
	switch t := v.(type) {
	case []store.FindingCount:
		if len(t) == 0 {
			return nil
		}
	case []string:
		if len(t) == 0 {
			return nil
		}
	case map[string]int:
		if len(t) == 0 {
			return nil
		}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// InsertEvents stores events. Delivery is at least once, so an event whose
// ID is already stored is skipped.
func (d *DB) InsertEvents(ctx context.Context, events []store.Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO events (
		id, ts, org_id, key_id, key_name, family, endpoint, model_requested, model_served, connection, hosting,
		stream, status, outcome, reason, cache, cache_reason, mode, policy_version,
		input_tokens, cached_tokens, cache_write_tokens, output_tokens, cost_usd, cost_avoided_usd, unpriced, alert,
		findings, unreadable, stages, total_ms, ttfb_ms, attempts, payload, semantic, semantic_check, similarity, guard, near_miss, route_model, route_reason, route_saving_usd, route_applied, budget, team_name, project_name, user_id, mac)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range events {
		_, err := stmt.ExecContext(ctx, e.ID, e.Time.UnixMilli(), e.OrgID, e.KeyID, e.KeyName, e.Family, e.Endpoint,
			e.ModelRequested, e.ModelServed, e.Connection, e.Hosting, b2i(e.Stream), e.Status, e.Outcome, e.Reason,
			e.Cache, e.CacheReason, e.Mode, e.PolicyVersion, e.InputTokens, e.CachedTokens, e.CacheWrite, e.OutputTokens,
			e.CostUSD, e.CostAvoidedUSD, b2i(e.Unpriced), b2i(e.Alert),
			jsonText(e.Findings), jsonText(e.Unreadable), jsonText(e.Stages), e.TotalMS, e.TTFBMS, e.Attempts, e.Payload,
			nullable(e.Semantic), nullable(e.SemanticCheck), e.Similarity, nullable(e.Guard), jsonText(e.NearMiss), nullable(e.RouteModel), nullable(e.RouteReason), e.RouteSavingUSD, b2i(e.RouteApplied), nullable(e.Budget), nullable(e.TeamName), nullable(e.ProjectName), nullable(e.User), nullable(e.MAC))
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

const totalsCols = `COUNT(*),
	COALESCE(SUM(input_tokens),0), COALESCE(SUM(cached_tokens),0), COALESCE(SUM(cache_write_tokens),0), COALESCE(SUM(output_tokens),0),
	COALESCE(SUM(cost_usd),0), COALESCE(SUM(cost_avoided_usd),0),
	COALESCE(SUM(cache = 'hit'),0), COALESCE(SUM(cache = 'miss'),0),
	COALESCE(SUM(outcome = 'blocked'),0), COALESCE(SUM(outcome = 'refused'),0), COALESCE(SUM(outcome = 'error'),0),
	COALESCE(SUM(alert),0), COALESCE(SUM(unpriced),0), COALESCE(AVG(total_ms),0),
	COALESCE(SUM(semantic IN ('hit', 'would_hit', 'miss')),0), COALESCE(SUM(semantic = 'hit'),0),
	COALESCE(SUM(CASE WHEN semantic = 'hit' THEN cost_avoided_usd END),0),
	COALESCE(SUM(semantic = 'would_hit'),0), COALESCE(SUM(CASE WHEN semantic = 'would_hit' THEN cost_usd END),0),
	COALESCE(SUM(semantic_check = 'agree'),0), COALESCE(SUM(semantic_check = 'disagree'),0), COALESCE(SUM(semantic = 'error'),0)`

func scanTotals(s interface{ Scan(...any) error }, prefix ...any) (store.Totals, error) {
	var t store.Totals
	dest := append(prefix, &t.Requests, &t.InputTokens, &t.CachedTokens, &t.CacheWrite, &t.OutputTokens,
		&t.CostUSD, &t.CostAvoidedUSD, &t.CacheHits, &t.CacheMisses, &t.Blocked, &t.Refused, &t.Errors,
		&t.Alerts, &t.Unpriced, &t.AvgMS,
		&t.SemanticLookups, &t.SemanticHits, &t.SemanticAvoidedUSD, &t.SemanticWouldHit, &t.SemanticWouldUSD,
		&t.SemanticAgree, &t.SemanticDisagree, &t.SemanticErrors)
	err := s.Scan(dest...)
	return t, err
}

func (d *DB) Totals(ctx context.Context, r store.Range) (store.Totals, error) {
	row := d.db.QueryRowContext(ctx, `SELECT `+totalsCols+` FROM events WHERE ts >= ? AND ts < ? AND (? = '' OR team_name = ?)`, r.From.UnixMilli(), r.To.UnixMilli(), r.Team, r.Team)
	return scanTotals(row)
}

func (d *DB) GroupBy(ctx context.Context, r store.Range, by string) ([]store.Group, error) {
	var expr string
	switch by {
	case "day":
		expr = `strftime('%Y-%m-%d', ts / 1000, 'unixepoch')`
	case "hour":
		expr = `strftime('%Y-%m-%dT%H:00', ts / 1000, 'unixepoch')`
	case "model":
		expr = `COALESCE(NULLIF(model_served, ''), model_requested, '')`
	case "key":
		expr = `COALESCE(NULLIF(key_name, ''), '(no key)')`
	case "team":
		expr = `COALESCE(NULLIF(team_name, ''), '(no team)')`
	case "project":
		expr = `COALESCE(NULLIF(project_name, ''), '(no project)')`
	case "user":
		expr = `COALESCE(NULLIF(user_id, ''), '(no user)')`
	case "connection":
		expr = `COALESCE(NULLIF(connection, ''), '(none)')`
	case "endpoint":
		expr = `family || ' ' || endpoint`
	default:
		return nil, fmt.Errorf("unknown grouping %q", by)
	}
	order := "SUM(cost_usd) DESC, COUNT(*) DESC"
	if by == "day" || by == "hour" {
		order = "1"
	}
	rows, err := d.db.QueryContext(ctx, `SELECT `+expr+`, `+totalsCols+` FROM events WHERE ts >= ? AND ts < ? AND (? = '' OR team_name = ?) GROUP BY 1 ORDER BY `+order,
		r.From.UnixMilli(), r.To.UnixMilli(), r.Team, r.Team)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Group
	for rows.Next() {
		var g store.Group
		t, err := scanTotals(rows, &g.Key)
		if err != nil {
			return nil, err
		}
		g.Totals = t
		out = append(out, g)
	}
	return out, rows.Err()
}

// Spend sums the cost per key since a time (OP-5): the budget counters are
// rebuilt from it at start.
func (d *DB) Spend(ctx context.Context, since time.Time) ([]store.SpendRow, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT COALESCE(key_id, ''), COALESCE(user_id, ''), COALESCE(SUM(cost_usd), 0) FROM events WHERE ts >= ? GROUP BY 1, 2`, since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.SpendRow
	for rows.Next() {
		var s store.SpendRow
		if err := rows.Scan(&s.KeyID, &s.User, &s.CostUSD); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Routing is the routing report (OP-4): the router's shadow decisions, by
// requested model, cheaper model, and reason.
func (d *DB) Routing(ctx context.Context, r store.Range) ([]store.RouteRow, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT COALESCE(NULLIF(model_requested, ''), '(none)'), COALESCE(route_model, ''), route_reason,
		       COUNT(*), COALESCE(SUM(cost_usd), 0), COALESCE(SUM(route_saving_usd), 0)
		FROM events
		WHERE ts >= ? AND ts < ? AND (? = '' OR team_name = ?) AND route_reason IS NOT NULL AND route_reason <> ''
		GROUP BY 1, 2, 3 ORDER BY 6 DESC, 4 DESC`, r.From.UnixMilli(), r.To.UnixMilli(), r.Team, r.Team)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.RouteRow
	for rows.Next() {
		var x store.RouteRow
		if err := rows.Scan(&x.Requested, &x.Would, &x.Reason, &x.Requests, &x.CostUSD, &x.SavingUSD); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// NearMisses counts exact-cache near misses per label.
func (d *DB) NearMisses(ctx context.Context, r store.Range) ([]store.NearMissRow, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT n.value, COUNT(DISTINCT e.id), SUM(e.cost_usd), COUNT(DISTINCT e.key_id)
		FROM events e, json_each(e.near_miss) n
		WHERE e.ts >= ? AND e.ts < ? AND (? = '' OR e.team_name = ?) AND e.near_miss IS NOT NULL
		GROUP BY 1 ORDER BY 2 DESC, 1`, r.From.UnixMilli(), r.To.UnixMilli(), r.Team, r.Team)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.NearMissRow
	for rows.Next() {
		var n store.NearMissRow
		var cost sql.NullFloat64
		if err := rows.Scan(&n.Label, &n.Requests, &cost, &n.Keys); err != nil {
			return nil, err
		}
		n.CostUSD = cost.Float64
		out = append(out, n)
	}
	return out, rows.Err()
}

// Security is the security report (OB-3), by virtual key or by time bucket.
func (d *DB) Security(ctx context.Context, r store.Range, by string) ([]store.SecurityRow, error) {
	var expr, order string
	switch by {
	case "key":
		expr, order = `COALESCE(NULLIF(key_name, ''), '(no key)')`, "with_any DESC, 2 DESC, 1"
	case "day":
		expr, order = `strftime('%Y-%m-%d', ts / 1000, 'unixepoch')`, "1"
	case "hour":
		expr, order = `strftime('%Y-%m-%dT%H:00', ts / 1000, 'unixepoch')`, "1"
	default:
		return nil, fmt.Errorf("unknown grouping %q", by)
	}
	threats := make([]string, len(store.ThreatTypes))
	for i, t := range store.ThreatTypes {
		threats[i] = "'" + t + "'" // constants of this package, never input
	}
	in := strings.Join(threats, ",")
	has := func(cond string) string {
		return `EXISTS (SELECT 1 FROM json_each(e.findings) f WHERE ` + cond + `)`
	}
	typ := `json_extract(f.value, '$.type')`
	isOutput := `substr(` + typ + `, 1, ` + strconv.Itoa(len(store.OutputPrefix)) + `) = '` + store.OutputPrefix + `'`
	data := has(typ + ` NOT IN (` + in + `) AND NOT ` + isOutput)
	threat := has(typ + ` IN (` + in + `)`)
	changed := has(isOutput + ` AND json_extract(f.value, '$.action') IN ('remove', 'block') AND json_extract(f.value, '$.applied')`)
	outAlert := has(isOutput + ` AND json_extract(f.value, '$.action') = 'alert'`)
	q := `SELECT ` + expr + `, COUNT(*),
		SUM(CASE WHEN ` + data + ` THEN 1 ELSE 0 END),
		SUM(CASE WHEN ` + threat + ` THEN 1 ELSE 0 END),
		SUM(CASE WHEN ` + changed + ` THEN 1 ELSE 0 END),
		SUM(CASE WHEN ` + outAlert + ` THEN 1 ELSE 0 END),
		SUM(CASE WHEN outcome = 'blocked' THEN 1 ELSE 0 END),
		SUM(CASE WHEN outcome = 'refused' THEN 1 ELSE 0 END),
		SUM(CASE WHEN alert THEN 1 ELSE 0 END),
		SUM(CASE WHEN guard = 'unavailable' THEN 1 ELSE 0 END),
		SUM(CASE WHEN e.findings IS NOT NULL OR outcome IN ('blocked', 'refused') OR alert THEN 1 ELSE 0 END) AS with_any
		FROM events e WHERE ts >= ? AND ts < ? AND (? = '' OR team_name = ?) GROUP BY 1 ORDER BY ` + order
	rows, err := d.db.QueryContext(ctx, q, r.From.UnixMilli(), r.To.UnixMilli(), r.Team, r.Team)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.SecurityRow
	for rows.Next() {
		var s store.SecurityRow
		var withAny int64
		if err := rows.Scan(&s.Key, &s.Requests, &s.WithData, &s.Threats, &s.AnswersChanged, &s.OutputAlerts, &s.Blocked, &s.Refused, &s.Alerts, &s.GuardDown, &withAny); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) Findings(ctx context.Context, r store.Range) ([]store.FindingRow, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT json_extract(f.value, '$.type'), json_extract(f.value, '$.action'), json_extract(f.value, '$.applied'),
		       SUM(json_extract(f.value, '$.count')), COUNT(DISTINCT e.id)
		FROM events e, json_each(e.findings) f
		WHERE e.ts >= ? AND e.ts < ? AND (? = '' OR e.team_name = ?) AND e.findings IS NOT NULL
		GROUP BY 1, 2, 3 ORDER BY 4 DESC`, r.From.UnixMilli(), r.To.UnixMilli(), r.Team, r.Team)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.FindingRow
	for rows.Next() {
		var f store.FindingRow
		var applied any
		if err := rows.Scan(&f.Type, &f.Action, &applied, &f.Count, &f.Requests); err != nil {
			return nil, err
		}
		switch a := applied.(type) {
		case int64:
			f.Applied = a != 0
		case bool:
			f.Applied = a
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

const eventCols = `id, ts, org_id, COALESCE(key_id,''), COALESCE(key_name,''), COALESCE(family,''), COALESCE(endpoint,''),
	COALESCE(model_requested,''), COALESCE(model_served,''), COALESCE(connection,''), COALESCE(hosting,''),
	COALESCE(stream,0), COALESCE(status,0), COALESCE(outcome,''), COALESCE(reason,''), COALESCE(cache,''), COALESCE(cache_reason,''),
	COALESCE(mode,''), COALESCE(policy_version,''), COALESCE(input_tokens,0), COALESCE(cached_tokens,0), COALESCE(cache_write_tokens,0),
	COALESCE(output_tokens,0), COALESCE(cost_usd,0), COALESCE(cost_avoided_usd,0), COALESCE(unpriced,0), COALESCE(alert,0),
	findings, unreadable, stages, COALESCE(total_ms,0), COALESCE(ttfb_ms,0), COALESCE(attempts,0), payload,
	COALESCE(semantic,''), COALESCE(semantic_check,''), COALESCE(similarity,0), COALESCE(guard,''), near_miss, COALESCE(route_model,''), COALESCE(route_reason,''), COALESCE(route_saving_usd,0), COALESCE(route_applied,0), COALESCE(budget,''), COALESCE(team_name,''), COALESCE(project_name,''), COALESCE(user_id,''), COALESCE(mac,'')`

func scanEvent(s interface{ Scan(...any) error }) (store.Event, error) {
	var e store.Event
	var ts int64
	var stream, unpriced, alert int
	var findings, unreadable, stages, nearMiss sql.NullString
	var routeApplied int
	err := s.Scan(&e.ID, &ts, &e.OrgID, &e.KeyID, &e.KeyName, &e.Family, &e.Endpoint, &e.ModelRequested, &e.ModelServed,
		&e.Connection, &e.Hosting, &stream, &e.Status, &e.Outcome, &e.Reason, &e.Cache, &e.CacheReason, &e.Mode,
		&e.PolicyVersion, &e.InputTokens, &e.CachedTokens, &e.CacheWrite, &e.OutputTokens, &e.CostUSD, &e.CostAvoidedUSD,
		&unpriced, &alert, &findings, &unreadable, &stages, &e.TotalMS, &e.TTFBMS, &e.Attempts, &e.Payload,
		&e.Semantic, &e.SemanticCheck, &e.Similarity, &e.Guard, &nearMiss, &e.RouteModel, &e.RouteReason, &e.RouteSavingUSD, &routeApplied, &e.Budget, &e.TeamName, &e.ProjectName, &e.User, &e.MAC)
	if err != nil {
		return e, err
	}
	e.Time = time.UnixMilli(ts)
	e.Stream, e.Unpriced, e.Alert = stream != 0, unpriced != 0, alert != 0
	e.RouteApplied = routeApplied != 0
	if findings.Valid {
		json.Unmarshal([]byte(findings.String), &e.Findings)
	}
	if unreadable.Valid {
		json.Unmarshal([]byte(unreadable.String), &e.Unreadable)
	}
	if stages.Valid {
		json.Unmarshal([]byte(stages.String), &e.Stages)
	}
	if nearMiss.Valid {
		json.Unmarshal([]byte(nearMiss.String), &e.NearMiss)
	}
	return e, nil
}

func (d *DB) ListEvents(ctx context.Context, f store.EventFilter) ([]store.Event, error) {
	q := `SELECT ` + eventCols + ` FROM events WHERE ts >= ? AND ts < ? AND (? = '' OR team_name = ?)`
	args := []any{f.From.UnixMilli(), f.To.UnixMilli(), f.Team, f.Team}
	if !f.Before.IsZero() {
		q += ` AND ts < ?`
		args = append(args, f.Before.UnixMilli())
	}
	if f.Outcome != "" {
		q += ` AND outcome = ?`
		args = append(args, f.Outcome)
	}
	if f.Cache != "" {
		q += ` AND cache = ?`
		args = append(args, f.Cache)
	}
	if f.KeyID != "" {
		q += ` AND key_id = ?`
		args = append(args, f.KeyID)
	}
	if f.User != "" {
		q += ` AND user_id = ?`
		args = append(args, f.User)
	}
	if f.Model != "" {
		q += ` AND (model_requested = ? OR model_served = ?)`
		args = append(args, f.Model, f.Model)
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q += ` ORDER BY ts DESC LIMIT ` + strconv.Itoa(limit)
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		e.Payload = nil
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) GetEvent(ctx context.Context, id string) (*store.Event, error) {
	e, err := scanEvent(d.db.QueryRowContext(ctx, `SELECT `+eventCols+` FROM events WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (d *DB) DeleteEventsBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := d.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, t.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *DB) SetCredentialRegion(ctx context.Context, name, region string) (bool, error) {
	res, err := d.db.ExecContext(ctx, `UPDATE provider_credentials SET region = ? WHERE name = ?`, region, name)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, d.BumpConfigVersion(ctx)
	}
	return false, nil
}

// ---- data handling (GV-4) ----

func (d *DB) CountEvents(ctx context.Context, f store.PurgeFilter) (int64, error) {
	if f.Empty() {
		return 0, store.ErrEmptyPurge
	}
	where, args := f.Where()
	var n int64
	err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE `+where, args...).Scan(&n)
	return n, err
}

func (d *DB) PurgeEvents(ctx context.Context, f store.PurgeFilter) (int64, error) {
	if f.Empty() {
		return 0, store.ErrEmptyPurge
	}
	where, args := f.Where()
	q := `DELETE FROM events WHERE ` + where
	if f.PayloadsOnly {
		q = `UPDATE events SET payload = NULL WHERE ` + where
	}
	res, err := d.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *DB) DeleteAdminBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := d.db.ExecContext(ctx, `DELETE FROM admin_actions WHERE ts < ?`, t.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *DB) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := d.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *DB) RecordCachePurge(ctx context.Context, label string, at time.Time) (int64, error) {
	var seq int64
	if err := d.db.QueryRowContext(ctx, `INSERT INTO cache_purges(ts, label) VALUES (?, ?) RETURNING seq`, at.UnixMilli(), label).Scan(&seq); err != nil {
		return 0, err
	}
	// Running gateways look for purges when the configuration changes.
	return seq, d.BumpConfigVersion(ctx)
}

func (d *DB) CachePurgesSince(ctx context.Context, seq int64) ([]store.CachePurge, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT seq, ts, label FROM cache_purges WHERE seq > ? ORDER BY seq LIMIT 10000`, seq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.CachePurge
	for rows.Next() {
		var p store.CachePurge
		var ts int64
		if err := rows.Scan(&p.Seq, &ts, &p.Label); err != nil {
			return nil, err
		}
		p.Time = time.UnixMilli(ts)
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---- end-user identity (AC-3) ----

func (d *DB) SetKeyUserSecret(ctx context.Context, idOrName string, sealed []byte) (bool, error) {
	res, err := d.db.ExecContext(ctx, `UPDATE virtual_keys SET user_secret = ? WHERE (id = ? OR name = ?) AND revoked_at IS NULL`, sealed, idOrName, idOrName)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, d.BumpConfigVersion(ctx)
	}
	return false, nil
}

func (d *DB) SetKeyRequireUser(ctx context.Context, idOrName string, required bool) (bool, error) {
	res, err := d.db.ExecContext(ctx, `UPDATE virtual_keys SET require_user = ? WHERE (id = ? OR name = ?) AND revoked_at IS NULL`, b2i(required), idOrName, idOrName)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, d.BumpConfigVersion(ctx)
	}
	return false, nil
}

// ---- the audit ledger (GV-3) ----

var _ store.Ledger = (*DB)(nil)

// adminID gives a new administration record its ID.
func adminID(id string) string {
	if id != "" {
		return id
	}
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (d *DB) UnsealedEvents(ctx context.Context, limit int) ([]store.Event, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT `+eventCols+` FROM events WHERE sealed = 0 ORDER BY ts, id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) UnsealedAdmin(ctx context.Context, limit int) ([]store.AdminAction, error) {
	return d.adminRows(ctx, `WHERE sealed = 0 ORDER BY ts, id LIMIT ?`, limit)
}

func (d *DB) adminRows(ctx context.Context, where string, args ...any) ([]store.AdminAction, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT id, ts, actor, action, target, COALESCE(detail, ''), COALESCE(data, '') FROM admin_actions `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.AdminAction
	for rows.Next() {
		var a store.AdminAction
		var ts int64
		if err := rows.Scan(&a.ID, &ts, &a.Actor, &a.Action, &a.Target, &a.Detail, &a.Data); err != nil {
			return nil, err
		}
		a.Time = time.UnixMilli(ts)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) Seal(ctx context.Context, entries []store.LedgerEntry, eventIDs, adminIDs []string) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	exec := func(q string, args ...any) error {
		_, err := tx.ExecContext(ctx, (q), args...)
		return err
	}
	for _, e := range entries {
		if err := exec(`INSERT INTO audit_ledger(seq, ts, kind, ref, digest, scope, prev, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			e.Seq, e.Time.UnixMilli(), e.Kind, e.Ref, e.Digest, e.Scope, e.Prev, e.Hash); err != nil {
			tx.Rollback()
			return err
		}
	}
	for _, id := range eventIDs {
		if err := exec(`UPDATE events SET sealed = 1 WHERE id = ?`, id); err != nil {
			tx.Rollback()
			return err
		}
	}
	for _, id := range adminIDs {
		if err := exec(`UPDATE admin_actions SET sealed = 1 WHERE id = ?`, id); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

const ledgerCols = `seq, ts, kind, ref, digest, scope, prev, hash`

func scanLedger(s interface{ Scan(...any) error }) (store.LedgerEntry, error) {
	var e store.LedgerEntry
	var ts int64
	err := s.Scan(&e.Seq, &ts, &e.Kind, &e.Ref, &e.Digest, &e.Scope, &e.Prev, &e.Hash)
	e.Time = time.UnixMilli(ts)
	return e, err
}

func (d *DB) LedgerHead(ctx context.Context) (store.LedgerEntry, error) {
	e, err := scanLedger(d.db.QueryRowContext(ctx, `SELECT `+ledgerCols+` FROM audit_ledger ORDER BY seq DESC LIMIT 1`))
	if errors.Is(err, sql.ErrNoRows) {
		return e, store.ErrNotFound
	}
	return e, err
}

func (d *DB) LedgerAfter(ctx context.Context, seq int64, limit int) ([]store.LedgerEntry, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT `+ledgerCols+` FROM audit_ledger WHERE seq > ? ORDER BY seq LIMIT ?`, seq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.LedgerEntry
	for rows.Next() {
		e, err := scanLedger(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// inList returns "?, ?, ..." for n values.
func inList(n int) string {
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}

func (d *DB) GetEvents(ctx context.Context, ids []string) (map[string]store.Event, error) {
	out := make(map[string]store.Event, len(ids))
	for i := 0; i < len(ids); i += 500 {
		batch := ids[i:min(i+500, len(ids))]
		args := make([]any, len(batch))
		for j, id := range batch {
			args[j] = id
		}
		rows, err := d.db.QueryContext(ctx, `SELECT `+eventCols+` FROM events WHERE id IN (`+inList(len(batch))+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			e, err := scanEvent(rows)
			if err != nil {
				rows.Close()
				return nil, err
			}
			out[e.ID] = e
		}
		rows.Close()
	}
	return out, nil
}

func (d *DB) GetAdmin(ctx context.Context, ids []string) (map[string]store.AdminAction, error) {
	out := make(map[string]store.AdminAction, len(ids))
	for i := 0; i < len(ids); i += 500 {
		batch := ids[i:min(i+500, len(ids))]
		args := make([]any, len(batch))
		for j, id := range batch {
			args[j] = id
		}
		as, err := d.adminRows(ctx, `WHERE id IN (`+inList(len(batch))+`)`, args...)
		if err != nil {
			return nil, err
		}
		for _, a := range as {
			out[a.ID] = a
		}
	}
	return out, nil
}

func (d *DB) countSealed(ctx context.Context, sealed int) (int64, int64, error) {
	var ev, ad int64
	if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE sealed = ?`, sealed).Scan(&ev); err != nil {
		return 0, 0, err
	}
	err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_actions WHERE sealed = ?`, sealed).Scan(&ad)
	return ev, ad, err
}

func (d *DB) CountSealed(ctx context.Context) (int64, int64, error)   { return d.countSealed(ctx, 1) }
func (d *DB) CountUnsealed(ctx context.Context) (int64, int64, error) { return d.countSealed(ctx, 0) }

// ---- policy documents ----

var _ store.PolicyStore = (*DB)(nil)

func (d *DB) GetPolicy(ctx context.Context, id string) (store.PolicyDoc, error) {
	doc := store.PolicyDoc{ID: id}
	var ts int64
	err := d.db.QueryRowContext(ctx, `SELECT body, updated_at, updated_by FROM policies WHERE id = ?`, id).Scan(&doc.Body, &ts, &doc.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return doc, store.ErrNotFound
	}
	doc.Updated = time.UnixMilli(ts)
	return doc, err
}

func (d *DB) ListPolicies(ctx context.Context) ([]store.PolicyDoc, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT id, body, updated_at, updated_by FROM policies ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.PolicyDoc
	for rows.Next() {
		var doc store.PolicyDoc
		var ts int64
		if err := rows.Scan(&doc.ID, &doc.Body, &ts, &doc.UpdatedBy); err != nil {
			return nil, err
		}
		doc.Updated = time.UnixMilli(ts)
		out = append(out, doc)
	}
	return out, rows.Err()
}

// historyThenChange keeps the current version of a document in the history,
// then runs change, in one transaction.
func (d *DB) historyThenChange(ctx context.Context, id, actor string, change func(tx *sql.Tx) (bool, error)) (bool, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, (`INSERT INTO policy_history(id, body, updated_at, updated_by, replaced_at, replaced_by)
		SELECT id, body, updated_at, updated_by, ?, ? FROM policies WHERE id = ?`), time.Now().UnixMilli(), actor, id); err != nil {
		tx.Rollback()
		return false, err
	}
	ok, err := change(tx)
	if err != nil {
		tx.Rollback()
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	if ok {
		return true, d.BumpConfigVersion(ctx)
	}
	return false, nil
}

func (d *DB) PutPolicy(ctx context.Context, doc store.PolicyDoc) error {
	if doc.Updated.IsZero() {
		doc.Updated = time.Now()
	}
	_, err := d.historyThenChange(ctx, doc.ID, doc.UpdatedBy, func(tx *sql.Tx) (bool, error) {
		_, err := tx.ExecContext(ctx, (`INSERT INTO policies(id, body, updated_at, updated_by) VALUES (?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET body = excluded.body, updated_at = excluded.updated_at, updated_by = excluded.updated_by`),
			doc.ID, doc.Body, doc.Updated.UnixMilli(), doc.UpdatedBy)
		return true, err
	})
	return err
}

func (d *DB) DeletePolicy(ctx context.Context, id, actor string) (bool, error) {
	return d.historyThenChange(ctx, id, actor, func(tx *sql.Tx) (bool, error) {
		res, err := tx.ExecContext(ctx, (`DELETE FROM policies WHERE id = ?`), id)
		if err != nil {
			return false, err
		}
		n, _ := res.RowsAffected()
		return n > 0, nil
	})
}
