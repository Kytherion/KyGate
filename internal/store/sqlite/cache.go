package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
)

// CacheDB is the exact-cache store of the Solo profile: a SQLite file of its
// own (cache.db), never a table in the configuration and event database.
// Cache entries are rewritten often and can be thrown away at any time; the
// other data cannot (architecture §4.5, §4.10).
//
// It holds sealed entries only: compressed, then encrypted under the
// per-organization key, and keyed by a keyed fingerprint. Deleting the file
// while KyGate is stopped is a safe purge.
type CacheDB struct {
	db *sql.DB
}

var (
	_ store.CacheStore    = (*CacheDB)(nil)
	_ store.SemanticStore = (*CacheDB)(nil)
)

// cacheMigrations are the schema of cache.db. Like the main database, an
// upgrade appends to the list and never edits an earlier entry.
var cacheMigrations = []string{
	`CREATE TABLE entries (
	   key TEXT PRIMARY KEY, org_id TEXT NOT NULL, sealed BLOB NOT NULL,
	   size INTEGER NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL);
	 CREATE INDEX entries_expires ON entries(expires);
	 CREATE INDEX entries_used ON entries(used);`,
	// The semantic cache: sealed entries grouped by context fingerprint.
	`CREATE TABLE semantic (
	   key TEXT PRIMARY KEY, context TEXT NOT NULL, org_id TEXT NOT NULL, sealed BLOB NOT NULL,
	   size INTEGER NOT NULL, expires INTEGER NOT NULL, created INTEGER NOT NULL);
	 CREATE INDEX semantic_context ON semantic(context, created);
	 CREATE INDEX semantic_expires ON semantic(expires);`,
	// labels for purges (GV-4), keyed hashes, " a b ".
	`ALTER TABLE entries ADD COLUMN labels TEXT NOT NULL DEFAULT '';
	 ALTER TABLE semantic ADD COLUMN labels TEXT NOT NULL DEFAULT '';`,
}

// OpenCache opens or creates the cache file. A file that is damaged, or that
// a newer KyGate wrote, returns an error; the caller then runs on the
// in-process cache alone.
func OpenCache(path string) (*CacheDB, error) {
	// auto_vacuum must be set before the first table is created; it lets Trim
	// give the space of deleted entries back to the file system.
	dsn := "file:" + path + "?_pragma=auto_vacuum(INCREMENTAL)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if err := migrate(db, cacheMigrations); err != nil {
		db.Close()
		return nil, err
	}
	return &CacheDB{db: db}, nil
}

// Close closes the file.
func (c *CacheDB) Close() error { return c.db.Close() }

func (c *CacheDB) GetEntry(ctx context.Context, key string) (store.CacheRecord, error) {
	r := store.CacheRecord{Key: key}
	var expires int64
	err := c.db.QueryRowContext(ctx, `SELECT org_id, sealed, expires FROM entries WHERE key = ?`, key).Scan(&r.OrgID, &r.Sealed, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return r, store.ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.Expires = time.UnixMilli(expires)
	return r, nil
}

func (c *CacheDB) PutEntries(ctx context.Context, recs []store.CacheRecord) error {
	if len(recs) == 0 {
		return nil
	}
	now := time.Now().UnixMilli()
	return c.inTx(ctx, `INSERT INTO entries(key, org_id, sealed, size, expires, used, labels) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET org_id = excluded.org_id, sealed = excluded.sealed, size = excluded.size,
		  expires = excluded.expires, used = excluded.used, labels = excluded.labels`, len(recs), func(i int) []any {
		r := recs[i]
		return []any{r.Key, r.OrgID, r.Sealed, len(r.Sealed), r.Expires.UnixMilli(), now, store.JoinLabels(r.Labels)}
	})
}

func (c *CacheDB) TouchEntries(ctx context.Context, keys []string, at time.Time) error {
	ms := at.UnixMilli()
	return c.inTx(ctx, `UPDATE entries SET used = ? WHERE key = ? AND used < ?`, len(keys), func(i int) []any {
		return []any{ms, keys[i], ms}
	})
}

func (c *CacheDB) DeleteEntries(ctx context.Context, keys []string) error {
	return c.inTx(ctx, `DELETE FROM entries WHERE key = ?`, len(keys), func(i int) []any { return []any{keys[i]} })
}

// inTx runs one statement n times in one transaction: one disk sync per batch.
func (c *CacheDB) inTx(ctx context.Context, query string, n int, args func(i int) []any) error {
	if n == 0 {
		return nil
	}
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for i := 0; i < n; i++ {
		if _, err := stmt.ExecContext(ctx, args(i)...); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// Trim deletes expired entries, then the least recently used entries until
// the file holds at most maxBytes. The size counted is the pages in use,
// which includes the overhead of rows and indexes, so the limit holds for the
// file itself. It trims to 90% of the limit, so that it does not run again at
// the next write.
func (c *CacheDB) Trim(ctx context.Context, now time.Time, maxBytes int64) (int64, error) {
	res, err := c.db.ExecContext(ctx, `DELETE FROM entries WHERE expires <= ?`, now.UnixMilli())
	if err != nil {
		return 0, err
	}
	removed, _ := res.RowsAffected()

	if maxBytes > 0 {
		used, err := c.usedBytes(ctx)
		if err != nil {
			return removed, err
		}
		if used > maxBytes {
			var sum int64
			if err := c.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(size), 0) FROM entries`).Scan(&sum); err != nil {
				return removed, err
			}
			// Entry bytes to remove, scaled from file bytes to entry bytes.
			target := maxBytes * 9 / 10
			drop := sum - sum*target/used
			if drop > 0 {
				res, err := c.db.ExecContext(ctx, `DELETE FROM entries WHERE key IN (
					SELECT key FROM (SELECT key, size, SUM(size) OVER (ORDER BY used, key ROWS UNBOUNDED PRECEDING) AS run FROM entries)
					WHERE run - size < ?)`, drop)
				if err != nil {
					return removed, err
				}
				n, _ := res.RowsAffected()
				removed += n
			}
		}
	}
	if removed > 0 {
		// Give freed pages back to the file system. A failure only leaves the file larger.
		c.db.ExecContext(ctx, `PRAGMA incremental_vacuum`)
		c.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	}
	return removed, nil
}

// usedBytes is the size of the pages that hold data.
func (c *CacheDB) usedBytes(ctx context.Context) (int64, error) {
	var pages, free, size int64
	if err := c.db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pages); err != nil {
		return 0, err
	}
	if err := c.db.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&free); err != nil {
		return 0, err
	}
	if err := c.db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&size); err != nil {
		return 0, err
	}
	return (pages - free) * size, nil
}

// ---- semantic cache ----

func (c *CacheDB) ListSemantic(ctx context.Context, org, context string, now time.Time, limit int) ([]store.SemanticRecord, error) {
	rows, err := c.db.QueryContext(ctx, `SELECT key, sealed, expires FROM semantic
		WHERE context = ? AND org_id = ? AND expires > ? ORDER BY created DESC LIMIT ?`, context, org, now.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.SemanticRecord
	for rows.Next() {
		r := store.SemanticRecord{Context: context, OrgID: org}
		var expires int64
		if err := rows.Scan(&r.Key, &r.Sealed, &expires); err != nil {
			return nil, err
		}
		r.Expires = time.UnixMilli(expires)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (c *CacheDB) PutSemantic(ctx context.Context, r store.SemanticRecord) error {
	_, err := c.db.ExecContext(ctx, `INSERT INTO semantic(key, context, org_id, sealed, size, expires, created, labels) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET context = excluded.context, org_id = excluded.org_id, sealed = excluded.sealed,
		  size = excluded.size, expires = excluded.expires, created = excluded.created, labels = excluded.labels`,
		r.Key, r.Context, r.OrgID, r.Sealed, len(r.Sealed), r.Expires.UnixMilli(), time.Now().UnixMilli(), store.JoinLabels(r.Labels))
	return err
}

func (c *CacheDB) TrimSemantic(ctx context.Context, now time.Time, maxEntries int) (int64, error) {
	res, err := c.db.ExecContext(ctx, `DELETE FROM semantic WHERE expires <= ?`, now.UnixMilli())
	if err != nil {
		return 0, err
	}
	removed, _ := res.RowsAffected()
	if maxEntries > 0 {
		res, err := c.db.ExecContext(ctx, `DELETE FROM semantic WHERE key IN (
			SELECT key FROM semantic ORDER BY created DESC LIMIT -1 OFFSET ?)`, maxEntries)
		if err != nil {
			return removed, err
		}
		n, _ := res.RowsAffected()
		removed += n
	}
	return removed, nil
}

func (c *CacheDB) SemanticStats(ctx context.Context) (store.CacheStoreStats, error) {
	var s store.CacheStoreStats
	err := c.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(size), 0) FROM semantic`).Scan(&s.Entries, &s.Bytes)
	return s, err
}

func (c *CacheDB) Stats(ctx context.Context) (store.CacheStoreStats, error) {
	var s store.CacheStoreStats
	err := c.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(size), 0) FROM entries`).Scan(&s.Entries, &s.Bytes)
	return s, err
}

// Purge deletes the exact entries with a label, or all of them (GV-4).
func (c *CacheDB) Purge(ctx context.Context, label string) (int64, error) {
	return c.purge(ctx, "entries", label)
}

// PurgeSemantic deletes the semantic entries with a label, or all of them.
func (c *CacheDB) PurgeSemantic(ctx context.Context, label string) (int64, error) {
	return c.purge(ctx, "semantic", label)
}

func (c *CacheDB) purge(ctx context.Context, table, label string) (int64, error) {
	q, args := `DELETE FROM `+table, []any{}
	if label != "" {
		q, args = q+` WHERE instr(labels, ?) > 0`, []any{" " + label + " "}
	}
	res, err := c.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		c.db.ExecContext(ctx, `PRAGMA incremental_vacuum`)
	}
	return n, nil
}
