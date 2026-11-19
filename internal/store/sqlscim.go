package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// SQLSCIM implements SCIMStore over database/sql for both drivers, which pass
// their own placeholder rewriting and duplicate-key test. Their migrations
// create scim_resources and scim_members.
type SQLSCIM struct {
	DB     *sql.DB
	Rebind func(string) string // ? placeholders to the driver's; nil keeps them
	Unique func(error) bool    // whether an error is a duplicate key
}

func (s SQLSCIM) q(query string) string {
	if s.Rebind == nil {
		return query
	}
	return s.Rebind(query)
}

func scimKey(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

func (s SQLSCIM) CreateSCIM(ctx context.Context, r SCIMResource) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, s.q(`INSERT INTO scim_resources(id, kind, name, name_key, external_id, active, data, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		r.ID, r.Kind, r.Name, scimKey(r.Name), r.ExternalID, boolInt(r.Active), r.Data, r.Created.UnixMilli(), r.Updated.UnixMilli())
	if err != nil {
		if s.Unique(err) {
			return ErrConflict
		}
		return err
	}
	if err := s.putMembers(ctx, tx, r); err != nil {
		return err
	}
	return tx.Commit()
}

func (s SQLSCIM) ReplaceSCIM(ctx context.Context, r SCIMResource) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, s.q(`UPDATE scim_resources SET name = ?, name_key = ?, external_id = ?, active = ?, data = ?, updated_at = ?
		WHERE kind = ? AND id = ?`),
		r.Name, scimKey(r.Name), r.ExternalID, boolInt(r.Active), r.Data, r.Updated.UnixMilli(), r.Kind, r.ID)
	if err != nil {
		if s.Unique(err) {
			return ErrConflict
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if r.Kind == SCIMGroup {
		if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM scim_members WHERE group_id = ?`), r.ID); err != nil {
			return err
		}
		if err := s.putMembers(ctx, tx, r); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s SQLSCIM) putMembers(ctx context.Context, tx *sql.Tx, r SCIMResource) error {
	if r.Kind != SCIMGroup {
		return nil
	}
	seen := map[string]bool{}
	for _, m := range r.Members {
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO scim_members(group_id, user_id) VALUES (?, ?)`), r.ID, m); err != nil {
			return err
		}
	}
	return nil
}

func (s SQLSCIM) GetSCIM(ctx context.Context, kind, id string) (SCIMResource, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(`SELECT id, kind, name, external_id, active, data, created_at, updated_at FROM scim_resources WHERE kind = ? AND id = ?`), kind, id)
	if err != nil {
		return SCIMResource{}, err
	}
	out, err := s.scan(ctx, rows)
	if err != nil {
		return SCIMResource{}, err
	}
	if len(out) == 0 {
		return SCIMResource{}, ErrNotFound
	}
	return out[0], nil
}

func (s SQLSCIM) ListSCIM(ctx context.Context, kind string) ([]SCIMResource, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(`SELECT id, kind, name, external_id, active, data, created_at, updated_at FROM scim_resources WHERE kind = ? ORDER BY name_key`), kind)
	if err != nil {
		return nil, err
	}
	return s.scan(ctx, rows)
}

func (s SQLSCIM) scan(ctx context.Context, rows *sql.Rows) ([]SCIMResource, error) {
	var out []SCIMResource
	for rows.Next() {
		var r SCIMResource
		var active int
		var created, updated int64
		if err := rows.Scan(&r.ID, &r.Kind, &r.Name, &r.ExternalID, &active, &r.Data, &created, &updated); err != nil {
			rows.Close()
			return nil, err
		}
		r.Active, r.Created, r.Updated = active != 0, time.UnixMilli(created), time.UnixMilli(updated)
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Kind != SCIMGroup {
			continue
		}
		mrows, err := s.DB.QueryContext(ctx, s.q(`SELECT user_id FROM scim_members WHERE group_id = ? ORDER BY user_id`), out[i].ID)
		if err != nil {
			return nil, err
		}
		for mrows.Next() {
			var m string
			if err := mrows.Scan(&m); err != nil {
				mrows.Close()
				return nil, err
			}
			out[i].Members = append(out[i].Members, m)
		}
		mrows.Close()
	}
	return out, nil
}

func (s SQLSCIM) DeleteSCIM(ctx context.Context, kind, id string) (bool, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, s.q(`DELETE FROM scim_resources WHERE kind = ? AND id = ?`), kind, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	col := "user_id"
	if kind == SCIMGroup {
		col = "group_id"
	}
	if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM scim_members WHERE `+col+` = ?`), id); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// IsUniqueViolation reports a duplicate key in SQLite's or PostgreSQL's words.
func IsUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "UNIQUE") || strings.Contains(s, "duplicate key") || strings.Contains(s, "23505") || errors.Is(err, ErrConflict)
}
