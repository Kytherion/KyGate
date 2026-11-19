package store

import (
	"context"
	"database/sql"
	"time"
)

// Quality signals (OB-4): what callers say about answers. An application
// rates an answer by its request ID (X-KyGate-Request-Id), with a fixed
// reason, never free text. The report joins ratings with their events, and
// counts a rating only when the key that sent it is the key that made the
// request.

// Feedback ratings and reasons.
var (
	FeedbackRatings = []string{"bad", "good"}
	FeedbackReasons = []string{"wrong", "outdated", "incomplete", "unsafe", "off_topic", "other"}
)

// Feedback is one rating of one answer.
type Feedback struct {
	RequestID string
	KeyID     string // the key that sent the rating
	Time      time.Time
	Rating    string // bad | good
	Reason    string // one of FeedbackReasons, or empty
}

// QualityRow counts ratings of answers served one way.
type QualityRow struct {
	Served   string `json:"served"`   // exact | semantic | model
	Model    string `json:"model"`    // the model that wrote the answer
	Routable bool   `json:"routable"` // the router would have sent it to a cheaper model
	Rating   string `json:"rating"`
	Reason   string `json:"reason,omitempty"`
	Count    int64  `json:"count"`
}

// QualityStore keeps ratings.
type QualityStore interface {
	// PutFeedback records a rating; a second rating of the same request by
	// the same key replaces the first.
	PutFeedback(ctx context.Context, f Feedback) error
	Quality(ctx context.Context, r Range) ([]QualityRow, error)
	DeleteFeedbackBefore(ctx context.Context, t time.Time) (int64, error)
}

// SQLQuality implements QualityStore over database/sql for both drivers.
type SQLQuality struct {
	DB     *sql.DB
	Rebind func(string) string
}

func (s SQLQuality) q(query string) string {
	if s.Rebind == nil {
		return query
	}
	return s.Rebind(query)
}

func (s SQLQuality) PutFeedback(ctx context.Context, f Feedback) error {
	_, err := s.DB.ExecContext(ctx, s.q(`INSERT INTO feedback(request_id, key_id, ts, rating, reason) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(request_id, key_id) DO UPDATE SET ts = excluded.ts, rating = excluded.rating, reason = excluded.reason`),
		f.RequestID, f.KeyID, f.Time.UnixMilli(), f.Rating, f.Reason)
	return err
}

func (s SQLQuality) Quality(ctx context.Context, r Range) ([]QualityRow, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(`SELECT
		CASE WHEN e.cache = 'hit' THEN 'exact' WHEN e.semantic = 'hit' THEN 'semantic' ELSE 'model' END,
		COALESCE(NULLIF(e.model_served, ''), e.model_requested, ''),
		CASE WHEN COALESCE(e.route_model, '') <> '' THEN 1 ELSE 0 END,
		f.rating, f.reason, COUNT(*)
		FROM feedback f JOIN events e ON e.id = f.request_id AND e.key_id = f.key_id
		WHERE e.ts >= ? AND e.ts < ? AND (? = '' OR e.team_name = ?)
		GROUP BY 1, 2, 3, 4, 5 ORDER BY 6 DESC`), r.From.UnixMilli(), r.To.UnixMilli(), r.Team, r.Team)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QualityRow
	for rows.Next() {
		var q QualityRow
		var routable int
		if err := rows.Scan(&q.Served, &q.Model, &routable, &q.Rating, &q.Reason, &q.Count); err != nil {
			return nil, err
		}
		q.Routable = routable != 0
		out = append(out, q)
	}
	return out, rows.Err()
}

func (s SQLQuality) DeleteFeedbackBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx, s.q(`DELETE FROM feedback WHERE ts < ?`), t.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
