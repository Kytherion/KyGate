package pipeline

// Quality signals (OB-4): an application rates an answer it got through
// KyGate, by the answer's request ID (X-KyGate-Request-Id):
//
//	POST /kygate/v1/feedback   {"request_id": "...", "rating": "bad", "reason": "wrong"}
//
// with the same virtual key that made the request. A rating carries a fixed
// reason, never free text: a comment could hold personal data. A second
// rating of the same request by the same key replaces the first. The report
// counts a rating only when its key made the request. This endpoint is not
// the request path of a model call; it writes to the database directly.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/Kytherion/KyGate/internal/identity"
	"github.com/Kytherion/KyGate/internal/ingress"
	"github.com/Kytherion/KyGate/internal/store"
)

func (g *Gateway) feedback(w http.ResponseWriter, r *http.Request) {
	if g.Feedback == nil {
		writeError(w, ingress.OpenAI, 404, "not_found", "feedback is not available on this gateway")
		return
	}
	caller, ok := g.Keys.Resolve(identity.FromRequest(r))
	if !ok {
		writeError(w, ingress.OpenAI, 401, "invalid_api_key", "KyGate did not recognize this API key. Use the virtual key that made the request.")
		return
	}
	var in struct {
		RequestID string `json:"request_id"`
		Rating    string `json:"rating"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&in); err != nil {
		writeError(w, ingress.OpenAI, 400, "invalid_request_error", "the body must be JSON: {\"request_id\", \"rating\": \"bad\" or \"good\", \"reason\"}")
		return
	}
	if !validRequestID(in.RequestID) {
		writeError(w, ingress.OpenAI, 400, "invalid_request_error", "request_id must be the X-KyGate-Request-Id of an answer")
		return
	}
	if !slices.Contains(store.FeedbackRatings, in.Rating) {
		writeError(w, ingress.OpenAI, 400, "invalid_request_error", "rating must be bad or good")
		return
	}
	if in.Reason != "" && !slices.Contains(store.FeedbackReasons, in.Reason) {
		writeError(w, ingress.OpenAI, 400, "invalid_request_error", "reason must be one of wrong, outdated, incomplete, unsafe, off_topic, other (free text is not accepted)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := g.Feedback.PutFeedback(ctx, store.Feedback{RequestID: in.RequestID, KeyID: caller.KeyID, Time: time.Now(), Rating: in.Rating, Reason: in.Reason}); err != nil {
		g.Logf("feedback: %v", err)
		writeError(w, ingress.OpenAI, 503, "unavailable", "KyGate could not record the rating; try again")
		return
	}
	g.Metrics.Add("kygate_feedback_total", 1, "rating", in.Rating)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(202)
	w.Write([]byte(`{"ok":true}`))
}

// validRequestID accepts the IDs KyGate gives: letters, digits, - and _.
func validRequestID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
