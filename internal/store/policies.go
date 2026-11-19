package store

// Policy documents in the configuration database. With
// PostgreSQL, policies live here instead of files next to policy.yaml, so
// that every gateway, in any number of pods, reads the same version without
// a shared volume. Each write keeps the previous version in a history.

import (
	"context"
	"time"
)

// PolicyDoc is one policy document: "org", or a level's "team-NAME",
// "project-NAME", or "key-NAME".
type PolicyDoc struct {
	ID        string    `json:"id"`
	Body      []byte    `json:"-"`
	Updated   time.Time `json:"updated"`
	UpdatedBy string    `json:"updated_by"`
}

// PolicyStore holds policy documents.
type PolicyStore interface {
	// GetPolicy returns ErrNotFound when there is no such document.
	GetPolicy(ctx context.Context, id string) (PolicyDoc, error)
	ListPolicies(ctx context.Context) ([]PolicyDoc, error)
	// PutPolicy writes a document, keeping the previous version in the
	// history, and changes the configuration version so gateways reload.
	PutPolicy(ctx context.Context, d PolicyDoc) error
	// DeletePolicy moves a document into the history.
	DeletePolicy(ctx context.Context, id, actor string) (bool, error)
}
