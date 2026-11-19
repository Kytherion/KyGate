package store

import (
	"context"
	"errors"
	"time"
)

// SCIM provisioning (GV-2): users and groups that the company's identity
// provider creates, changes, and removes through SCIM 2.0. They are kept apart
// from the users list that administrators edit, which stays as it was.

// SCIM resource kinds.
const (
	SCIMUser  = "User"
	SCIMGroup = "Group"
)

// SCIMResource is one provisioned user or group.
type SCIMResource struct {
	ID         string // KyGate's ID, given at creation
	Kind       string // SCIMUser or SCIMGroup
	Name       string // userName (an email, in lower case) or the group's displayName; unique per kind, ignoring case
	ExternalID string // the identity provider's own ID, when it sends one
	Active     bool   // users; a group is always active
	Data       []byte // the attributes KyGate keeps, as JSON (never a password)
	Members    []string
	Created    time.Time
	Updated    time.Time
}

// ErrConflict is returned when a resource of the same kind already has the name.
var ErrConflict = errors.New("already exists")

// SCIMStore keeps provisioned users and groups. Members are user IDs; deleting
// a user takes it out of every group.
type SCIMStore interface {
	// CreateSCIM adds a resource; ErrConflict when its name is taken.
	CreateSCIM(ctx context.Context, r SCIMResource) error
	// ReplaceSCIM changes a resource (its members too, for a group);
	// ErrNotFound when absent, ErrConflict when the new name is taken.
	ReplaceSCIM(ctx context.Context, r SCIMResource) error
	GetSCIM(ctx context.Context, kind, id string) (SCIMResource, error) // ErrNotFound when absent
	ListSCIM(ctx context.Context, kind string) ([]SCIMResource, error)
	DeleteSCIM(ctx context.Context, kind, id string) (bool, error)
}
