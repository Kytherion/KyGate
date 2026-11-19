package postgres

import (
	"context"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
)

// The stores written once for both drivers (store.SQLSCIM, SQLFleet,
// SQLQuality), over this database.

// SCIM provisioning (GV-2).

var _ store.SCIMStore = (*DB)(nil)

func (d *DB) scim() store.SQLSCIM {
	return store.SQLSCIM{DB: d.db, Rebind: rebind, Unique: store.IsUniqueViolation}
}

func (d *DB) CreateSCIM(ctx context.Context, r store.SCIMResource) error {
	return d.scim().CreateSCIM(ctx, r)
}
func (d *DB) ReplaceSCIM(ctx context.Context, r store.SCIMResource) error {
	return d.scim().ReplaceSCIM(ctx, r)
}
func (d *DB) GetSCIM(ctx context.Context, kind, id string) (store.SCIMResource, error) {
	return d.scim().GetSCIM(ctx, kind, id)
}
func (d *DB) ListSCIM(ctx context.Context, kind string) ([]store.SCIMResource, error) {
	return d.scim().ListSCIM(ctx, kind)
}
func (d *DB) DeleteSCIM(ctx context.Context, kind, id string) (bool, error) {
	return d.scim().DeleteSCIM(ctx, kind, id)
}

// The fleet's heartbeats.

var _ store.FleetStore = (*DB)(nil)

func (d *DB) fleet() store.SQLFleet { return store.SQLFleet{DB: d.db, Rebind: rebind} }

func (d *DB) PutInstance(ctx context.Context, in store.Instance) error {
	return d.fleet().PutInstance(ctx, in)
}
func (d *DB) ListInstances(ctx context.Context) ([]store.Instance, error) {
	return d.fleet().ListInstances(ctx)
}
func (d *DB) DeleteInstancesBefore(ctx context.Context, t time.Time) (int64, error) {
	return d.fleet().DeleteInstancesBefore(ctx, t)
}

// Quality signals (OB-4).

var _ store.QualityStore = (*DB)(nil)

func (d *DB) quality() store.SQLQuality { return store.SQLQuality{DB: d.db, Rebind: rebind} }

func (d *DB) PutFeedback(ctx context.Context, f store.Feedback) error {
	return d.quality().PutFeedback(ctx, f)
}
func (d *DB) Quality(ctx context.Context, r store.Range) ([]store.QualityRow, error) {
	return d.quality().Quality(ctx, r)
}
func (d *DB) DeleteFeedbackBefore(ctx context.Context, t time.Time) (int64, error) {
	return d.quality().DeleteFeedbackBefore(ctx, t)
}
