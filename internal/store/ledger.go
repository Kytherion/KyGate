package store

// The audit ledger (GV-3): tamper evidence for usage and audit
// events and for the administration trail. The ledger is append-only and
// holds digests, never content: one row per event and per administration
// record, each chained to the previous row by a keyed hash. Retention and
// purges delete events, never ledger rows, and they are recorded in the
// ledger themselves, so a verification tells a recorded deletion from one
// made behind KyGate's back. One writer, the control process, seals rows in
// order (internal/audit).

import (
	"context"
	"time"
)

// LedgerEntry is one row of the ledger.
type LedgerEntry struct {
	Seq  int64     `json:"seq"`
	Time time.Time `json:"ts"` // the time of the event or record it seals
	// Kind is event (signed by its gateway), event_unsigned (recorded before
	// gateways signed events), event_forged (its gateway signature did not
	// match: sealed so that it is seen, and reported), admin, purge, or
	// retention.
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`    // the event ID or the administration record ID
	Digest string `json:"digest"` // keyed digest of the content
	// Scope is JSON: an event's key, team, project, and user (metadata, so a
	// verification can tell which purge removed it); a purge's filter; or
	// retention's cutoffs.
	Scope string `json:"scope,omitempty"`
	Prev  string `json:"prev"`
	Hash  string `json:"hash"`
}

// Ledger kinds.
const (
	LedgerEvent         = "event"
	LedgerEventUnsigned = "event_unsigned"
	LedgerEventForged   = "event_forged"
	LedgerAdmin         = "admin"
	LedgerPurge         = "purge"
	LedgerRetention     = "retention"
)

// Ledger is the store side of the audit ledger. Both database drivers
// implement it.
type Ledger interface {
	// UnsealedEvents and UnsealedAdmin return rows not in the ledger yet,
	// oldest first.
	UnsealedEvents(ctx context.Context, limit int) ([]Event, error)
	UnsealedAdmin(ctx context.Context, limit int) ([]AdminAction, error)
	// Seal appends entries and marks the rows they seal, in one transaction.
	Seal(ctx context.Context, entries []LedgerEntry, eventIDs, adminIDs []string) error
	// LedgerHead returns the last entry, or ErrNotFound for an empty ledger.
	LedgerHead(ctx context.Context) (LedgerEntry, error)
	LedgerAfter(ctx context.Context, seq int64, limit int) ([]LedgerEntry, error)
	// GetEvents and GetAdmin fetch rows by ID; absent IDs are left out.
	GetEvents(ctx context.Context, ids []string) (map[string]Event, error)
	GetAdmin(ctx context.Context, ids []string) (map[string]AdminAction, error)
	// CountSealed and CountUnsealed count events and administration records.
	CountSealed(ctx context.Context) (events, admin int64, err error)
	CountUnsealed(ctx context.Context) (events, admin int64, err error)
}
