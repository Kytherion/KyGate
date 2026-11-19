// Package audit makes the audit trail tamper-evident and sends it to SIEMs
// (GV-3).
//
// Three keys, each derived from the master key per organization:
//
//   - the event key: each gateway signs every event it records (Event.MAC),
//     so a row written into the database behind KyGate's back is told apart
//     from one a gateway wrote;
//   - the digest key: the ledger keeps a keyed digest of each event and each
//     administration record, never its content;
//   - the chain key: each ledger row's hash covers the previous row's hash.
//
// The control process seals new rows into the ledger every few seconds
// (Sealer). Verify walks the ledger: a broken chain, an altered or missing
// row, a forged event, or a row that claims to be sealed without a ledger
// entry is reported; a row removed by a recorded retention run or purge is
// not. Ledger heads go to SIEMs with every record, so even someone holding
// the master key cannot rewrite history without the copy disagreeing.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
)

// Keys are the per-organization keys of the audit trail.
type Keys struct {
	event, digest, chain []byte
}

// NewKeys derives the keys from the master key.
func NewKeys(master []byte, org string) Keys {
	return Keys{
		event:  store.DeriveKey(master, "audit-event", org),
		digest: store.DeriveKey(master, "audit-digest", org),
		chain:  store.DeriveKey(master, "audit-chain", org),
	}
}

func mac(key []byte, parts ...[]byte) string {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		fmt.Fprintf(m, "%d:", len(p))
		m.Write(p)
	}
	return hex.EncodeToString(m.Sum(nil))
}

// Canonical is the form of an event that is signed and digested: every
// recorded field except the captured payload (which a purge may remove, and
// which is sealed under its own key bound to the event ID) and the signature
// itself, with the time in milliseconds as the database keeps it.
func Canonical(e store.Event) []byte {
	ms := e.Time.UnixMilli()
	e.Time, e.Payload, e.MAC, e.Extra = time.Time{}, nil, "", nil
	b, _ := json.Marshal(struct {
		TS int64       `json:"ts_ms"`
		E  store.Event `json:"e"`
	}{ms, e})
	return b
}

// Sign returns an event's gateway signature.
func (k Keys) Sign(e store.Event) string { return mac(k.event, []byte("event"), Canonical(e)) }

// Signed reports whether an event carries a valid signature; unsigned events
// (recorded before signing began) report false, false.
func (k Keys) Signed(e store.Event) (signed, valid bool) {
	if e.MAC == "" {
		return false, false
	}
	return true, hmac.Equal([]byte(e.MAC), []byte(k.Sign(e)))
}

// EventDigest is the ledger's digest of an event.
func (k Keys) EventDigest(e store.Event) string {
	return mac(k.digest, []byte("event"), Canonical(e))
}

// AdminDigest is the ledger's digest of an administration record.
func (k Keys) AdminDigest(a store.AdminAction) string {
	return mac(k.digest, []byte("admin"), []byte(a.ID), []byte(fmt.Sprint(a.Time.UnixMilli())),
		[]byte(a.Actor), []byte(a.Action), []byte(a.Target), []byte(a.Detail), []byte(a.Data))
}

// Genesis is the previous hash of the first ledger entry.
const Genesis = "genesis"

// EntryHash is the hash of a ledger entry, chained to the previous one.
func (k Keys) EntryHash(e store.LedgerEntry) string {
	return mac(k.chain, []byte(fmt.Sprint(e.Seq)), []byte(fmt.Sprint(e.Time.UnixMilli())), []byte(e.Kind),
		[]byte(e.Ref), []byte(e.Digest), []byte(e.Scope), []byte(e.Prev))
}

// eventScope is the metadata a verification needs to tell which purge
// removed an event: never a value.
type eventScope struct {
	Key     string `json:"k,omitempty"`
	Team    string `json:"t,omitempty"`
	Project string `json:"p,omitempty"`
	User    string `json:"u,omitempty"`
}

// RetentionData is what a retention run records for the ledger: the cutoffs
// it applied, in Unix milliseconds.
type RetentionData struct {
	EventsBefore   int64 `json:"events_before,omitempty"`
	PayloadsBefore int64 `json:"payloads_before,omitempty"`
	AdminBefore    int64 `json:"admin_before,omitempty"`
}

// Administration actions whose records carry ledger data.
const (
	ActionPurgeEvents = "purge.events"
	ActionRetention   = "retention"
)
