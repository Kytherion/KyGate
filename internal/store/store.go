// Package store defines the interfaces behind every stateful dependency, and
// the encryption used for data at rest (principle 5, architecture §4.10).
//
// The Solo profile uses sqlite: the configuration and event database, and
// the exact-cache file, which is a database of its own (cache.db) because
// cache entries can be thrown away and the rest cannot. The Team profile uses
// postgres and valkey behind the same interfaces.
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// VirtualKey is a KyGate API key. Only its hash is stored (architecture §4.9).
type VirtualKey struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Hash      string     `json:"-"`
	Prefix    string     `json:"prefix"`
	OrgID     string     `json:"org_id"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	// ProjectID places the key in the hierarchy organization -> team ->
	// project -> key (AC-4); empty: directly under the organization.
	ProjectID string `json:"project_id,omitempty"`
	// End-user identity (AC-3). RequireUser refuses a request
	// that names no person. UserSecret is the key's signing secret for user
	// tokens, sealed under the master key; it is never returned.
	RequireUser bool   `json:"require_user,omitempty"`
	UserSecret  []byte `json:"-"`
	HasSecret   bool   `json:"user_tokens,omitempty"`
}

// AdminAction is one change made through the admin API, for the audit trail
// (GV-3). It names what changed, never a secret.
type AdminAction struct {
	ID     string    `json:"id,omitempty"` // set by the store
	Time   time.Time `json:"ts"`
	Actor  string    `json:"actor"`  // "admin token" until single sign-on
	Action string    `json:"action"` // such as team.create, key.revoke, policy.write
	Target string    `json:"target"`
	Detail string    `json:"detail,omitempty"`
	// Data is machine-readable detail for the audit ledger: a purge's
	// filter, or retention's cutoffs, as JSON. Never a value.
	Data string `json:"-"`
}

// User is a person who signs in to the console (AC-3, GV-2), by email, with a
// role; a team lead also has a team.
type User struct {
	Email     string     `json:"email"`
	Role      string     `json:"role"` // admin | security | finance | team_lead | viewer
	TeamID    string     `json:"team_id,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	LastLogin *time.Time `json:"last_login,omitempty"`
}

// Session is a signed-in console session. Only the hash of its token is
// stored, as for keys.
type Session struct {
	Hash    string
	Email   string // or "admin token"
	Role    string
	TeamID  string
	CSRF    string // the value the browser must echo on every change
	Created time.Time
	Expires time.Time
}

// Team is a group of projects (AC-4).
type Team struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	OrgID     string    `json:"org_id"`
	CreatedAt time.Time `json:"created_at"`
}

// Project is a group of keys, in a team or directly under the organization.
type Project struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	TeamID    string    `json:"team_id,omitempty"`
	OrgID     string    `json:"org_id"`
	CreatedAt time.Time `json:"created_at"`
}

// Credential is a stored provider credential, encrypted with envelope
// encryption: a random data key encrypts the secret, and the master key
// encrypts the data key.
type Credential struct {
	Name       string
	Provider   string
	BaseURL    string
	Region     string // where the endpoint processes data, such as eu; empty: unknown (GV-4)
	WrappedDEK []byte
	Ciphertext []byte
	CreatedAt  time.Time
}

// ConfigStore holds configuration: keys, credentials, settings.
type ConfigStore interface {
	Meta(ctx context.Context, key string) (string, error)
	SetMeta(ctx context.Context, key, value string) error
	// ConfigVersion changes whenever keys or credentials change, so that a
	// running gateway picks up a change made from the command line.
	ConfigVersion(ctx context.Context) (int64, error)
	BumpConfigVersion(ctx context.Context) error

	CreateKey(ctx context.Context, k VirtualKey) error
	ListKeys(ctx context.Context) ([]VirtualKey, error)
	RevokeKey(ctx context.Context, idOrName string) (bool, error)

	// The hierarchy (AC-4). Names are unique per kind. A team with projects,
	// or a project with active keys, cannot be deleted.
	CreateTeam(ctx context.Context, t Team) error
	ListTeams(ctx context.Context) ([]Team, error)
	DeleteTeam(ctx context.Context, name string) (bool, error)
	CreateProject(ctx context.Context, p Project) error
	ListProjects(ctx context.Context) ([]Project, error)
	DeleteProject(ctx context.Context, name string) (bool, error)
	// SetKeyProject moves a key (by ID or name) into a project; "" takes it out.
	SetKeyProject(ctx context.Context, idOrName, projectID string) (bool, error)
	// SetKeyUserSecret stores a key's sealed signing secret for user tokens
	// (nil removes it); SetKeyRequireUser sets whether it needs one (AC-3).
	SetKeyUserSecret(ctx context.Context, idOrName string, sealed []byte) (bool, error)
	SetKeyRequireUser(ctx context.Context, idOrName string, required bool) (bool, error)

	// People and their console sessions (AC-3, GV-2).
	PutUser(ctx context.Context, u User) error
	GetUser(ctx context.Context, email string) (User, error) // ErrNotFound when absent
	ListUsers(ctx context.Context) ([]User, error)
	DeleteUser(ctx context.Context, email string) (bool, error)
	TouchUser(ctx context.Context, email string, at time.Time) error
	CreateSession(ctx context.Context, s Session) error
	GetSession(ctx context.Context, hash string) (Session, error) // ErrNotFound when absent or expired
	DeleteSession(ctx context.Context, hash string) error
	// DeleteSessionsOf ends every session of a person, when they are removed.
	DeleteSessionsOf(ctx context.Context, email string) error

	// The audit trail of administration (GV-3).
	RecordAdmin(ctx context.Context, a AdminAction) error
	ListAdmin(ctx context.Context, limit int) ([]AdminAction, error)
	// DeleteAdminBefore applies the trail's retention period (GV-4).
	DeleteAdminBefore(ctx context.Context, t time.Time) (int64, error)
	// DeleteExpiredSessions removes sessions that can no longer be used.
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error)

	// Cache purges (GV-4): recorded, with a sequence number, so that every
	// gateway applies each one to its own memory as well.
	RecordCachePurge(ctx context.Context, label string, at time.Time) (int64, error)
	CachePurgesSince(ctx context.Context, seq int64) ([]CachePurge, error)

	PutCredential(ctx context.Context, c Credential) error
	ListCredentials(ctx context.Context) ([]Credential, error)
	DeleteCredential(ctx context.Context, name string) (bool, error)
	// SetCredentialRegion changes a stored credential's region ("" clears it).
	SetCredentialRegion(ctx context.Context, name, region string) (bool, error)
}

// Event is one usage and audit event, one per request (architecture §4.8).
// It holds metadata only: finding types and counts, never values.
type Event struct {
	ID             string    `json:"id"`
	Time           time.Time `json:"ts"`
	OrgID          string    `json:"org_id"`
	KeyID          string    `json:"key_id,omitempty"`
	KeyName        string    `json:"key_name,omitempty"`
	Family         string    `json:"family"`
	Endpoint       string    `json:"endpoint"`
	ModelRequested string    `json:"model_requested,omitempty"`
	ModelServed    string    `json:"model_served,omitempty"`
	Connection     string    `json:"connection,omitempty"`
	Hosting        string    `json:"hosting,omitempty"`
	Stream         bool      `json:"stream"`
	Status         int       `json:"status"`
	Outcome        string    `json:"outcome"` // ok | blocked | refused | error | client_error
	Reason         string    `json:"reason,omitempty"`
	Cache          string    `json:"cache"` // hit | miss | bypass | off
	CacheReason    string    `json:"cache_reason,omitempty"`
	// Semantic is the semantic cache's result: hit (served), would_hit
	// (shadow mode), miss, error, or empty when the request was not eligible.
	Semantic string `json:"semantic,omitempty"`
	// SemanticCheck compares a shadow hit with the real answer: agree,
	// disagree, or empty when it could not be checked.
	SemanticCheck string `json:"semantic_check,omitempty"`
	// Guard is the ML detection result: ok, unavailable, or empty when the
	// policy needs no Guard.
	Guard          string         `json:"guard,omitempty"`
	Similarity     float64        `json:"similarity,omitempty"`
	Mode           string         `json:"mode"`
	PolicyVersion  string         `json:"policy_version"`
	InputTokens    int64          `json:"input_tokens"`
	CachedTokens   int64          `json:"cached_input_tokens"`
	CacheWrite     int64          `json:"cache_write_tokens"`
	OutputTokens   int64          `json:"output_tokens"`
	CostUSD        float64        `json:"cost_usd"`
	CostAvoidedUSD float64        `json:"cost_avoided_usd"`
	Unpriced       bool           `json:"unpriced,omitempty"`
	Alert          bool           `json:"alert,omitempty"`
	Findings       []FindingCount `json:"findings,omitempty"`
	// NearMiss explains an exact-cache miss: what differed from a recent
	// request of the same key that asked the same question, as "field:kind"
	// labels such as "system:date". Never a value.
	NearMiss []string `json:"near_miss,omitempty"`
	// The router's shadow decision (OP-4): the model it would have used, why,
	// and what the real usage would have cost less there.
	RouteModel     string  `json:"route_model,omitempty"`
	RouteReason    string  `json:"route_reason,omitempty"`
	RouteSavingUSD float64 `json:"route_saving_usd,omitempty"`
	// RouteApplied is true when the request really went to RouteModel: past a
	// budget's soft limit (OP-5). Budget names the budget state, such as
	// "soft:key:monthly" or "hard:org:daily".
	RouteApplied bool   `json:"route_applied,omitempty"`
	Budget       string `json:"budget,omitempty"`
	// The caller's place in the hierarchy, by name, for reports by team and
	// project (AC-4).
	TeamName    string `json:"team_name,omitempty"`
	ProjectName string `json:"project_name,omitempty"`
	// User is the person behind the request (AC-3), pseudonymized: a keyed
	// hash of the ID the application or identity provider gave, never the ID.
	User       string         `json:"user,omitempty"`
	Unreadable []string       `json:"unreadable,omitempty"`
	Stages     map[string]int `json:"stages_us,omitempty"` // microseconds per stage
	TotalMS    int64          `json:"total_ms"`
	TTFBMS     int64          `json:"ttfb_ms,omitempty"`
	Attempts   int            `json:"attempts,omitempty"`
	Payload    []byte         `json:"payload,omitempty"` // encrypted masked payload, if captured
	// MAC is the gateway's signature of the event (GV-3): a keyed hash of
	// its content, checked before the event is sealed into the audit ledger.
	MAC   string          `json:"mac,omitempty"`
	Extra json.RawMessage `json:"extra,omitempty"`
}

// FindingCount is how many values of one type were found, and what was done.
// Applied is false when the action was only recorded (monitor mode).
type FindingCount struct {
	Type    string `json:"type"`
	Action  string `json:"action"`
	Count   int    `json:"count"`
	Applied bool   `json:"applied"`
}

// Range selects events by time.
type Range struct {
	From, To time.Time
	// Team limits a report to one team's requests, by name; empty: all. A
	// team lead's reports are limited to their team (GV-2).
	Team string
}

// Totals is the headline of a report.
type Totals struct {
	Requests       int64   `json:"requests"`
	InputTokens    int64   `json:"input_tokens"`
	CachedTokens   int64   `json:"cached_input_tokens"`
	CacheWrite     int64   `json:"cache_write_tokens"`
	OutputTokens   int64   `json:"output_tokens"`
	CostUSD        float64 `json:"cost_usd"`
	CostAvoidedUSD float64 `json:"cost_avoided_usd"`
	CacheHits      int64   `json:"cache_hits"`
	CacheMisses    int64   `json:"cache_misses"`
	// The semantic cache. Its hits are also counted in CacheHits.
	SemanticLookups    int64   `json:"semantic_lookups"`
	SemanticHits       int64   `json:"semantic_hits"`
	SemanticAvoidedUSD float64 `json:"semantic_avoided_usd"`
	SemanticWouldHit   int64   `json:"semantic_would_hit"`
	SemanticWouldUSD   float64 `json:"semantic_would_avoid_usd"` // what the shadow hits would have saved
	SemanticAgree      int64   `json:"semantic_agree"`
	SemanticDisagree   int64   `json:"semantic_disagree"`
	SemanticErrors     int64   `json:"semantic_errors"`
	Blocked            int64   `json:"blocked"`
	Refused            int64   `json:"refused"`
	Errors             int64   `json:"errors"`
	Alerts             int64   `json:"alerts"`
	Unpriced           int64   `json:"unpriced"`
	AvgMS              float64 `json:"avg_ms"`
}

// Group is one row of a grouped report.
type Group struct {
	Key string `json:"key"`
	Totals
}

// FindingRow is one row of the findings report.
type FindingRow struct {
	Type     string `json:"type"`
	Action   string `json:"action"`
	Applied  bool   `json:"applied"`
	Count    int64  `json:"count"`
	Requests int64  `json:"requests"`
}

// ThreatTypes are the finding types that are threats, not data (PR-5).
var ThreatTypes = []string{"PROMPT_INJECTION"}

// OutputPrefix starts the finding types of output inspection (PR-6).
const OutputPrefix = "OUTPUT_"

// SecurityRow is one row of the security report (OB-3): for one virtual key,
// or one time bucket, how many requests had something to report. A request
// counts once per column, whatever the number of values in it.
type SecurityRow struct {
	Key            string `json:"key"`
	Requests       int64  `json:"requests"`
	WithData       int64  `json:"with_data"`       // a data finding (fast detectors or the Guard)
	Threats        int64  `json:"threats"`         // a threat finding, such as prompt injection
	AnswersChanged int64  `json:"answers_changed"` // output inspection removed or blocked something
	OutputAlerts   int64  `json:"output_alerts"`   // output inspection flagged and changed nothing
	Blocked        int64  `json:"blocked"`
	Refused        int64  `json:"refused"`
	Alerts         int64  `json:"alerts"`
	GuardDown      int64  `json:"guard_unavailable"`
}

// NearMissRow is one label of the near-miss report: how many exact-cache
// misses it explains, and what those requests cost.
type NearMissRow struct {
	Label    string  `json:"label"` // field:kind, such as system:date
	Requests int64   `json:"requests"`
	CostUSD  float64 `json:"cost_usd"`
	Keys     int64   `json:"keys"`
}

// RouteRow is one row of the routing report (OP-4, shadow mode): requests
// for one model, and what the router would have done with them.
type RouteRow struct {
	Requested string  `json:"requested"`
	Would     string  `json:"would"`  // the cheaper model, or "" when it stays
	Reason    string  `json:"reason"` // why it would move, or why it stays
	Requests  int64   `json:"requests"`
	CostUSD   float64 `json:"cost_usd"`
	SavingUSD float64 `json:"saving_usd"` // the real usage priced at the cheaper model
}

// Counters hold the budget counters (OP-5): spend per organization and key,
// per month and day. Solo keeps them in memory and rebuilds them from the
// event ledger at start; Team keeps them in a Valkey instance of their own,
// never evicted. The request path reads and adds in one call.
type Counters interface {
	// Add adds delta to a counter, creating it with an expiry, and returns
	// the new value.
	Add(ctx context.Context, key string, delta float64, expires time.Time) (float64, error)
	// Get returns a counter, or 0.
	Get(ctx context.Context, key string) (float64, error)
}

// Database is the store of configuration and events: SQLite in Solo,
// PostgreSQL in Team.
type Database interface {
	ConfigStore
	EventStore
	Ledger
	PolicyStore
	SCIMStore
	FleetStore
	QualityStore
	Close() error
}

// SpendRow is one key's spend since a time, from the event ledger.
type SpendRow struct {
	KeyID   string
	User    string
	CostUSD float64
}

// EventFilter narrows a request list.
type EventFilter struct {
	Range
	Outcome string
	Cache   string
	KeyID   string
	User    string // pseudonym
	Model   string
	Limit   int
	Before  time.Time
}

// EventStore holds usage and audit events.
type EventStore interface {
	InsertEvents(ctx context.Context, events []Event) error
	Totals(ctx context.Context, r Range) (Totals, error)
	// GroupBy groups by "day", "hour", "model", "key", "team", "project", "user", "connection", or "endpoint".
	GroupBy(ctx context.Context, r Range, by string) ([]Group, error)
	Findings(ctx context.Context, r Range) ([]FindingRow, error)
	// Spend sums the cost per key since a time: the ledger that rebuilds the
	// budget counters at start.
	Spend(ctx context.Context, since time.Time) ([]SpendRow, error)
	// Routing is the routing report: the router's shadow decisions.
	Routing(ctx context.Context, r Range) ([]RouteRow, error)
	// NearMisses counts the exact-cache near misses per label.
	NearMisses(ctx context.Context, r Range) ([]NearMissRow, error)
	// Security groups the security report by "key", "day", or "hour".
	Security(ctx context.Context, r Range, by string) ([]SecurityRow, error)
	ListEvents(ctx context.Context, f EventFilter) ([]Event, error)
	GetEvent(ctx context.Context, id string) (*Event, error)
	DeleteEventsBefore(ctx context.Context, t time.Time) (int64, error)
	// CountEvents and PurgeEvents select with a PurgeFilter (GV-4); a
	// payloads-only purge clears captured payloads and keeps the events.
	CountEvents(ctx context.Context, f PurgeFilter) (int64, error)
	PurgeEvents(ctx context.Context, f PurgeFilter) (int64, error)
}

// CacheRecord is one exact-cache entry held outside process memory. Sealed is
// the same form as in memory: the entry compressed with zstd, then encrypted
// with AES-GCM under the per-organization key. A cache store never sees plain
// text, and Key is a keyed fingerprint, never a prompt (architecture §4.5).
type CacheRecord struct {
	Key     string
	OrgID   string
	Sealed  []byte
	Expires time.Time
	// Labels name the entry for a later purge (GV-4): the key that stored it
	// and the application's tags, each a keyed hash (LabelSize hex
	// characters), never a tag or a key ID in clear.
	Labels []string
}

// LabelSize is the length of a label: 16 bytes of HMAC, in hex.
const LabelSize = 32

// JoinLabels writes labels as one column value, " a b ", so that a purge
// matches " a " exactly.
func JoinLabels(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	return " " + strings.Join(labels, " ") + " "
}

// CacheStoreStats describe a cache store.
type CacheStoreStats struct {
	Entries int64 `json:"entries"`
	Bytes   int64 `json:"bytes"` // sealed entry bytes
}

// CacheStore holds exact-cache entries outside process memory: a SQLite file
// of its own in Solo (cache.db), Valkey in Team and Enterprise. The cache
// fails open: a caller treats every error as a miss (principle 2).
type CacheStore interface {
	// GetEntry returns ErrNotFound when the key is absent.
	GetEntry(ctx context.Context, key string) (CacheRecord, error)
	PutEntries(ctx context.Context, recs []CacheRecord) error
	// TouchEntries records a use, for least-recently-used eviction.
	TouchEntries(ctx context.Context, keys []string, at time.Time) error
	DeleteEntries(ctx context.Context, keys []string) error
	// Trim deletes expired entries, then the least recently used ones until
	// the store holds at most maxBytes.
	Trim(ctx context.Context, now time.Time, maxBytes int64) (removed int64, err error)
	// Purge deletes the entries that carry a label, or every entry when
	// label is empty (GV-4).
	Purge(ctx context.Context, label string) (removed int64, err error)
	Stats(ctx context.Context) (CacheStoreStats, error)
	Close() error
}

// SemanticRecord is one semantic-cache entry. Context is a keyed fingerprint
// of everything before the last user message; Sealed holds the masked last
// message, its embedding, and the masked answer, compressed and encrypted
// under the per-organization key. A store sees neither text nor vectors.
type SemanticRecord struct {
	Key     string
	Context string
	OrgID   string
	Sealed  []byte
	Expires time.Time
	Labels  []string // as in CacheRecord
}

// SemanticStore holds semantic-cache entries: in cache.db in Solo, beside the
// exact cache. It fails open, like CacheStore.
type SemanticStore interface {
	// ListSemantic returns the unexpired entries of one context, newest first.
	ListSemantic(ctx context.Context, org, context string, now time.Time, limit int) ([]SemanticRecord, error)
	PutSemantic(ctx context.Context, rec SemanticRecord) error
	// TrimSemantic deletes expired entries, then the oldest beyond maxEntries.
	TrimSemantic(ctx context.Context, now time.Time, maxEntries int) (removed int64, err error)
	SemanticStats(ctx context.Context) (CacheStoreStats, error)
	// PurgeSemantic deletes the entries that carry a label, or all of them.
	PurgeSemantic(ctx context.Context, label string) (removed int64, err error)
}

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("not found")

// ---- Encryption at rest ----

// DeriveKey derives a 32-byte key for one purpose and one organization from
// the master key, so that organizations never share a key.
func DeriveKey(master []byte, purpose, orgID string) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte("kygate/v1/" + purpose + "/" + orgID))
	return m.Sum(nil)
}

// Seal encrypts with AES-256-GCM. The nonce is prepended. aad binds the
// ciphertext to its context, such as an organization ID.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// Open decrypts what Seal produced.
func Open(key, sealed, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], aad)
}

// SealEnvelope encrypts a secret under a fresh data key, and the data key
// under the key-encryption key.
func SealEnvelope(kek, secret, aad []byte) (wrappedDEK, ciphertext []byte, err error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, err
	}
	if ciphertext, err = Seal(dek, secret, aad); err != nil {
		return nil, nil, err
	}
	if wrappedDEK, err = Seal(kek, dek, aad); err != nil {
		return nil, nil, err
	}
	return wrappedDEK, ciphertext, nil
}

// OpenEnvelope reverses SealEnvelope.
func OpenEnvelope(kek, wrappedDEK, ciphertext, aad []byte) ([]byte, error) {
	dek, err := Open(kek, wrappedDEK, aad)
	if err != nil {
		return nil, err
	}
	return Open(dek, ciphertext, aad)
}
