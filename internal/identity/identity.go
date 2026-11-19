// Package identity resolves virtual keys to callers (capability AC-2,
// pipeline stage 2). Virtual keys are stored as hashes and shown once. The
// request path reads an in-memory snapshot and makes no database call.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
)

// KeyPrefix starts every virtual key.
const KeyPrefix = "kg-"

// Caller is who sent a request.
type Caller struct {
	KeyID   string
	KeyName string
	OrgID   string
	// The key's place in the hierarchy organization -> team -> project ->
	// key (AC-4); empty when the key sits directly under the organization.
	TeamID, TeamName       string
	ProjectID, ProjectName string
	// User is the person behind the request, pseudonymized (AC-3); empty when
	// the request named none. UserSource is app or idp.
	User, UserSource string

	requireUser bool
	userSecret  []byte // the key's signing secret, unsealed, in memory only
}

// RequiresUser reports whether the key refuses requests that name no person.
func (c Caller) RequiresUser() bool { return c.requireUser }

// Snapshot is the set of active keys, by hash.
type Snapshot struct {
	byHash map[string]Caller
}

// Resolver holds the current snapshot.
type Resolver struct {
	snap atomic.Pointer[Snapshot]
	// Unseal opens a key's sealed signing secret for user tokens. Without
	// it, or when it fails, the key accepts no application user tokens.
	Unseal func(sealed []byte, keyID string) ([]byte, error)
}

// NewResolver returns a resolver with no keys.
func NewResolver() *Resolver {
	r := &Resolver{}
	r.snap.Store(&Snapshot{byHash: map[string]Caller{}})
	return r
}

// Load replaces the snapshot from the stored keys.
func (r *Resolver) Load(keys []store.VirtualKey) { r.LoadHierarchy(keys, nil, nil) }

// LoadHierarchy replaces the snapshot from the stored keys, placing each in
// its project and team.
func (r *Resolver) LoadHierarchy(keys []store.VirtualKey, projects []store.Project, teams []store.Team) {
	proj := map[string]store.Project{}
	for _, p := range projects {
		proj[p.ID] = p
	}
	team := map[string]store.Team{}
	for _, t := range teams {
		team[t.ID] = t
	}
	s := &Snapshot{byHash: make(map[string]Caller, len(keys))}
	for _, k := range keys {
		if k.RevokedAt != nil {
			continue
		}
		c := Caller{KeyID: k.ID, KeyName: k.Name, OrgID: k.OrgID, requireUser: k.RequireUser}
		if len(k.UserSecret) > 0 && r.Unseal != nil {
			if s, err := r.Unseal(k.UserSecret, k.ID); err == nil {
				c.userSecret = s
			}
		}
		if p, ok := proj[k.ProjectID]; ok {
			c.ProjectID, c.ProjectName = p.ID, p.Name
			if t, ok := team[p.TeamID]; ok {
				c.TeamID, c.TeamName = t.ID, t.Name
			}
		}
		s.byHash[k.Hash] = c
	}
	r.snap.Store(s)
}

// LoadFrom reads keys, projects, and teams from the store and loads them.
func (r *Resolver) LoadFrom(ctx context.Context, cs store.ConfigStore) error {
	ks, err := cs.ListKeys(ctx)
	if err != nil {
		return err
	}
	ps, err := cs.ListProjects(ctx)
	if err != nil {
		return err
	}
	ts, err := cs.ListTeams(ctx)
	if err != nil {
		return err
	}
	r.LoadHierarchy(ks, ps, ts)
	return nil
}

// Count is the number of active keys.
func (r *Resolver) Count() int { return len(r.snap.Load().byHash) }

// Resolve finds the caller for a presented key.
func (r *Resolver) Resolve(key string) (Caller, bool) {
	if !strings.HasPrefix(key, KeyPrefix) {
		return Caller{}, false
	}
	c, ok := r.snap.Load().byHash[Hash(key)]
	return c, ok
}

// FromRequest extracts the key a client presented. OpenAI clients send
// "Authorization: Bearer", Anthropic clients send "x-api-key".
func FromRequest(r *http.Request) string {
	if k := strings.TrimSpace(r.Header.Get("X-Api-Key")); k != "" {
		return k
	}
	if a := r.Header.Get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		return strings.TrimSpace(a[7:])
	}
	return ""
}

// Hash is the stored form of a key.
func Hash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// NewKey returns a new random secret with a prefix.
func NewKey(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// NewID returns a random identifier with a prefix.
func NewID(prefix string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// CreateKey makes and stores a new virtual key, and returns the secret. The
// secret is not stored and cannot be shown again.
func CreateKey(ctx context.Context, cs store.ConfigStore, name, orgID string) (string, store.VirtualKey, error) {
	secret := NewKey(KeyPrefix)
	k := store.VirtualKey{
		ID: NewID("key_"), Name: name, Hash: Hash(secret), Prefix: secret[:len(KeyPrefix)+6],
		OrgID: orgID, CreatedAt: time.Now(),
	}
	if err := cs.CreateKey(ctx, k); err != nil {
		return "", k, err
	}
	return secret, k, nil
}

// EqualHash compares a presented secret with a stored hash in constant time.
func EqualHash(secret, hash string) bool {
	return subtle.ConstantTimeCompare([]byte(Hash(secret)), []byte(hash)) == 1
}
