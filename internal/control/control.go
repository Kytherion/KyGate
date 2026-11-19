// Package control is the control role: first-start setup, the master key,
// stored provider credentials, the reporting and admin APIs, and the console
// (architecture §3.7, §3.8, §4.9).
//
// In Solo the control role runs inside the single process (--role=all); in
// Team it runs apart from the gateways (--role=control).
package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Kytherion/KyGate/internal/identity"
	"github.com/Kytherion/KyGate/internal/kms"
	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/provider"
	"github.com/Kytherion/KyGate/internal/store"
)

// Paths inside the data directory.
const (
	DBFile        = "kygate.db"
	MasterKeyFile = "master.key"
	PolicyFile    = "policy.yaml"
	CatalogFile   = "catalog.yaml"
	SpoolDir      = "spool"
	// CacheFile holds the exact cache when the policy keeps it on disk. It is
	// a database of its own, apart from DBFile; deleting it while KyGate is
	// stopped is a safe purge.
	CacheFile = "cache.db"
)

// MasterKeyEnv supplies the master key instead of the key file.
const MasterKeyEnv = "KYGATE_MASTER_KEY"

// The master key wrapped by a key-management service: a file
// in the data directory, or its content in an environment variable (for a
// container's secret). KMSEnv names the service a first start wraps a new
// master key with.
const (
	MasterKeyWrappedFile = "master.key.wrapped"
	MasterKeyWrappedEnv  = "KYGATE_MASTER_KEY_WRAPPED"
	KMSEnv               = "KYGATE_KMS"
)

// WrappedKey is the content of master.key.wrapped.
type WrappedKey struct {
	KMS     string    `json:"kms"`     // the service and key, never a credential
	Wrapped string    `json:"wrapped"` // base64
	Created time.Time `json:"created"`
}

// kmsTimeout bounds one call to a key-management service.
const kmsTimeout = 30 * time.Second

// WrapMasterKey wraps a master key with the service a URI names, checks that
// the service unwraps it back, and returns the file content.
func WrapMasterKey(uri string, key []byte) (WrappedKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), kmsTimeout)
	defer cancel()
	w, err := kms.Open(ctx, uri)
	if err != nil {
		return WrappedKey{}, err
	}
	wrapped, err := w.Wrap(ctx, key)
	if err != nil {
		return WrappedKey{}, err
	}
	back, err := w.Unwrap(ctx, wrapped)
	if err != nil {
		return WrappedKey{}, fmt.Errorf("the service wrapped the key but cannot unwrap it: %v", err)
	}
	if !bytes.Equal(back, key) {
		return WrappedKey{}, errors.New("the service unwrapped a different key")
	}
	return WrappedKey{KMS: w.URI(), Wrapped: base64.StdEncoding.EncodeToString(wrapped), Created: time.Now().UTC()}, nil
}

// unwrapMasterKey asks the service for the master key.
func unwrapMasterKey(raw []byte, where string) ([]byte, string, error) {
	var wk WrappedKey
	if err := json.Unmarshal(raw, &wk); err != nil || wk.KMS == "" || wk.Wrapped == "" {
		return nil, "", fmt.Errorf("%s is not a wrapped master key", where)
	}
	wrapped, err := base64.StdEncoding.DecodeString(wk.Wrapped)
	if err != nil {
		return nil, "", fmt.Errorf("%s is damaged", where)
	}
	ctx, cancel := context.WithTimeout(context.Background(), kmsTimeout)
	defer cancel()
	// KYGATE_KMS, when set, says how this process reaches the same key: the
	// key was perhaps wrapped from a workstation with a token, and is
	// unwrapped by pods with their Kubernetes login.
	uri := wk.KMS
	if v := strings.TrimSpace(os.Getenv(KMSEnv)); v != "" {
		uri = v
	}
	w, err := kms.Open(ctx, uri)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %v", where, err)
	}
	k, err := w.Unwrap(ctx, wrapped)
	if err != nil {
		return nil, "", fmt.Errorf("the master key cannot be unwrapped by %s: %v", w.URI(), err)
	}
	if len(k) != 32 {
		return nil, "", fmt.Errorf("%s unwrapped a key of %d bytes, not 32", w.URI(), len(k))
	}
	return k, "key-management service " + w.URI(), nil
}

// WriteWrapped writes master.key.wrapped, readable only by its owner.
func WriteWrapped(dataDir string, wk WrappedKey) error {
	b, _ := json.MarshalIndent(wk, "", "  ")
	return os.WriteFile(filepath.Join(dataDir, MasterKeyWrappedFile), append(b, '\n'), 0o600)
}

// LoadMasterKey reads the master key: from the environment; or wrapped by a
// key-management service (KYGATE_MASTER_KEY_WRAPPED or master.key.wrapped),
// unwrapped once here; or from the plain key file. At the first start it
// creates one: wrapped only, when KYGATE_KMS names a service; otherwise in a
// file readable only by the account running KyGate. On one machine, the
// plain file protects a copied database or a backup; it does not protect
// against someone who controls the machine.
func LoadMasterKey(dataDir string, create bool) (key []byte, source string, created bool, err error) {
	if v := strings.TrimSpace(os.Getenv(MasterKeyEnv)); v != "" {
		k, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(k) != 32 {
			return nil, "", false, fmt.Errorf("%s must be 32 bytes, base64-encoded (for example: openssl rand -base64 32)", MasterKeyEnv)
		}
		return k, "environment", false, nil
	}
	plainPath := filepath.Join(dataDir, MasterKeyFile)
	if v := strings.TrimSpace(os.Getenv(MasterKeyWrappedEnv)); v != "" {
		return withPlainNote(unwrapMasterKey([]byte(v), MasterKeyWrappedEnv))(plainPath)
	}
	if raw, err := os.ReadFile(filepath.Join(dataDir, MasterKeyWrappedFile)); err == nil {
		return withPlainNote(unwrapMasterKey(raw, MasterKeyWrappedFile))(plainPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", false, err
	}
	b, err := os.ReadFile(plainPath)
	if err == nil {
		k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(k) != 32 {
			return nil, "", false, fmt.Errorf("%s is damaged: it must hold 32 bytes, base64-encoded", plainPath)
		}
		return k, plainPath, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) || !create {
		return nil, "", false, fmt.Errorf("no master key: %w", err)
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, "", false, err
	}
	if uri := strings.TrimSpace(os.Getenv(KMSEnv)); uri != "" {
		wk, err := WrapMasterKey(uri, k)
		if err != nil {
			return nil, "", false, fmt.Errorf("%s: %v", KMSEnv, err)
		}
		if err := WriteWrapped(dataDir, wk); err != nil {
			return nil, "", false, err
		}
		return k, "key-management service " + wk.KMS, true, nil
	}
	if err := os.WriteFile(plainPath, []byte(base64.StdEncoding.EncodeToString(k)+"\n"), 0o600); err != nil {
		return nil, "", false, err
	}
	return k, plainPath, true, nil
}

// withPlainNote adds a reminder to the source when a plain key file still
// sits next to the wrapped key.
func withPlainNote(k []byte, source string, err error) func(string) ([]byte, string, bool, error) {
	return func(plainPath string) ([]byte, string, bool, error) {
		if err != nil {
			return nil, "", false, err
		}
		if _, statErr := os.Stat(plainPath); statErr == nil {
			source += "; the plain key file master.key is still there: remove it with 'kygate master-key wrap --remove-plain' once you keep a copy elsewhere"
		}
		return k, source, false, nil
	}
}

// SetupResult is what the first start created. Secrets are set only when they
// were just created; they are shown once and never again.
type SetupResult struct {
	OrgID         string
	FirstStart    bool
	VirtualKey    string
	AdminToken    string
	PolicyPath    string
	PolicyCreated bool
	MasterKey     []byte
	MasterSource  string
	MasterCreated bool
}

// Setup prepares an installation. With an empty data directory it creates the
// master key, one organization, the starter policy, one virtual key, and one
// admin token, and asks no questions (architecture §3.7). On later starts it
// changes nothing.
func Setup(ctx context.Context, cs store.ConfigStore, dataDir, policyPath string) (*SetupResult, error) {
	res := &SetupResult{PolicyPath: policyPath}
	var err error
	res.MasterKey, res.MasterSource, res.MasterCreated, err = LoadMasterKey(dataDir, true)
	if err != nil {
		return nil, err
	}
	org, err := cs.Meta(ctx, "org_id")
	if errors.Is(err, store.ErrNotFound) {
		res.FirstStart = true
		org = identity.NewID("org_")
		if err := cs.SetMeta(ctx, "org_id", org); err != nil {
			return nil, err
		}
		if err := cs.SetMeta(ctx, "created_at", time.Now().UTC().Format(time.RFC3339)); err != nil {
			return nil, err
		}
		// A check value, so that a later start with a different master key is
		// detected before stored credentials fail to decrypt.
		check, err := store.Seal(store.DeriveKey(res.MasterKey, "check", org), []byte("kygate"), []byte(org))
		if err != nil {
			return nil, err
		}
		if err := cs.SetMeta(ctx, "master_check", base64.StdEncoding.EncodeToString(check)); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	res.OrgID = org
	if err := VerifyMasterKey(ctx, cs, res.MasterKey, org); err != nil {
		return nil, err
	}

	// With policies in the database (PostgreSQL), policyPath is empty here
	// and SeedPolicies gives the database its policies instead.
	if _, err := os.Stat(policyPath); policyPath != "" && errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(policyPath, policy.Starter(), 0o600); err != nil {
			return nil, err
		}
		res.PolicyCreated = true
	}

	keys, err := cs.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		secret, _, err := identity.CreateKey(ctx, cs, "default", org)
		if err != nil {
			return nil, err
		}
		res.VirtualKey = secret
	}
	if _, err := cs.Meta(ctx, "admin_token_hash"); errors.Is(err, store.ErrNotFound) {
		tok, err := ResetAdminToken(ctx, cs)
		if err != nil {
			return nil, err
		}
		res.AdminToken = tok
	}
	return res, nil
}

// VerifyMasterKey checks that the master key is the one the installation was
// created with.
func VerifyMasterKey(ctx context.Context, cs store.ConfigStore, master []byte, org string) error {
	v, err := cs.Meta(ctx, "master_check")
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	sealed, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return err
	}
	if _, err := store.Open(store.DeriveKey(master, "check", org), sealed, []byte(org)); err != nil {
		return errors.New("the master key does not match this installation: restore the original master.key, or set the original KYGATE_MASTER_KEY")
	}
	return nil
}

// ResetAdminToken creates a new admin token, replacing the old one.
func ResetAdminToken(ctx context.Context, cs store.ConfigStore) (string, error) {
	tok := identity.NewKey("kgadmin-")
	if err := cs.SetMeta(ctx, "admin_token_hash", identity.Hash(tok)); err != nil {
		return "", err
	}
	return tok, nil
}

// ProviderKinds are the providers a credential can be stored for.
var ProviderKinds = []string{provider.OpenAI, provider.Anthropic, provider.Local}

// AddCredential stores a provider credential, encrypted under the master key.
func AddCredential(ctx context.Context, cs store.ConfigStore, master []byte, org, name, kind, baseURL, region, secret string) error {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, " /\\") {
		return errors.New("the name must be one word, without slashes")
	}
	valid := false
	for _, k := range ProviderKinds {
		valid = valid || k == kind
	}
	if !valid {
		return fmt.Errorf("provider must be one of %s", strings.Join(ProviderKinds, ", "))
	}
	if kind == provider.Local && baseURL == "" {
		return errors.New("a local model server needs --base-url, for example http://localhost:11434/v1")
	}
	if kind != provider.Local && secret == "" {
		return errors.New("the key is empty")
	}
	if strings.HasPrefix(secret, identity.KeyPrefix) {
		return errors.New("this is a KyGate virtual key, not a provider key")
	}
	region, err := NormalizeRegion(region)
	if err != nil {
		return err
	}
	wrapped, ct, err := store.SealEnvelope(store.DeriveKey(master, "kek", org), []byte(secret), []byte("credential/"+name))
	if err != nil {
		return err
	}
	return cs.PutCredential(ctx, store.Credential{Name: name, Provider: kind, BaseURL: baseURL, Region: region, WrappedDEK: wrapped, Ciphertext: ct, CreatedAt: time.Now()})
}

// StoredConnections decrypts the stored credentials into connections.
func StoredConnections(ctx context.Context, cs store.ConfigStore, master []byte, org string) ([]*provider.Connection, []string, error) {
	creds, err := cs.ListCredentials(ctx)
	if err != nil {
		return nil, nil, err
	}
	var out []*provider.Connection
	var warnings []string
	kek := store.DeriveKey(master, "kek", org)
	for _, c := range creds {
		secret, err := store.OpenEnvelope(kek, c.WrappedDEK, c.Ciphertext, []byte("credential/"+c.Name))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("stored credential %q cannot be decrypted with this master key; it is skipped", c.Name))
			continue
		}
		conn := provider.NewConnection(c.Name, c.Provider, c.BaseURL, string(secret), "stored")
		conn.Region = c.Region
		out = append(out, conn)
	}
	return out, warnings, nil
}

// Connections merges environment and stored connections. A stored connection
// with the same name as an environment one is skipped: the environment wins.
func Connections(ctx context.Context, cs store.ConfigStore, master []byte, org string, selfAddrs []string) ([]*provider.Connection, []string, error) {
	envConns, warnings := provider.FromEnv(provider.Environ(), selfAddrs)
	stored, w2, err := StoredConnections(ctx, cs, master, org)
	if err != nil {
		return nil, nil, err
	}
	warnings = append(warnings, w2...)
	names := map[string]bool{}
	for _, c := range envConns {
		names[c.Name] = true
	}
	all := envConns
	for _, c := range stored {
		if names[c.Name] {
			warnings = append(warnings, fmt.Sprintf("stored credential %q has the same name as an environment variable connection; the environment variable is used", c.Name))
			continue
		}
		all = append(all, c)
	}
	// KYGATE_REGION_<NAME> sets or replaces a connection's region, for
	// environment and stored connections alike: KYGATE_REGION_OPENAI_TEAM=eu
	// for the connection openai-team.
	env := map[string]string{}
	for _, kv := range provider.Environ() {
		if i := strings.IndexByte(kv, '='); i > 0 && strings.HasPrefix(kv, "KYGATE_REGION_") {
			env[kv[:i]] = kv[i+1:]
		}
	}
	for _, c := range all {
		v, ok := env[RegionVariable(c.Name)]
		if !ok {
			continue
		}
		r, err := NormalizeRegion(v)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v; the connection keeps no region", RegionVariable(c.Name), err))
			r = ""
		}
		c.Region = r
	}
	return all, warnings, nil
}

// RegionVariable is the environment variable that sets a connection's
// region: KYGATE_REGION_ and the name in upper case, dashes as underscores.
func RegionVariable(name string) string {
	return "KYGATE_REGION_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}

// NormalizeRegion checks a connection's region; "" means none.
func NormalizeRegion(r string) (string, error) {
	r = strings.ToLower(strings.TrimSpace(r))
	if r == "" {
		return "", nil
	}
	if !policy.ValidConnectionRegion(r) {
		return "", fmt.Errorf("%q is not a region name: use letters, digits, and dashes, such as eu or us-east", r)
	}
	return r, nil
}
