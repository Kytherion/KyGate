//go:build !enterprise

package control

// The Community edition's side of the Enterprise capabilities: single
// sign-on, the users list, SCIM provisioning, and the audit ledger with its
// SIEM export. Each one answers that it is part of the Enterprise edition;
// none is silently skipped. The admin token keeps working for every role
// check, as the admin.

import (
	"context"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Kytherion/KyGate/internal/edition"
	"github.com/Kytherion/KyGate/internal/store"
)

// SSOFile is the single sign-on settings file in the data directory.
const SSOFile = "sso.yaml"

// SIEMFile is the SIEM destinations file in the data directory.
const SIEMFile = "siem.yaml"

// SSO is single sign-on; the Community edition has none.
type SSO struct{}

func (s *SSO) redirectURL() string { return "" }
func (s *SSO) displayName() string { return "" }

// LoadSSO: the Community edition signs in with the admin token only. An
// sso.yaml is reported, not ignored silently: a policy of sign-in by person
// cannot be met here.
func LoadSSO(dir string, _ func() (string, error)) (*SSO, error) {
	if _, err := os.Stat(filepath.Join(dir, SSOFile)); err == nil {
		return nil, edition.Unavailable("single sign-on (" + SSOFile + ")")
	}
	return nil, nil
}

// StoredSSOSecret: no single sign-on, no secret.
func StoredSSOSecret(context.Context, store.ConfigStore, []byte, string) (string, error) {
	return "", nil
}

// Audit is the audit ledger and SIEM export; the Community edition keeps the
// audit trail and signs every event, without the sealed ledger.
type Audit struct{}

// NewAudit: a siem.yaml in the data directory is refused, so that an export
// someone counts on is never silently missing.
func NewAudit(_ store.Database, _ []byte, _, dataDir string, logf func(string, ...any)) (*Audit, error) {
	if _, err := os.Stat(filepath.Join(dataDir, SIEMFile)); err == nil {
		return nil, edition.Unavailable("SIEM export (" + SIEMFile + ")")
	}
	return nil, nil
}

// Run does nothing: there is no ledger to seal.
func (a *Audit) Run(context.Context) {}

func enterpriseOnly(feature string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		apiError(w, 404, edition.Unavailable(feature).Error())
	}
}

func (c *Console) auditRoutes(api *http.ServeMux) {
	h := enterpriseOnly("the tamper-evident audit ledger")
	api.HandleFunc("GET /api/v1/admin/audit", h)
	api.HandleFunc("POST /api/v1/admin/audit/verify", h)
}

func (c *Console) ssoLogin(w http.ResponseWriter, r *http.Request) {
	enterpriseOnly("single sign-on")(w, r)
}

func (c *Console) ssoCallback(w http.ResponseWriter, r *http.Request) {
	enterpriseOnly("single sign-on")(w, r)
}

func (c *Console) scimHandler() http.Handler { return enterpriseOnly("SCIM provisioning") }

func (c *Console) adminUsers(w http.ResponseWriter, r *http.Request) {
	enterpriseOnly("console users and roles")(w, r)
}

func (c *Console) adminPutUser(w http.ResponseWriter, r *http.Request) {
	enterpriseOnly("console users and roles")(w, r)
}

func (c *Console) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	enterpriseOnly("console users and roles")(w, r)
}
