package control

// Who may use the console and the admin API, and what each may do (AC-3,
// GV-2). A caller is either a person signed in with single
// sign-on, whose session is a cookie, or the holder of the admin token: in a
// browser session (from the sign-in page) or in a Bearer header (scripts and
// the command line). Five roles:
//
//	admin      everything
//	security   reads everything; writes the mode, data, threats, and output
//	           sections of any policy file; reads the audit trail
//	finance    reads everything; writes the budgets and rate_limits sections
//	team_lead  reads their team only; manages their team's projects and keys;
//	           writes their team's and its projects' policy files, except
//	           budgets and rate limits
//	viewer     reads everything; writes nothing
//
// A browser session sends its CSRF value in X-KyGate-CSRF on every change; the
// cookie is HttpOnly and SameSite=Strict.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Kytherion/KyGate/internal/identity"
	"github.com/Kytherion/KyGate/internal/store"
)

// Roles.
const (
	RoleAdmin    = "admin"
	RoleSecurity = "security"
	RoleFinance  = "finance"
	RoleTeamLead = "team_lead"
	RoleViewer   = "viewer"
)

// Roles lists the roles, the strongest first.
var Roles = []string{RoleAdmin, RoleSecurity, RoleFinance, RoleTeamLead, RoleViewer}

// ValidRole reports whether r is a role.
func ValidRole(r string) bool {
	for _, x := range Roles {
		if x == r {
			return true
		}
	}
	return false
}

// TokenActor names the admin token in the audit trail.
const TokenActor = "admin token"

// SessionCookie is the console's session cookie.
const SessionCookie = "kygate_session"

// SessionLifetime is how long a sign-in lasts.
const SessionLifetime = 12 * time.Hour

// Principal is who is calling.
type Principal struct {
	Actor    string `json:"actor"` // an email, or "admin token"
	Role     string `json:"role"`
	TeamID   string `json:"team_id,omitempty"`
	TeamName string `json:"team,omitempty"`
	Via      string `json:"via"` // sso | token-session | bearer
	CSRF     string `json:"csrf,omitempty"`
}

type principalKey struct{}

// PrincipalOf returns the caller of a request that passed auth.
func PrincipalOf(r *http.Request) Principal {
	p, _ := r.Context().Value(principalKey{}).(Principal)
	return p
}

// Section groups of policy files, by who may write them.
var policySections = map[string][]string{
	RoleSecurity: {"kind", "scope", "mode", "data", "threats", "output"},
	RoleFinance:  {"kind", "scope", "budgets", "rate_limits"},
	RoleTeamLead: {"kind", "scope", "mode", "data", "threats", "output", "cache", "routing"},
}

// ReadsAll reports whether the caller sees the whole organization.
func (p Principal) ReadsAll() bool { return p.Role != RoleTeamLead }

func randomToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// auth resolves the caller, requires one, and checks the CSRF value of a
// browser session on every change.
func (c *Console) auth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := c.authenticate(r)
		if err != nil {
			apiError(w, 401, err.Error())
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && p.Via != "bearer" {
			if p.CSRF == "" || r.Header.Get("X-KyGate-CSRF") != p.CSRF {
				apiError(w, 403, "this change is missing its CSRF value: reload the console page")
				return
			}
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

func (c *Console) authenticate(r *http.Request) (Principal, error) {
	a := r.Header.Get("Authorization")
	if len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		tok := strings.TrimSpace(a[7:])
		hash, err := c.Config.Meta(r.Context(), "admin_token_hash")
		if err == nil && identity.EqualHash(tok, hash) {
			return Principal{Actor: TokenActor, Role: RoleAdmin, Via: "bearer"}, nil
		}
		return Principal{}, errors.New("this admin token was not accepted: use the token printed at the first start, or run 'kygate admin-token reset'")
	}
	ck, err := r.Cookie(SessionCookie)
	if err != nil || ck.Value == "" {
		return Principal{}, errors.New("sign in first")
	}
	s, err := c.Config.GetSession(r.Context(), identity.Hash(ck.Value))
	if err != nil {
		return Principal{}, errors.New("the session has ended: sign in again")
	}
	p := Principal{Actor: s.Email, Role: s.Role, TeamID: s.TeamID, CSRF: s.CSRF, Via: "sso"}
	if s.Email == TokenActor {
		p.Via = "token-session"
	}
	if p.TeamID != "" {
		ts, _ := c.Config.ListTeams(r.Context())
		for _, t := range ts {
			if t.ID == p.TeamID {
				p.TeamName = t.Name
			}
		}
		if p.TeamName == "" && p.Role == RoleTeamLead {
			return Principal{}, errors.New("your team no longer exists: ask an administrator")
		}
	}
	return p, nil
}

// startSession signs a caller in: a server-side session, and its cookie.
func (c *Console) startSession(w http.ResponseWriter, r *http.Request, email, role, teamID string) error {
	tok := randomToken(32)
	now := time.Now()
	s := store.Session{Hash: identity.Hash(tok), Email: email, Role: role, TeamID: teamID, CSRF: randomToken(24), Created: now, Expires: now.Add(SessionLifetime)}
	if err := c.Config.CreateSession(r.Context(), s); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: c.secureCookies(r), Expires: s.Expires})
	return nil
}

// secureCookies: Secure when the console is reached over HTTPS.
func (c *Console) secureCookies(r *http.Request) bool {
	return r.TLS != nil || strings.HasPrefix(c.ssoRedirect(), "https://")
}

func (c *Console) ssoRedirect() string { return c.SSO.redirectURL() }

// tokenLogin signs in with the admin token, from the console's sign-in page.
// With single sign-on configured it is the break-glass way in, and recorded.
func (c *Console) tokenLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if err := readJSON(r, &in); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	hash, err := c.Config.Meta(r.Context(), "admin_token_hash")
	if err != nil || !identity.EqualHash(strings.TrimSpace(in.Token), hash) {
		time.Sleep(300 * time.Millisecond)
		apiError(w, 401, "this admin token was not accepted")
		return
	}
	if err := c.startSession(w, r, TokenActor, RoleAdmin, ""); err != nil {
		apiError(w, 500, err.Error())
		return
	}
	detail := ""
	if c.SSO != nil {
		detail = "break-glass: single sign-on is configured"
	}
	c.Config.RecordAdmin(r.Context(), store.AdminAction{Time: time.Now(), Actor: TokenActor, Action: "session.start", Target: "console", Detail: detail})
	writeJSON(w, map[string]any{"ok": true})
}

func (c *Console) logout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(SessionCookie); err == nil {
		c.Config.DeleteSession(r.Context(), identity.Hash(ck.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(204)
}

// me says who is signed in, with the CSRF value the page sends back.
func (c *Console) me(w http.ResponseWriter, r *http.Request) {
	p, err := c.authenticate(r)
	if err != nil {
		apiError(w, 401, err.Error())
		return
	}
	writeJSON(w, p)
}

// authConfig tells the sign-in page which ways in exist.
func (c *Console) authConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"sso": c.SSO != nil, "sso_name": c.SSO.displayName()})
}

// --------------------------------------------------------------- permissions

// require answers 403 unless the caller has one of the roles.
func require(w http.ResponseWriter, r *http.Request, roles ...string) (Principal, bool) {
	p := PrincipalOf(r)
	for _, x := range roles {
		if p.Role == x {
			return p, true
		}
	}
	apiError(w, 403, "your role ("+p.Role+") cannot do this")
	return p, false
}
