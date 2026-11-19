package identity

// End-user identity (AC-3). An application that serves many
// people with one virtual key names the person behind each request in the
// X-KyGate-User header, with a signed token:
//
//   - an application token: a JWT signed with HS256 under the key's own
//     signing secret (created by KyGate, shown once, stored sealed), with
//     "sub" (the person) and "exp" (at most 24 hours ahead);
//   - an identity-provider token: a JWT the company's OpenID Connect provider
//     signed (RS256, ES256 ...), checked against the provider's published
//     keys, its issuer, an allowed audience, and its expiry.
//
// The algorithm in the token's header decides which check applies, and each
// check accepts only its own algorithms, so a token cannot pass one check by
// claiming the other's. KyGate keeps only a pseudonym of the person: a keyed
// hash of the ID, per organization. Events, counters, and reports never hold
// the ID itself.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// UserHeader carries the user token.
const UserHeader = "X-KyGate-User"

// UserSecretPrefix starts every key signing secret.
const UserSecretPrefix = "kgus-"

// MaxAppTokenLife bounds how far ahead an application token may expire, so
// that a leaked token is useful for a day at most.
const MaxAppTokenLife = 24 * time.Hour

const maxUserID = 256

// Errors of user tokens. Each becomes a 401, or a 503 for ErrIdPUnavailable.
var (
	ErrUserRequired   = errors.New("this key requires a user token in the " + UserHeader + " header")
	ErrNoUserSecret   = errors.New("this key has no signing secret for application user tokens: create one with 'kygate key user-secret NAME'")
	ErrNoIdP          = errors.New("this installation accepts no identity-provider user tokens (identity.user_tokens in the policy)")
	ErrIdPUnavailable = errors.New("the identity provider's signing keys cannot be read right now; the request is refused rather than sent unchecked")
)

// Pseudonym is the stored form of a person's ID: u_ and 20 hex characters of
// HMAC-SHA-256 under the organization's user key.
func Pseudonym(userKey []byte, id string) string {
	m := hmac.New(sha256.New, userKey)
	m.Write([]byte(id))
	return "u_" + hex.EncodeToString(m.Sum(nil))[:20]
}

// NewUserSecret returns a new signing secret for a key's user tokens.
func NewUserSecret() string { return NewKey(UserSecretPrefix) }

// SignAppToken makes an application user token, as an application would; for
// 'kygate key user-token' and tests.
func SignAppToken(secret, user string, ttl time.Duration, now time.Time) (string, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(secret)}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	return jwt.Signed(sig).Claims(jwt.Claims{Subject: user, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(ttl))}).Serialize()
}

// tokenAlg reads the algorithm a token's header names.
func tokenAlg(token string) (string, error) {
	head, _, ok := strings.Cut(token, ".")
	if !ok {
		return "", errors.New("not a signed token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return "", errors.New("not a signed token")
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(raw, &h) != nil || h.Alg == "" {
		return "", errors.New("not a signed token")
	}
	return h.Alg, nil
}

// verifyAppToken checks an HS256 token against a key's signing secret.
func verifyAppToken(token string, secret []byte, now time.Time) (string, error) {
	tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		return "", errors.New("not a valid HS256 token")
	}
	var c jwt.Claims
	if err := tok.Claims(secret, &c); err != nil {
		return "", errors.New("the signature does not match this key's signing secret")
	}
	if c.Expiry == nil {
		return "", errors.New("the token has no expiry (exp)")
	}
	if err := c.ValidateWithLeeway(jwt.Expected{Time: now}, 30*time.Second); err != nil {
		return "", fmt.Errorf("the token is not valid now: %v", err)
	}
	if c.Expiry.Time().After(now.Add(MaxAppTokenLife + 30*time.Second)) {
		return "", fmt.Errorf("the token expires more than %s ahead; sign shorter tokens", MaxAppTokenLife)
	}
	return c.Subject, nil
}

// IdP checks user tokens from the company's OpenID Connect provider. It is
// configured from the policy; discovery and key downloads happen in the
// background or when the provider rotates its keys, never on every request.
type IdP struct {
	mu        sync.RWMutex
	issuer    string
	audiences []string
	claim     string
	verifier  *oidc.IDTokenVerifier
	lastErr   string
	gen       int
	logf      func(string, ...any)
}

// NewIdP returns an IdP checker with nothing configured.
func NewIdP(logf func(string, ...any)) *IdP {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &IdP{logf: logf}
}

// Configure sets the provider. A new issuer starts discovery in the
// background, retried until it works; until then such tokens are refused.
func (p *IdP) Configure(issuer string, audiences []string, claim string) {
	if claim == "" {
		claim = "sub"
	}
	p.mu.Lock()
	same := issuer == p.issuer
	p.issuer, p.audiences, p.claim = issuer, append([]string(nil), audiences...), claim
	if same {
		p.mu.Unlock()
		return
	}
	p.verifier, p.lastErr = nil, ""
	p.gen++
	gen := p.gen
	p.mu.Unlock()
	if issuer == "" {
		return
	}
	go p.discover(issuer, gen)
}

func (p *IdP) discover(issuer string, gen int) {
	for wait := time.Second; ; wait = min(wait*2, time.Minute) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		prov, err := oidc.NewProvider(ctx, issuer)
		cancel()
		p.mu.Lock()
		if p.gen != gen {
			p.mu.Unlock()
			return
		}
		if err == nil {
			// The audience is checked against the policy's list below.
			p.verifier = prov.Verifier(&oidc.Config{SkipClientIDCheck: true})
			p.lastErr = ""
			p.mu.Unlock()
			p.logf("user tokens: the identity provider %s is ready", issuer)
			return
		}
		p.lastErr = err.Error()
		p.mu.Unlock()
		p.logf("user tokens: cannot read the identity provider %s yet: %v", issuer, err)
		time.Sleep(wait)
	}
}

// State says whether the IdP is configured and ready, for the console and banner.
func (p *IdP) State() (issuer string, ready bool, lastErr string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.issuer, p.verifier != nil, p.lastErr
}

func (p *IdP) verify(ctx context.Context, token string) (string, error) {
	p.mu.RLock()
	issuer, v, auds, claim := p.issuer, p.verifier, p.audiences, p.claim
	p.mu.RUnlock()
	if issuer == "" {
		return "", ErrNoIdP
	}
	if v == nil {
		return "", ErrIdPUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	t, err := v.Verify(ctx, token)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", ErrIdPUnavailable
		}
		return "", fmt.Errorf("the identity provider's token is not valid: %v", err)
	}
	ok := false
	for _, a := range t.Audience {
		for _, want := range auds {
			ok = ok || a == want
		}
	}
	if !ok {
		return "", errors.New("the identity provider's token is for another audience (identity.user_tokens.audiences)")
	}
	var c map[string]any
	if err := t.Claims(&c); err != nil {
		return "", errors.New("the token's claims cannot be read")
	}
	if claim == "email" {
		if v, set := c["email_verified"].(bool); set && !v {
			return "", errors.New("the token's email is not verified")
		}
	}
	id, _ := c[claim].(string)
	if id == "" {
		return "", fmt.Errorf("the token has no %q claim", claim)
	}
	return id, nil
}

// User checks the user token of a request on a caller's key and fills in the
// caller's User. An empty token is allowed unless the key requires one.
func (r *Resolver) User(ctx context.Context, c *Caller, token string, idp *IdP, userKey []byte, now time.Time) error {
	token = strings.TrimSpace(token)
	if token == "" {
		if c.requireUser {
			return ErrUserRequired
		}
		return nil
	}
	alg, err := tokenAlg(token)
	if err != nil {
		return err
	}
	var id, source string
	switch {
	case alg == "HS256":
		if len(c.userSecret) == 0 {
			return ErrNoUserSecret
		}
		id, err = verifyAppToken(token, c.userSecret, now)
		source = "app"
	case strings.HasPrefix(alg, "HS") || strings.EqualFold(alg, "none"):
		return fmt.Errorf("tokens signed with %s are not accepted: application tokens use HS256", alg)
	default:
		if idp == nil {
			return ErrNoIdP
		}
		id, err = idp.verify(ctx, token)
		source = "idp"
	}
	if err != nil {
		return err
	}
	id = NormalizeUserID(id)
	if id == "" || len(id) > maxUserID {
		return fmt.Errorf("the token names no person (sub), or an ID longer than %d characters", maxUserID)
	}
	c.User, c.UserSource = Pseudonym(userKey, id), source
	return nil
}

// NormalizeUserID is the form of a person's ID that is hashed: trimmed, and
// in lower case when it is an email address, which names the same person
// whatever its case, from an application or from the identity provider.
func NormalizeUserID(id string) string {
	id = strings.TrimSpace(id)
	if strings.Contains(id, "@") {
		id = strings.ToLower(id)
	}
	return id
}
