package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/Kytherion/KyGate/internal/store"
)

var userKey = []byte("0123456789abcdef0123456789abcdef")

func callerWith(secret string, require bool) *Caller {
	c := &Caller{KeyID: "key_1", requireUser: require}
	if secret != "" {
		c.userSecret = []byte(secret)
	}
	return c
}

func TestAppTokens(t *testing.T) {
	r := NewResolver()
	ctx := context.Background()
	now := time.Now()
	secret := NewUserSecret()
	tok, err := SignAppToken(secret, "Ana@Example.com", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	c := callerWith(secret, false)
	if err := r.User(ctx, c, tok, nil, userKey, now); err != nil {
		t.Fatal(err)
	}
	if c.User != Pseudonym(userKey, "ana@example.com") || c.UserSource != "app" || strings.Contains(c.User, "ana") {
		t.Fatalf("a pseudonym, the same whatever the email's case: %q", c.User)
	}
	refuse := func(name string, c *Caller, tok string, want string) {
		t.Helper()
		err := r.User(ctx, c, tok, nil, userKey, now)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	refuse("another key's secret", callerWith(NewUserSecret(), false), tok, "signature")
	refuse("a key without a secret", callerWith("", false), tok, "no signing secret")
	expired, _ := SignAppToken(secret, "ana", time.Minute, now.Add(-time.Hour))
	refuse("expired", callerWith(secret, false), expired, "not valid now")
	long, _ := SignAppToken(secret, "ana", 48*time.Hour, now)
	refuse("too long", callerWith(secret, false), long, "more than")
	noSub, _ := SignAppToken(secret, "", time.Hour, now)
	refuse("no person", callerWith(secret, false), noSub, "names no person")
	refuse("garbage", callerWith(secret, false), "not-a-token", "not a signed token")
	// alg none, and HS384, are never accepted.
	none := b64(`{"alg":"none","typ":"JWT"}`) + "." + b64(`{"sub":"ana","exp":9999999999}`) + "."
	refuse("alg none", callerWith(secret, false), none, "not accepted")
	sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS384, Key: []byte(secret + secret)}, nil)
	hs384, _ := jwt.Signed(sig).Claims(jwt.Claims{Subject: "ana", Expiry: jwt.NewNumericDate(now.Add(time.Hour))}).Serialize()
	refuse("HS384", callerWith(secret, false), hs384, "not accepted")
	// No token: fine, unless the key requires one.
	if err := r.User(ctx, callerWith(secret, false), "", nil, userKey, now); err != nil {
		t.Fatal(err)
	}
	if err := r.User(ctx, callerWith(secret, true), "", nil, userKey, now); err != ErrUserRequired {
		t.Fatal(err)
	}
}

func b64(s string) string {
	return strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(base64Std(s)), "=")
}

// fakeIdP serves OpenID discovery and its published keys.
type fakeIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newFakeIdP(t *testing.T) *fakeIdP {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIdP{key: k}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": f.srv.URL, "jwks_uri": f.srv.URL + "/keys",
			"authorization_endpoint": f.srv.URL + "/auth", "token_endpoint": f.srv.URL + "/token", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	return f
}

func (f *fakeIdP) sign(t *testing.T, claims map[string]any) string {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: f.key, KeyID: "k1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := map[string]any{"iss": f.srv.URL, "aud": "kygate-apps", "sub": "u-42", "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range claims {
		c[k] = v
	}
	s, err := jwt.Signed(sig).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestIdPTokens(t *testing.T) {
	f := newFakeIdP(t)
	idp := NewIdP(t.Logf)
	r := NewResolver()
	ctx := context.Background()
	c := callerWith(NewUserSecret(), false)
	if err := r.User(ctx, c, f.sign(t, nil), idp, userKey, time.Now()); err != ErrNoIdP {
		t.Fatalf("no provider configured: %v", err)
	}
	idp.Configure(f.srv.URL, []string{"kygate-apps"}, "email")
	for i := 0; i < 100; i++ {
		if _, ready, _ := idp.State(); ready {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := r.User(ctx, c, f.sign(t, map[string]any{"email": "Ana@Example.com", "email_verified": true}), idp, userKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	if c.User != Pseudonym(userKey, "ana@example.com") || c.UserSource != "idp" {
		t.Fatalf("the same person as an application token naming the same email: %q", c.User)
	}
	for name, claims := range map[string]map[string]any{
		"another audience": {"aud": "someone-else", "email": "a@x"},
		"unverified email": {"email": "a@x", "email_verified": false},
		"no email":         {},
		"expired":          {"email": "a@x", "exp": time.Now().Add(-time.Hour).Unix()},
		"another issuer":   {"email": "a@x", "iss": "https://evil.example"},
	} {
		if err := r.User(ctx, callerWith("", false), f.sign(t, claims), idp, userKey, time.Now()); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// A token signed by another key with the provider's key ID.
	other := &fakeIdP{srv: f.srv}
	other.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	if err := r.User(ctx, callerWith("", false), other.sign(t, map[string]any{"email": "a@x"}), idp, userKey, time.Now()); err == nil {
		t.Fatal("a forged signature is refused")
	}
	// An application token never passes as the provider's, and the reverse.
	if err := r.User(ctx, callerWith("", false), f.sign(t, map[string]any{"email": "a@x"}), nil, userKey, time.Now()); err != ErrNoIdP {
		t.Fatal(err)
	}
}

func TestPseudonymIsKeyed(t *testing.T) {
	a, b := Pseudonym(userKey, "ana"), Pseudonym([]byte("another organization's key......"), "ana")
	if a == b || len(a) != 22 || !strings.HasPrefix(a, "u_") {
		t.Fatalf("%s %s", a, b)
	}
	_ = store.ErrNotFound
}

func base64Std(s string) string { return stdB64.EncodeToString([]byte(s)) }

var stdB64 = base64.StdEncoding
