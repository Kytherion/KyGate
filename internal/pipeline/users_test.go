package pipeline_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/control"
	"github.com/Kytherion/KyGate/internal/identity"
	"github.com/Kytherion/KyGate/internal/policy"
	"github.com/Kytherion/KyGate/internal/store"
)

// userRig gives both harness keys a signing secret for user tokens.
func userRig(t *testing.T, pol string) (*harness, func(key, user string) string, func(id string) string) {
	h := newHarness(t, pol)
	ctx := context.Background()
	org, _ := h.db.Meta(ctx, "org_id")
	secrets := map[string]string{}
	keys, _ := h.db.ListKeys(ctx)
	for _, k := range keys {
		s, _, err := control.CreateUserSecret(ctx, h.db, h.g.MasterKey, org, k.Name)
		if err != nil {
			t.Fatal(err)
		}
		secrets[k.Name] = s
	}
	h.keys.Unseal = control.UserSecretOpener(h.g.MasterKey, org)
	if err := h.keys.LoadFrom(ctx, h.db); err != nil {
		t.Fatal(err)
	}
	token := func(key, user string) string {
		tok, err := identity.SignAppToken(secrets[key], user, time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	return h, token, func(id string) string { return control.Pseudonym(h.g.MasterKey, org, id) }
}

// AC-3: a user token names the person behind a shared key; the event keeps a
// pseudonym, and the token never reaches the provider.
func TestUserTokens(t *testing.T) {
	h, token, pseudonym := userRig(t, "")
	resp, body := h.post("/v1/chat/completions", h.keyA, chat("hello", false), "X-KyGate-Cache", "no-cache", identity.UserHeader, token("default", "Ana@Example.com"))
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	e := h.events()[0]
	if e.User != pseudonym("ana@example.com") || strings.Contains(e.User, "ana") {
		t.Fatalf("the event names the person by pseudonym only: %q", e.User)
	}
	for k := range h.up.headers[len(h.up.headers)-1] {
		if strings.EqualFold(k, identity.UserHeader) {
			t.Fatal("the user token is never forwarded to a provider")
		}
	}
	// A token signed for one key does not pass on another.
	resp, body = h.post("/v1/chat/completions", h.keyB, chat("hello", false), identity.UserHeader, token("default", "ana"))
	if resp.StatusCode != 401 || !strings.Contains(body, "invalid_user_token") {
		t.Fatalf("another key's token: %d %s", resp.StatusCode, body)
	}
	// Without a token: allowed, until the key requires one.
	if resp, _ := h.post("/v1/chat/completions", h.keyA, chat("no user", false)); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	h.db.SetKeyRequireUser(context.Background(), "default", true)
	h.keys.LoadFrom(context.Background(), h.db)
	resp, body = h.post("/v1/chat/completions", h.keyA, chat("no user", false))
	if resp.StatusCode != 401 || !strings.Contains(body, "requires a user token") {
		t.Fatalf("a key that requires a person: %d %s", resp.StatusCode, body)
	}
	if e := h.events()[0]; e.Outcome != "client_error" || e.KeyName != "default" {
		t.Fatalf("the refusal is recorded against the key: %+v", e)
	}
	// Reports by user.
	g, _ := h.db.GroupBy(context.Background(), store.Range{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)}, "user")
	found := false
	for _, r := range g {
		found = found || (r.Key == pseudonym("ana@example.com") && r.Requests == 1)
	}
	if !found {
		t.Fatalf("by user: %+v", g)
	}
}

// A person's limits count across every key they use.
func TestPerUserLimits(t *testing.T) {
	pol := strings.Replace(string(policy.Starter()), "routing:\n", "rate_limits:\n  per_user: { requests_per_minute: 2 }\n\nrouting:\n", 1)
	h, token, _ := userRig(t, pol)
	codes := []int{}
	for i, key := range []string{h.keyA, h.keyB, h.keyA} {
		name := map[string]string{h.keyA: "default", h.keyB: "bob"}[key]
		resp, _ := h.post("/v1/chat/completions", key, chat(fmt.Sprintf("q %d", i), false), identity.UserHeader, token(name, "ana"))
		codes = append(codes, resp.StatusCode)
	}
	if fmt.Sprint(codes) != "[200 200 429]" {
		t.Fatalf("two requests a minute for ana, whatever the key: %v", codes)
	}
	resp, _ := h.post("/v1/chat/completions", h.keyA, chat("q other", false), identity.UserHeader, token("default", "bo"))
	if resp.StatusCode != 200 {
		t.Fatal("another person has their own limit")
	}
}
