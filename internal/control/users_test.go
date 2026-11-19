package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/identity"
	"github.com/Kytherion/KyGate/internal/store"
)

func TestUserAdminAPI(t *testing.T) {
	a := newAdminRig(t)
	ctx := context.Background()
	code, body := a.do("POST", "/api/v1/admin/keys/default/user-secret", "")
	var out struct{ Secret string }
	json.Unmarshal([]byte(body), &out)
	if code != 201 || !strings.HasPrefix(out.Secret, identity.UserSecretPrefix) {
		t.Fatalf("%d %s", code, body)
	}
	// The resolver opens the sealed secret and accepts the key's tokens.
	r := identity.NewResolver()
	r.Unseal = UserSecretOpener(a.console.MasterKey, a.console.OrgID)
	if err := r.LoadFrom(ctx, a.db); err != nil {
		t.Fatal(err)
	}
	ks, _ := a.db.ListKeys(ctx)
	if len(ks[0].UserSecret) == 0 || strings.Contains(string(ks[0].UserSecret), out.Secret) {
		t.Fatal("the secret is stored sealed")
	}
	if code, body := a.do("GET", "/api/v1/admin/hierarchy", ""); code != 200 || strings.Contains(body, out.Secret) || !strings.Contains(body, `"user_tokens":true`) {
		t.Fatalf("the secret is never returned again: %s", body)
	}
	if code, _ := a.do("PUT", "/api/v1/admin/keys/default/require-user", `{"required":true}`); code != 200 {
		t.Fatal(code)
	}
	if code, _ := a.do("PUT", "/api/v1/admin/keys/nobody/require-user", `{"required":true}`); code != 404 && code != 403 {
		t.Fatal(code)
	}

	// Pseudonyms, reports, and a purge by person.
	_, body = a.do("POST", "/api/v1/users/pseudonym", `{"id":"Ana@Example.com"}`)
	var p struct{ User string }
	json.Unmarshal([]byte(body), &p)
	if p.User != Pseudonym(a.console.MasterKey, a.console.OrgID, "ana@example.com") {
		t.Fatalf("%s", body)
	}
	now := time.Now()
	a.db.InsertEvents(ctx, []store.Event{
		{ID: "e1", Time: now, OrgID: "o", User: p.User, Family: "openai", Endpoint: "chat", Outcome: "ok", Cache: "miss", Mode: "enforce"},
		{ID: "e2", Time: now, OrgID: "o", User: "u_bbbbbbbbbbbbbbbbbbbb", Family: "openai", Endpoint: "chat", Outcome: "ok", Cache: "miss", Mode: "enforce"},
	})
	if code, body := a.do("GET", "/api/v1/requests?range=24h&user="+p.User, ""); code != 200 || !strings.Contains(body, `"id":"e1"`) || strings.Contains(body, `"id":"e2"`) {
		t.Fatalf("requests by person: %s", body)
	}
	if code, body := a.do("POST", "/api/v1/admin/purge/events", `{"user":"ana@example.com"}`); code != 200 || !strings.Contains(body, `"deleted":1`) {
		t.Fatalf("%d %s", code, body)
	}
	log, _ := a.db.ListAdmin(ctx, 20)
	for _, l := range log {
		if strings.Contains(strings.ToLower(l.Target+l.Detail), "ana") {
			t.Fatalf("the trail never holds a person's ID: %+v", l)
		}
	}
}
