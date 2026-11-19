package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
)

func TestFleetView(t *testing.T) {
	a := newAdminRig(t)
	ctx := context.Background()
	now := time.Now()
	st, _ := json.Marshal(InstanceState{Gateway: true, Profile: "Team", Counters: "valkey", Providers: []ProviderBrief{{Name: "openai", Provider: "openai", State: "ok"}}})
	a.db.PutInstance(ctx, store.Instance{ID: "g1", Role: "gateway", Host: "gw-1", Version: "v", Started: now, Seen: now, State: st})
	a.db.PutInstance(ctx, store.Instance{ID: "g2", Role: "gateway", Host: "gw-2", Version: "v", Started: now, Seen: now.Add(-2 * time.Minute), State: st})
	a.db.PutInstance(ctx, store.Instance{ID: "gone", Role: "gateway", Host: "gw-3", Version: "v", Started: now, Seen: time.UnixMilli(1)})

	code, body := a.do("GET", "/api/v1/fleet", "")
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	var out struct {
		Rows []FleetMember `json:"rows"`
	}
	json.Unmarshal([]byte(body), &out)
	status := map[string]string{}
	for _, m := range out.Rows {
		status[m.Host] = m.Status
	}
	if status["gw-1"] != "up" || status["gw-2"] != "silent" || status["gw-3"] != "" || len(out.Rows) != 2 {
		t.Fatalf("up, silent, and a process that left: %v", status)
	}
	if out.Rows[0].State == nil || out.Rows[0].State.Counters != "valkey" {
		t.Fatalf("state: %+v", out.Rows[0].State)
	}
	if strings.Contains(body, "sk-") || strings.Contains(body, "base_url") {
		t.Fatalf("a heartbeat carries no key and no provider address: %s", body)
	}
}

// A heartbeat writes its row, then leaves the view when it stops cleanly.
func TestHeartbeatJoinsAndLeaves(t *testing.T) {
	a := newAdminRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	hb := &Heartbeat{DB: a.db, Role: "all", Version: "test", Logf: t.Logf, Collect: func() InstanceState { return InstanceState{Gateway: true, Control: true} }}
	done := make(chan struct{})
	go func() { hb.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, body := a.do("GET", "/api/v1/fleet", "")
		if strings.Contains(body, `"status":"up"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no heartbeat: %s", body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if _, body := a.do("GET", "/api/v1/fleet", ""); strings.Contains(body, `"role":"all"`) {
		t.Fatalf("a cleanly stopped process is still listed: %s", body)
	}
}
