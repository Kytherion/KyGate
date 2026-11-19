package control

// The fleet view: every KyGate process (Solo's single one, Team's control
// process and gateways, Helm's pods) writes a heartbeat to the database every
// HeartbeatEvery, in the background, with its own view of what it depends on:
// the Guard, the counters, the cache, the event spool, the providers. The
// console reads them. A process that stops cleanly removes its row; one that
// crashed shows as silent, and the control process forgets it after a day.
// A heartbeat carries metadata only: no key, no value, no text, no address of
// a provider.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/Kytherion/KyGate/internal/detect/guard"
	"github.com/Kytherion/KyGate/internal/events"
	"github.com/Kytherion/KyGate/internal/store"
)

// Heartbeat timing.
const (
	HeartbeatEvery = 10 * time.Second
	silentAfter    = 3 * HeartbeatEvery
	forgetAfter    = 24 * time.Hour
)

// InstanceState is one process's own view, written with its heartbeat.
type InstanceState struct {
	Gateway   bool            `json:"gateway"` // serves the model API
	Control   bool            `json:"control"` // serves the console, seals the ledger
	Profile   string          `json:"profile"` // Solo | Team
	InFlight  int             `json:"in_flight"`
	Spool     events.Health   `json:"spool"`
	Guard     *GuardSummary   `json:"guard,omitempty"`
	Counters  string          `json:"counters"`          // memory | valkey | valkey, degraded
	Degraded  int64           `json:"counters_degraded"` // budget checks answered from the last known figures
	Fallbacks int64           `json:"rates_fallbacks"`   // rate decisions taken locally because Valkey failed
	Cache     string          `json:"cache"`             // memory | file | valkey; with "unavailable" when it is
	CacheErr  int64           `json:"cache_errors"`      // errors of the store behind the in-process cache
	Providers []ProviderBrief `json:"providers"`
}

// GuardSummary is the Guard as one process sees it.
type GuardSummary struct {
	State     string  `json:"state"` // ready | loading | unreachable | unknown
	Version   string  `json:"version,omitempty"`
	Calls     int64   `json:"calls"`
	Failures  int64   `json:"failures"`
	AvgMS     float64 `json:"avg_ms"`
	LastError string  `json:"last_error,omitempty"`
}

// SummarizeGuard trims the Guard's state to what the fleet view shows.
func SummarizeGuard(g *guard.Client) *GuardSummary {
	if g == nil {
		return nil
	}
	s := g.State()
	return &GuardSummary{State: s.State, Version: s.Version, Calls: s.Calls, Failures: s.Failures, AvgMS: s.AvgMS, LastError: s.LastError}
}

// ProviderBrief is one provider connection as one process sees it.
type ProviderBrief struct {
	Name       string `json:"name"`
	Provider   string `json:"provider"`
	State      string `json:"state"`
	LastStatus int    `json:"last_status,omitempty"`
	Requests   int64  `json:"requests"`
	Failures   int64  `json:"failures"`
}

// Heartbeat writes this process's row until ctx ends, then removes it.
type Heartbeat struct {
	DB       store.FleetStore
	Role     string
	Version  string
	Collect  func() InstanceState
	Forget   bool // the control process forgets silent processes after a day
	Logf     func(format string, a ...any)
	instance store.Instance
}

// Run beats at once, then every HeartbeatEvery.
func (h *Heartbeat) Run(ctx context.Context) {
	host, _ := os.Hostname()
	b := make([]byte, 6)
	rand.Read(b)
	h.instance = store.Instance{ID: hex.EncodeToString(b), Role: h.Role, Host: host, Version: h.Version, Started: time.Now()}
	t := time.NewTicker(HeartbeatEvery)
	defer t.Stop()
	failing := false
	for {
		err := h.beat(ctx)
		switch {
		case err != nil && !failing:
			h.Logf("fleet heartbeat: %v (the console's fleet view will show this process as silent)", err)
			failing = true
		case err == nil && failing:
			h.Logf("fleet heartbeat: written again")
			failing = false
		}
		select {
		case <-ctx.Done():
			gone, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			// Stopped cleanly: leave the fleet. A crash leaves a silent row.
			h.leave(gone)
			cancel()
			return
		case <-t.C:
		}
	}
}

func (h *Heartbeat) beat(ctx context.Context) error {
	st, _ := json.Marshal(h.Collect())
	h.instance.Seen, h.instance.State = time.Now(), st
	if err := h.DB.PutInstance(ctx, h.instance); err != nil {
		return err
	}
	if h.Forget {
		h.DB.DeleteInstancesBefore(ctx, time.Now().Add(-forgetAfter))
	}
	return nil
}

// leave marks this process's row as gone by moving its last sighting far
// into the past, so that the next forget removes it, and the view stops
// listing it now.
func (h *Heartbeat) leave(ctx context.Context) {
	h.instance.Seen = time.UnixMilli(1)
	h.DB.PutInstance(ctx, h.instance)
}

// FleetMember is one process as the console shows it.
type FleetMember struct {
	store.Instance
	Status string         `json:"status"` // up | silent
	State  *InstanceState `json:"state,omitempty"`
}

// fleet serves GET /api/v1/fleet: every process heard from in the last day.
func (c *Console) fleet(w http.ResponseWriter, r *http.Request) {
	if p := PrincipalOf(r); !p.ReadsAll() {
		apiError(w, 403, "the fleet view is for roles that see the whole organization")
		return
	}
	fs, ok := c.Config.(store.FleetStore)
	if !ok {
		apiError(w, 404, "this store keeps no heartbeats")
		return
	}
	ins, err := fs.ListInstances(r.Context())
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	now := time.Now()
	out := []FleetMember{}
	for _, in := range ins {
		if in.Seen.Before(now.Add(-forgetAfter)) {
			continue // stopped cleanly, or long gone
		}
		m := FleetMember{Instance: in, Status: "up"}
		if now.Sub(in.Seen) > silentAfter {
			m.Status = "silent"
		}
		var st InstanceState
		if json.Unmarshal(in.State, &st) == nil {
			m.State = &st
		}
		out = append(out, m)
	}
	writeJSON(w, map[string]any{"now": now, "silent_after_s": int(silentAfter.Seconds()), "rows": out})
}
