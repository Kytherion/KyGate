package limits

// Budget counters when the shared store is down (Team, architecture §5.4):
// "budgets continue on the last known values; policy decides whether hard
// limits fail open or closed".
//
// FallbackCounters wraps the shared counters (Valkey). Every answer from the
// store is mirrored in memory. When the store fails, the counter goes on
// from its mirrored value, in this process, and the call returns
// ErrApproximate with the value, so the budget check still runs, on an
// approximate figure. The spend added during the outage is kept and added to
// the store once it answers again, so the shared figures catch up.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
)

// ErrApproximate means the value comes from this process's last known
// figures, not from the shared store.
var ErrApproximate = errors.New("the shared budget counters cannot be reached: this process goes on from the last values it saw")

// FallbackCounters implements store.Counters over a shared store, with a
// local mirror for outages.
type FallbackCounters struct {
	Shared store.Counters

	mirror  *MemoryCounters // the last value seen of each counter, plus local additions during an outage
	mu      sync.Mutex
	pending map[string]pendingAdd // added locally while the store was down

	// Degraded counts the calls answered from the mirror.
	Degraded atomic.Int64
	down     atomic.Bool
	retryAt  atomic.Int64 // Unix ms: while down, the store is tried again after this
}

// retryEvery is how often a process tries the store again during an
// outage; in between, requests use the mirror without waiting on the network.
const retryEvery = 2 * time.Second

// skip reports whether to answer from the mirror without trying the store.
func (f *FallbackCounters) skip() bool {
	return f.down.Load() && time.Now().UnixMilli() < f.retryAt.Load()
}

func (f *FallbackCounters) failed() {
	f.down.Store(true)
	f.retryAt.Store(time.Now().Add(retryEvery).UnixMilli())
	f.Degraded.Add(1)
}

type pendingAdd struct {
	delta   float64
	expires time.Time
}

// NewFallbackCounters wraps shared counters.
func NewFallbackCounters(shared store.Counters) *FallbackCounters {
	return &FallbackCounters{Shared: shared, mirror: NewMemoryCounters(), pending: map[string]pendingAdd{}}
}

// Down reports whether the last call could not reach the store.
func (f *FallbackCounters) Down() bool { return f.down.Load() }

// Add adds to the shared counter, or to the mirror when the store fails.
func (f *FallbackCounters) Add(ctx context.Context, key string, delta float64, expires time.Time) (float64, error) {
	if !f.skip() {
		f.replay(ctx)
		v, err := f.Shared.Add(ctx, key, delta, expires)
		if err == nil {
			f.down.Store(false)
			f.set(key, v, expires)
			return v, nil
		}
		f.failed()
	} else {
		f.Degraded.Add(1)
	}
	f.mu.Lock()
	p := f.pending[key]
	p.delta += delta
	p.expires = expires
	f.pending[key] = p
	f.mu.Unlock()
	v, _ := f.mirror.Add(ctx, key, delta, expires)
	return v, ErrApproximate
}

// Get reads the shared counter, or the mirror when the store fails.
func (f *FallbackCounters) Get(ctx context.Context, key string) (float64, error) {
	if !f.skip() {
		f.replay(ctx)
		v, err := f.Shared.Get(ctx, key)
		if err == nil {
			f.down.Store(false)
			return v, nil
		}
		f.failed()
	} else {
		f.Degraded.Add(1)
	}
	v, _ := f.mirror.Get(ctx, key)
	return v, ErrApproximate
}

func (f *FallbackCounters) set(key string, v float64, expires time.Time) {
	f.mirror.mu.Lock()
	f.mirror.m[key] = memCounter{v: v, expires: expires}
	f.mirror.mu.Unlock()
}

// replay adds what was counted locally during an outage to the store, before
// any new figure is read, so that the store's answers include it. What
// cannot be added yet stays pending.
func (f *FallbackCounters) replay(ctx context.Context) {
	if !f.down.Load() {
		return
	}
	f.mu.Lock()
	pending := f.pending
	f.pending = map[string]pendingAdd{}
	f.mu.Unlock()
	now := time.Now()
	failed := false
	for k, p := range pending {
		if p.delta == 0 || now.After(p.expires) {
			continue
		}
		if !failed {
			if v, err := f.Shared.Add(ctx, k, p.delta, p.expires); err == nil {
				f.set(k, v, p.expires)
				continue
			}
			failed = true
		}
		f.mu.Lock()
		q := f.pending[k]
		q.delta += p.delta
		q.expires = p.expires
		f.pending[k] = q
		f.mu.Unlock()
	}
}
