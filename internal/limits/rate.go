package limits

// Rate limits per virtual key (OP-5): requests per minute, and
// tokens per minute. Each is a token bucket that refills continuously, so a
// key may burst up to a minute's worth and then waits. Tokens are estimated
// before the call and corrected with the provider's usage after it. In Solo
// the buckets live in this process; with several gateways (Team), each
// instance keeps its own, an approximate limit (architecture §5.4).

import (
	"math"
	"sync"
	"time"
)

// Rates holds the buckets.
type Rates struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	level float64 // what remains
	at    time.Time
}

// NewRates returns empty buckets.
func NewRates() *Rates { return &Rates{buckets: map[string]*bucket{}} }

// take takes n from the bucket of key, whose size and refill per minute is
// perMinute. It reports how long to wait when the bucket is short.
func (r *Rates) take(key string, perMinute int, n float64, now time.Time, force bool) (bool, time.Duration) {
	if perMinute <= 0 {
		return true, 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.buckets[key]
	size := float64(perMinute)
	if b == nil {
		b = &bucket{level: size, at: now}
		r.buckets[key] = b
		if len(r.buckets) > 100000 {
			r.buckets = map[string]*bucket{key: b}
		}
	}
	b.level = math.Min(size, b.level+now.Sub(b.at).Minutes()*size)
	b.at = now
	if b.level >= n || force {
		b.level -= n
		return true, 0
	}
	wait := time.Duration((n - b.level) / size * float64(time.Minute))
	return false, wait.Round(time.Second) + time.Second
}

// Request counts one request of a key. ok is false when the key is over its
// requests per minute; retry says when to try again. In monitor mode (force)
// the request is counted and allowed.
func (r *Rates) Request(keyID string, perMinute int, now time.Time, force bool) (ok bool, retry time.Duration) {
	return r.take("req:"+keyID, perMinute, 1, now, force)
}

// Tokens takes an estimate of tokens for a key.
func (r *Rates) Tokens(keyID string, perMinute int, n int, now time.Time, force bool) (ok bool, retry time.Duration) {
	return r.take("tok:"+keyID, perMinute, float64(n), now, force)
}

// AdjustTokens corrects an estimate with the real count (positive: more were
// used than estimated).
func (r *Rates) AdjustTokens(keyID string, perMinute int, delta int, now time.Time) {
	if perMinute <= 0 || delta == 0 {
		return
	}
	r.take("tok:"+keyID, perMinute, float64(delta), now, true)
}

// Limiter is a per-key rate limiter: Rates in one process, SharedRates when
// several gateways share the counters (Team).
type Limiter interface {
	Request(keyID string, perMinute int, now time.Time, force bool) (bool, time.Duration)
	Tokens(keyID string, perMinute int, n int, now time.Time, force bool) (bool, time.Duration)
	AdjustTokens(keyID string, perMinute int, delta int, now time.Time)
}

var _ Limiter = (*Rates)(nil)
