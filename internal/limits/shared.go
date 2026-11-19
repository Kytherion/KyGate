package limits

// SharedRates enforces the per-key rate limits over counters that several
// gateways share (Team, Valkey): one counter per key and calendar minute,
// added to and checked in one step. A request that would pass the limit gives
// its count back. Unlike the token bucket of one process, a minute starts
// fresh: a key may use its whole limit at the end of one minute and again at
// the start of the next.
//
// When the counters cannot be reached, each gateway falls back to its own
// token buckets (Local): the limits become approximate, per instance, as
// architecture §5.4 says, rather than off.

import (
	"context"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
)

// SharedRates implements Limiter over store.Counters.
type SharedRates struct {
	C     store.Counters
	Local *Rates // used while C fails; nil means no limit then

	// Fallbacks counts the decisions taken by Local because C failed.
	Fallbacks atomic.Int64
}

var _ Limiter = (*SharedRates)(nil)

func (s *SharedRates) take(kind, keyID string, perMinute int, n float64, now time.Time, force bool) (bool, time.Duration) {
	if perMinute <= 0 {
		return true, 0
	}
	minute := now.UTC().Truncate(time.Minute)
	key := "rate:" + kind + ":" + keyID + ":" + strconv.FormatInt(minute.Unix(), 10)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	v, err := s.C.Add(ctx, key, n, minute.Add(2*time.Minute))
	if err != nil {
		s.Fallbacks.Add(1)
		if s.Local == nil {
			return true, 0
		}
		return s.Local.take(kind+":"+keyID, perMinute, n, now, force)
	}
	if v <= float64(perMinute) || force {
		return true, 0
	}
	s.C.Add(ctx, key, -n, minute.Add(2*time.Minute))
	return false, minute.Add(time.Minute).Sub(now).Round(time.Second) + time.Second
}

func (s *SharedRates) Request(keyID string, perMinute int, now time.Time, force bool) (bool, time.Duration) {
	return s.take("req", keyID, perMinute, 1, now, force)
}

func (s *SharedRates) Tokens(keyID string, perMinute int, n int, now time.Time, force bool) (bool, time.Duration) {
	return s.take("tok", keyID, perMinute, float64(n), now, force)
}

func (s *SharedRates) AdjustTokens(keyID string, perMinute int, delta int, now time.Time) {
	if perMinute <= 0 || delta == 0 {
		return
	}
	s.take("tok", keyID, perMinute, float64(delta), now, true)
}
