// Package limits protects the gateway from overload (pipeline stage 3).
//
// It caps concurrent requests and request size. Rate limits and budgets per
// organization, team, user, and key, with reserve and settle, are in rate.go
// and budget.go (capability OP-5).
package limits

// Concurrency is a cap on requests in flight.
type Concurrency struct {
	slots chan struct{}
}

// NewConcurrency allows n requests at once.
func NewConcurrency(n int) *Concurrency {
	return &Concurrency{slots: make(chan struct{}, n)}
}

// TryAcquire takes a slot, or reports false when every slot is busy.
func (c *Concurrency) TryAcquire() bool {
	select {
	case c.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release returns a slot.
func (c *Concurrency) Release() { <-c.slots }

// InFlight is the number of requests holding a slot.
func (c *Concurrency) InFlight() int { return len(c.slots) }

// MaxBodyBytes is the largest request body accepted.
const MaxBodyBytes = 32 << 20
