package cache

// Coalescing (OP-6; architecture §4.5). Identical requests that
// arrive while the first is still running wait for it and share its answer.
// The first, the leader, makes the call, detached from its own connection;
// the provider's response is recorded on a tape, and every caller, the leader
// included, reads the tape from its start, so a follower of a stream first
// gets what was produced so far, then follows live. Each caller rehydrates
// the masked answer with its own values (principle 5). Per gateway instance.

import (
	"context"
	"io"
	"net/http"
	"sync"
)

// Flights holds the calls in flight, by key.
type Flights struct {
	mu sync.Mutex
	m  map[string]*Flight
}

// NewFlights returns an empty registry.
func NewFlights() *Flights { return &Flights{m: map[string]*Flight{}} }

// Flight is one call that several callers share.
type Flight struct {
	mu      sync.Mutex
	cond    *sync.Cond
	ready   chan struct{} // closed when the status and headers are known, or on abort
	aborted bool
	status  int
	header  http.Header
	conn    string // the provider connection's name
	buf     []byte
	done    bool
	err     error
}

// Join returns the flight for key and whether the caller leads it. A leader
// must call Start or Abort, then Leave.
func (f *Flights) Join(key string) (*Flight, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if fl, ok := f.m[key]; ok {
		return fl, false
	}
	fl := &Flight{ready: make(chan struct{})}
	fl.cond = sync.NewCond(&fl.mu)
	f.m[key] = fl
	return fl, true
}

// Leave removes the leader's flight, once its answer is stored in the cache:
// a request that arrives later gets a cache hit instead.
func (f *Flights) Leave(key string, fl *Flight) {
	f.mu.Lock()
	if f.m[key] == fl {
		delete(f.m, key)
	}
	f.mu.Unlock()
}

// InFlight is the number of shared calls running.
func (f *Flights) InFlight() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.m)
}

// Abort tells followers that no answer is coming: they make their own call.
func (fl *Flight) Abort() {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	select {
	case <-fl.ready:
		return
	default:
	}
	fl.aborted = true
	close(fl.ready)
}

// Start records the provider's response on the tape, in the background, and
// returns a response that reads it, for the leader.
func (fl *Flight) Start(resp *http.Response, conn string) *http.Response {
	fl.mu.Lock()
	fl.status, fl.header, fl.conn = resp.StatusCode, resp.Header.Clone(), conn
	close(fl.ready)
	fl.mu.Unlock()
	go func() {
		defer resp.Body.Close()
		// Small: the buffer lives as long as the call, and a stream arrives
		// in small pieces (eval/load measures an open stream's memory).
		b := make([]byte, 4<<10)
		for {
			n, err := resp.Body.Read(b)
			fl.mu.Lock()
			fl.buf = append(fl.buf, b[:n]...)
			if err != nil {
				fl.done = true
				if err != io.EOF {
					fl.err = err
				}
			}
			fl.cond.Broadcast()
			fl.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return fl.response()
}

// Wait waits for the leader's response. ok is false when the leader gave up
// before answering, or the caller left.
func (fl *Flight) Wait(ctx context.Context) (resp *http.Response, conn string, ok bool) {
	select {
	case <-fl.ready:
	case <-ctx.Done():
		return nil, "", false
	}
	fl.mu.Lock()
	aborted := fl.aborted
	fl.mu.Unlock()
	if aborted {
		return nil, "", false
	}
	return fl.response(), fl.conn, true
}

func (fl *Flight) response() *http.Response {
	return &http.Response{StatusCode: fl.status, Header: fl.header.Clone(), Body: &tapeReader{fl: fl}}
}

// tapeReader reads the tape from its start, waiting for more until it ends.
type tapeReader struct {
	fl  *Flight
	off int
}

func (t *tapeReader) Read(p []byte) (int, error) {
	fl := t.fl
	fl.mu.Lock()
	defer fl.mu.Unlock()
	for t.off >= len(fl.buf) && !fl.done {
		fl.cond.Wait()
	}
	if t.off >= len(fl.buf) {
		if fl.err != nil {
			return 0, fl.err
		}
		return 0, io.EOF
	}
	n := copy(p, fl.buf[t.off:])
	t.off += n
	return n, nil
}

func (t *tapeReader) Close() error { return nil }
