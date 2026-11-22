package cache

// Coalescing (OP-6; architecture §4.5). Identical requests that
// arrive while the first is still running wait for it and share its answer.
// The first, the leader, makes the call, detached from its own connection;
// the provider's response is recorded on a tape, and every caller, the leader
// included, reads the tape from its start, so a follower of a stream first
// gets what was produced so far, then follows live. Each caller rehydrates
// the masked answer with its own values (principle 5). Per gateway instance.
//
// Every caller can leave at any time: a reader whose own request ends stops
// waiting at once. The call goes on while one caller still reads it, and ends
// when the last one leaves before the answer is complete, since nobody would
// use the rest of it.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
)

// MaxTape bounds what one shared call records, as a plain answer is bounded
// when it is read.
const MaxTape = 64 << 20

// ErrTapeFull ends a shared call whose answer is larger than MaxTape.
var ErrTapeFull = errors.New("the model's answer is larger than 64 MB")

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
	// readers are the callers that read the tape or wait for it: a follower
	// counts from the moment it joins, the leader from Start.
	readers int
	end     func() // ends the call
	// orphaned is set when the last reader left before the end: the call was
	// ended, and a caller that arrives now makes its own.
	orphaned bool
}

// Join returns the flight for key and whether the caller leads it. A leader
// must call Start or Abort, then Leave; a follower must call Wait.
func (f *Flights) Join(key string) (*Flight, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if fl, ok := f.m[key]; ok {
		// Counted from now on, so the call cannot end between the leader
		// leaving and this follower starting to read.
		fl.mu.Lock()
		fl.readers++
		fl.mu.Unlock()
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
// returns a response that reads it, for the leader, whose request is ctx. end
// ends the call: it is called when the tape is complete, or when the last
// reader leaves before that.
func (fl *Flight) Start(ctx context.Context, resp *http.Response, conn string, end func()) *http.Response {
	fl.mu.Lock()
	fl.status, fl.header, fl.conn, fl.end = resp.StatusCode, resp.Header.Clone(), conn, end
	close(fl.ready)
	fl.readers++
	r := fl.reader(ctx)
	fl.mu.Unlock()
	go func() {
		defer end()
		defer resp.Body.Close()
		// Small: the buffer lives as long as the call, and a stream arrives
		// in small pieces (eval/load measures an open stream's memory).
		b := make([]byte, 4<<10)
		for {
			n, err := resp.Body.Read(b)
			fl.mu.Lock()
			fl.buf = append(fl.buf, b[:n]...)
			if err == nil && len(fl.buf) > MaxTape {
				err = ErrTapeFull
			}
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
	return r
}

// Wait waits for the leader's response, for a follower that Join counted. ok
// is false when the leader gave up before answering, when the shared call
// already ended for lack of readers, or when the caller left; the follower
// then no longer counts.
func (fl *Flight) Wait(ctx context.Context) (resp *http.Response, conn string, ok bool) {
	select {
	case <-fl.ready:
	case <-ctx.Done():
		fl.mu.Lock()
		fl.leave()
		fl.mu.Unlock()
		return nil, "", false
	}
	fl.mu.Lock()
	defer fl.mu.Unlock()
	if fl.aborted || fl.orphaned {
		fl.leave()
		return nil, "", false
	}
	return fl.reader(ctx), fl.conn, true
}

// leave counts one reader out. When the last one leaves before the answer is
// complete, nobody would read the rest: the call ends. fl.mu is held.
func (fl *Flight) leave() {
	fl.readers--
	if fl.readers == 0 && !fl.done && fl.end != nil {
		fl.orphaned = true
		fl.end()
	}
}

// reader returns a response that reads the tape for a counted caller whose
// request is ctx. fl.mu is held.
func (fl *Flight) reader(ctx context.Context) *http.Response {
	t := &tapeReader{fl: fl, ctx: ctx}
	// The caller leaving wakes its reader, which then stops waiting.
	t.stop = context.AfterFunc(ctx, func() {
		fl.mu.Lock()
		fl.cond.Broadcast()
		fl.mu.Unlock()
	})
	return &http.Response{StatusCode: fl.status, Header: fl.header.Clone(), Body: t}
}

// tapeReader reads the tape from its start, waiting for more until it ends or
// its caller leaves.
type tapeReader struct {
	fl     *Flight
	off    int
	ctx    context.Context
	stop   func() bool
	closed bool
}

func (t *tapeReader) Read(p []byte) (int, error) {
	fl := t.fl
	fl.mu.Lock()
	defer fl.mu.Unlock()
	for t.off >= len(fl.buf) && !fl.done {
		if err := t.ctx.Err(); err != nil {
			return 0, err
		}
		// The wake-up for ctx takes fl.mu, so it cannot slip in between the
		// check above and this wait.
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

// Close stops this caller's reading. When the last reader leaves before the
// answer is complete, the call ends.
func (t *tapeReader) Close() error {
	t.stop()
	fl := t.fl
	fl.mu.Lock()
	defer fl.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	fl.leave()
	return nil
}
