// Package events writes one usage and audit event per request (capability
// GV-3, OB-1, architecture §4.8).
//
// Events are written first to an append-only spool on local disk, then
// delivered to the event store. A gateway that crashes loses nothing that
// reached the spool. Delivery is at least once; event IDs let the store drop
// duplicates. Events carry metadata only, never prompt or answer text, unless
// the policy captures masked payloads, which are encrypted.
package events

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Kytherion/KyGate/internal/store"
)

// ErrSpoolFull is returned when the spool holds more than its limit.
var ErrSpoolFull = errors.New("event spool is full")

// Spool is the append-only event file set.
type Spool struct {
	dir      string
	maxBytes int64

	mu      sync.Mutex
	cur     *os.File
	curN    int
	size    atomic.Int64
	dropped atomic.Int64
	Logf    func(format string, a ...any)

	// Delivery health, for the console's fleet view.
	lastOK  atomic.Int64 // Unix milliseconds of the last delivery that emptied the spool
	healthM sync.Mutex
	lastErr string
	errAt   time.Time
}

// Health is what the fleet view shows about delivery.
type Health struct {
	Bytes        int64     `json:"bytes"`   // waiting in the spool
	Dropped      int64     `json:"dropped"` // events dropped because the spool was full
	LastDelivery time.Time `json:"last_delivery,omitzero"`
	LastError    string    `json:"last_error,omitempty"`
	LastErrorAt  time.Time `json:"last_error_at,omitzero"`
}

// Health reports the spool's delivery state.
func (s *Spool) Health() Health {
	h := Health{Bytes: s.size.Load(), Dropped: s.dropped.Load()}
	if ms := s.lastOK.Load(); ms > 0 {
		h.LastDelivery = time.UnixMilli(ms)
	}
	s.healthM.Lock()
	h.LastError, h.LastErrorAt = s.lastErr, s.errAt
	s.healthM.Unlock()
	return h
}

func (s *Spool) noteDelivery(err error) {
	if err == nil {
		s.lastOK.Store(time.Now().UnixMilli())
		return
	}
	s.healthM.Lock()
	s.lastErr, s.errAt = err.Error(), time.Now()
	s.healthM.Unlock()
}

const current = "current.jsonl"

// OpenSpool opens the spool directory. A segment left by a previous run is
// kept and delivered.
func OpenSpool(dir string, maxBytes int64) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Spool{dir: dir, maxBytes: maxBytes, Logf: func(string, ...any) {}}
	if _, err := os.Stat(filepath.Join(dir, current)); err == nil {
		if err := os.Rename(filepath.Join(dir, current), filepath.Join(dir, segName())); err != nil {
			return nil, err
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			s.size.Add(info.Size())
		}
	}
	f, err := os.OpenFile(filepath.Join(dir, current), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	s.cur = f
	return s, nil
}

var segSeq atomic.Int64

func segName() string {
	return fmt.Sprintf("seg-%020d-%06d.jsonl", time.Now().UnixNano(), segSeq.Add(1)%1000000)
}

// Full reports whether the spool is over its limit.
func (s *Spool) Full() bool { return s.size.Load() >= s.maxBytes }

// Bytes is the current spool size.
func (s *Spool) Bytes() int64 { return s.size.Load() }

// Dropped counts events dropped because the spool was full.
func (s *Spool) Dropped() int64 { return s.dropped.Load() }

// Append writes one event.
func (s *Spool) Append(e *store.Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if s.Full() {
		s.dropped.Add(1)
		return ErrSpoolFull
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.cur.Write(line)
	s.size.Add(int64(n))
	s.curN++
	return err
}

// rotate closes the current segment, if it holds events, and starts a new one.
func (s *Spool) rotate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.curN == 0 {
		return nil
	}
	if err := s.cur.Sync(); err != nil {
		return err
	}
	if err := s.cur.Close(); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(s.dir, current), filepath.Join(s.dir, segName())); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(s.dir, current), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	s.cur, s.curN = f, 0
	return nil
}

// Deliver rotates the current segment and writes every closed segment to the
// store, oldest first. A segment is removed only after the store accepted it.
func (s *Spool) Deliver(ctx context.Context, es store.EventStore) (err error) {
	defer func() { s.noteDelivery(err) }()
	if err := s.rotate(); err != nil {
		return err
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var segs []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "seg-") {
			segs = append(segs, e.Name())
		}
	}
	sort.Strings(segs)
	for _, name := range segs {
		path := filepath.Join(s.dir, name)
		batch, size, err := readSegment(path)
		if err != nil {
			s.Logf("event spool: segment %s is unreadable and is kept for inspection: %v", name, err)
			os.Rename(path, path+".bad")
			continue
		}
		if err := es.InsertEvents(ctx, batch); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		s.size.Add(-size)
	}
	return nil
}

func readSegment(path string) ([]store.Event, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	info, _ := f.Stat()
	var out []store.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e store.Event
		if err := json.Unmarshal(line, &e); err != nil {
			// A torn last line after a crash: skip it, keep the rest.
			continue
		}
		out = append(out, e)
	}
	return out, info.Size(), sc.Err()
}

// Run delivers events every interval until ctx ends, then delivers once more.
func (s *Spool) Run(ctx context.Context, es store.EventStore, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			final, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := s.Deliver(final, es); err != nil {
				s.Logf("event spool: final delivery failed; events stay in the spool: %v", err)
			}
			cancel()
			return
		case <-t.C:
			if err := s.Deliver(ctx, es); err != nil {
				s.Logf("event spool: delivery failed, will retry: %v", err)
			}
		}
	}
}

// Close closes the current segment.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur.Close()
}
