// Package guard is the gateway's client of the Guard, the ML service that
// detects personal data and threats (capabilities PR-2, PR-5; architecture
// §4.4). The Guard detects; the gateway enforces (invariant 1): this client
// returns findings and threats, and the pipeline decides.
//
// Security fails closed (invariant 2): every call has a deadline, and an error,
// a missed deadline, or an answer that does not fit the request is returned as
// an error, which the pipeline handles with the policy's on_guard_unavailable.
package guard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Kytherion/KyGate/internal/detect"
	"github.com/Kytherion/KyGate/internal/detect/guard/guardpb"
)

// DefaultTimeout is the base deadline of one Inspect call. The deadline grows
// with the amount of text sent, because a model on a CPU takes time per token:
// PerThousandChars more for each 1,000 characters, up to MaxTimeout. A Guard
// that does not answer within it counts as unavailable (fail closed).
const (
	DefaultTimeout   = 2 * time.Second
	PerThousandChars = time.Second
	MaxTimeout       = 60 * time.Second
)

// Segment is one piece of text to inspect.
type Segment struct {
	Index     int // index in the request
	ID        string
	Role      guardpb.Role
	Kind      guardpb.ContentKind
	Untrusted bool
	Text      string
}

// Threat is a threat score for one segment.
type Threat struct {
	Segment  int
	Type     string
	Score    float64
	Detector string
}

// Client talks to one Guard.
type Client struct {
	Addr    string
	Timeout time.Duration
	conn    *grpc.ClientConn
	api     guardpb.GuardClient

	calls, failures atomic.Int64
	totalMicros     atomic.Int64
	mu              sync.Mutex
	lastErr         string
	lastErrAt       time.Time
	info            *guardpb.InfoResponse
	infoAt          time.Time
}

// Dial connects lazily: an unreachable Guard is an error at the first call,
// not at start, so the gateway starts and applies on_guard_unavailable.
//
// The address is resolved by DNS, and calls are spread over every address it
// returns (round robin): with a headless Kubernetes service, each call goes
// to the next Guard pod, not all of them to one (architecture section 4.4).
// TLS, and mutual TLS, come from KYGATE_GUARD_TLS_CA, KYGATE_GUARD_TLS_CERT,
// KYGATE_GUARD_TLS_KEY, and KYGATE_GUARD_TLS_SERVER_NAME.
func Dial(addr string) (*Client, error) {
	creds, err := TransportFromEnv()
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds),
		grpc.WithDefaultServiceConfig(`{"loadBalancingConfig":[{"round_robin":{}}]}`))
	if err != nil {
		return nil, err
	}
	return &Client{Addr: addr, Timeout: DefaultTimeout, conn: conn, api: guardpb.NewGuardClient(conn)}, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// ErrNotReady means the Guard answers but has not loaded its models yet.
var ErrNotReady = errors.New("the Guard is not ready: its models are still loading")

// Inspect returns the findings and threats for the segments. Offsets are
// checked against the text; an answer that does not fit is an error.
func (c *Client) Inspect(ctx context.Context, segs []Segment, entityTypes, threatTypes []string, policyVersion string) ([]detect.Finding, []Threat, error) {
	if len(segs) == 0 {
		return nil, nil, nil
	}
	req := &guardpb.InspectRequest{EntityTypes: entityTypes, ThreatTypes: threatTypes, PolicyVersion: policyVersion}
	byID := map[string]Segment{}
	for _, s := range segs {
		req.Segments = append(req.Segments, &guardpb.Segment{Id: s.ID, Role: s.Role, Kind: s.Kind, Untrusted: s.Untrusted, Text: s.Text})
		byID[s.ID] = s
	}
	chars := 0
	for _, s := range segs {
		chars += len(s.Text)
	}
	ctx, cancel := context.WithTimeout(ctx, c.deadline(chars))
	defer cancel()
	start := time.Now()
	resp, err := c.api.Inspect(ctx, req)
	c.record(start, err)
	if err != nil {
		return nil, nil, fmt.Errorf("the Guard at %s: %w", c.Addr, err)
	}
	var findings []detect.Finding
	for _, f := range resp.Findings {
		s, ok := byID[f.SegmentId]
		start, end := int(f.Start), int(f.End)
		if !ok || start < 0 || end > len(s.Text) || start >= end || !utf8.RuneStart(byteAt(s.Text, start)) || (end < len(s.Text) && !utf8.RuneStart(s.Text[end])) {
			err := fmt.Errorf("the Guard at %s returned a finding that does not fit its segment (%q %d-%d)", c.Addr, f.SegmentId, start, end)
			c.fail(err)
			return nil, nil, err
		}
		if f.EntityType == "" {
			err := fmt.Errorf("the Guard at %s returned a finding with no data type", c.Addr)
			c.fail(err)
			return nil, nil, err
		}
		findings = append(findings, detect.Finding{Segment: s.Index, Type: f.EntityType, Start: start, End: end, Score: float64(f.Score), Detector: f.Detector, Language: f.Language})
	}
	var threats []Threat
	for _, t := range resp.Threats {
		s, ok := byID[t.SegmentId]
		if !ok {
			err := fmt.Errorf("the Guard at %s returned a threat for an unknown segment %q", c.Addr, t.SegmentId)
			c.fail(err)
			return nil, nil, err
		}
		threats = append(threats, Threat{Segment: s.Index, Type: t.Type, Score: float64(t.Score), Detector: t.Detector})
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Segment != findings[j].Segment {
			return findings[i].Segment < findings[j].Segment
		}
		return findings[i].Start < findings[j].Start
	})
	return findings, threats, nil
}

func byteAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

// Info asks the Guard for its models and readiness, and keeps the answer for
// the console.
func (c *Client) Info(ctx context.Context) (*guardpb.InfoResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	info, err := c.api.Info(ctx, &guardpb.InfoRequest{})
	if err != nil {
		c.fail(err)
		return nil, err
	}
	c.mu.Lock()
	c.info, c.infoAt = info, time.Now()
	c.mu.Unlock()
	return info, nil
}

// Watch refreshes the Guard's information until ctx ends, so the console
// shows its state and the pipeline knows whether it is ready.
func (c *Client) Watch(ctx context.Context, every time.Duration) {
	c.Info(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Info(ctx)
		}
	}
}

// deadline is the time one Inspect call of so many bytes of text may take.
func (c *Client) deadline(chars int) time.Duration {
	d := c.timeout() + time.Duration(chars)*PerThousandChars/1000
	if d > MaxTimeout {
		d = MaxTimeout
	}
	return d
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

func (c *Client) record(start time.Time, err error) {
	c.calls.Add(1)
	c.totalMicros.Add(time.Since(start).Microseconds())
	if err != nil {
		c.fail(err)
	}
}

func (c *Client) fail(err error) {
	c.failures.Add(1)
	c.mu.Lock()
	c.lastErr, c.lastErrAt = err.Error(), time.Now()
	c.mu.Unlock()
}

// State is what the console shows about the Guard.
type State struct {
	Addr        string           `json:"addr"`
	State       string           `json:"state"` // ready | loading | unreachable | unknown
	Calls       int64            `json:"calls"`
	Failures    int64            `json:"failures"`
	AvgMS       float64          `json:"avg_ms"`
	LastError   string           `json:"last_error,omitempty"`
	LastErrorAt time.Time        `json:"last_error_at,omitempty"`
	Version     string           `json:"version,omitempty"`
	EntityTypes []string         `json:"entity_types,omitempty"`
	ThreatTypes []string         `json:"threat_types,omitempty"`
	Languages   []string         `json:"languages,omitempty"`
	Models      []*guardpb.Model `json:"models,omitempty"`
	// Coverage says, per data type, which level finds it: list or model.
	Coverage []Coverage `json:"coverage,omitempty"`
}

// Coverage is the level that finds one data type, and the detectors behind it.
type Coverage struct {
	EntityType string   `json:"entity_type"`
	Level      string   `json:"level"` // model | list
	Detectors  []string `json:"detectors"`
}

// Levels returns the level per data type from the Guard's last Info answer,
// and false when the Guard has not answered Info yet.
func (c *Client) Levels() (map[string]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.info == nil {
		return nil, false
	}
	out := map[string]string{}
	for _, cv := range c.info.Coverage {
		out[cv.EntityType] = cv.Level
	}
	return out, true
}

// State returns the Guard's state for the console.
func (c *Client) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := State{Addr: c.Addr, State: "unknown", Calls: c.calls.Load(), Failures: c.failures.Load(), LastError: c.lastErr, LastErrorAt: c.lastErrAt}
	if s.Calls > 0 {
		s.AvgMS = float64(c.totalMicros.Load()) / float64(s.Calls) / 1000
	}
	switch {
	case c.info != nil && c.lastErrAt.After(c.infoAt):
		s.State = "unreachable"
	case c.info != nil && c.info.Ready:
		s.State = "ready"
	case c.info != nil:
		s.State = "loading"
	case c.lastErr != "":
		s.State = "unreachable"
	}
	if c.info != nil {
		s.Version, s.EntityTypes, s.ThreatTypes, s.Languages, s.Models = c.info.Version, c.info.EntityTypes, c.info.ThreatTypes, c.info.Languages, c.info.Models
		for _, cv := range c.info.Coverage {
			s.Coverage = append(s.Coverage, Coverage{EntityType: cv.EntityType, Level: cv.Level, Detectors: cv.Detectors})
		}
	}
	return s
}

// Ready reports whether the last Info said the Guard is ready.
func (c *Client) Ready() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.info != nil && c.info.Ready
}

// TransportFromEnv returns the Guard link's transport: plain gRPC, or TLS
// with the CA in KYGATE_GUARD_TLS_CA, and mutual TLS when
// KYGATE_GUARD_TLS_CERT and KYGATE_GUARD_TLS_KEY name this gateway's own
// certificate.
func TransportFromEnv() (credentials.TransportCredentials, error) {
	ca, cert, key := os.Getenv("KYGATE_GUARD_TLS_CA"), os.Getenv("KYGATE_GUARD_TLS_CERT"), os.Getenv("KYGATE_GUARD_TLS_KEY")
	if ca == "" {
		if cert != "" || key != "" {
			return nil, errors.New("KYGATE_GUARD_TLS_CERT and _KEY need KYGATE_GUARD_TLS_CA, the CA of the Guard's certificate")
		}
		return insecure.NewCredentials(), nil
	}
	pem, err := os.ReadFile(ca)
	if err != nil {
		return nil, fmt.Errorf("KYGATE_GUARD_TLS_CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("KYGATE_GUARD_TLS_CA %s holds no certificate", ca)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: os.Getenv("KYGATE_GUARD_TLS_SERVER_NAME")}
	if (cert == "") != (key == "") {
		return nil, errors.New("KYGATE_GUARD_TLS_CERT and KYGATE_GUARD_TLS_KEY go together")
	}
	if cert != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("the gateway's Guard client certificate: %v", err)
		}
		tc.Certificates = []tls.Certificate{pair}
	}
	return credentials.NewTLS(tc), nil
}

// TransportDescription says how the gateway talks to the Guard, for the banner.
func TransportDescription() string {
	switch {
	case os.Getenv("KYGATE_GUARD_TLS_CERT") != "":
		return "mutual TLS"
	case os.Getenv("KYGATE_GUARD_TLS_CA") != "":
		return "TLS"
	}
	return "plain gRPC"
}
