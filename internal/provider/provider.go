// Package provider holds the provider connections and the adapters that call
// them: OpenAI, Anthropic, and OpenAI-compatible local model servers
// (capability AC-5).
//
// A connection is a provider or a local server, a name, and a credential.
// Credentials come from environment variables or from the encrypted store;
// both end in the same registry, so the request path does not know where a
// key came from (architecture §4.9). A credential is never logged, displayed,
// or returned by an API.
package provider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Kind of provider.
const (
	OpenAI    = "openai"
	Anthropic = "anthropic"
	Local     = "local"
)

// Default base URLs, without the /v1 suffix.
const (
	DefaultOpenAIBase    = "https://api.openai.com"
	DefaultAnthropicBase = "https://api.anthropic.com"
)

// Connection is one credential for one provider, or one local model server.
type Connection struct {
	Name     string
	Provider string // openai | anthropic | local
	BaseURL  string // without a trailing /v1
	Source   string // env | stored
	// Region is where the endpoint processes data, such as eu (GV-4); empty
	// when nobody said. A policy that pins regions never uses a connection
	// without one.
	Region string
	// Organization and Project are the OpenAI organization and project the
	// key bills, sent as OpenAI-Organization and OpenAI-Project. They belong
	// to the connection, never to a client: a caller of the gateway does not
	// choose what the operator's key bills. Empty: the key's own default.
	Organization, Project string
	key                   string

	mu         sync.Mutex
	state      string // unused | ok | rate_limited | rejected | unreachable | error
	lastStatus int
	lastError  string
	lastUsed   time.Time
	coolUntil  time.Time
	requests   int64
	failures   int64
	models     []string // discovered models, local servers only
}

// NewConnection builds a connection. key may be empty for local servers.
func NewConnection(name, provider, baseURL, key, source string) *Connection {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	baseURL = strings.TrimSuffix(baseURL, "/v1")
	if baseURL == "" {
		switch provider {
		case OpenAI:
			baseURL = DefaultOpenAIBase
		case Anthropic:
			baseURL = DefaultAnthropicBase
		}
	}
	return &Connection{Name: name, Provider: provider, BaseURL: baseURL, key: key, Source: source, state: "unused"}
}

// Hosting is local for local model servers, external otherwise.
func (c *Connection) Hosting() string {
	if c.Provider == Local {
		return "local"
	}
	return "external"
}

// State is what the console shows about a connection. It never holds the key.
type State struct {
	Name       string    `json:"name"`
	Provider   string    `json:"provider"`
	Hosting    string    `json:"hosting"`
	Source     string    `json:"source"`
	BaseURL    string    `json:"base_url"`
	Region     string    `json:"region,omitempty"`
	State      string    `json:"state"`
	LastStatus int       `json:"last_status,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
	LastUsed   time.Time `json:"last_used,omitempty"`
	Requests   int64     `json:"requests"`
	Failures   int64     `json:"failures"`
	Models     []string  `json:"models,omitempty"`
	KeyHint    string    `json:"key_hint,omitempty"`
}

// Snapshot returns the connection state.
func (c *Connection) Snapshot() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := State{Name: c.Name, Provider: c.Provider, Hosting: c.Hosting(), Source: c.Source, BaseURL: c.BaseURL, Region: c.Region,
		State: c.state, LastStatus: c.lastStatus, LastError: c.lastError, LastUsed: c.lastUsed,
		Requests: c.requests, Failures: c.failures, Models: append([]string(nil), c.models...)}
	if len(c.key) >= 8 {
		// The last four characters only, enough to tell two keys apart.
		s.KeyHint = "…" + c.key[len(c.key)-4:]
	}
	return s
}

func (c *Connection) available(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return now.After(c.coolUntil)
}

func (c *Connection) record(status int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastUsed = time.Now()
	c.requests++
	c.lastStatus = status
	switch {
	case err != nil:
		c.state, c.lastError = "unreachable", err.Error()
		c.failures++
		c.coolUntil = time.Now().Add(5 * time.Second)
	case status == 429:
		c.state, c.lastError = "rate_limited", "rate limited by the provider"
		c.failures++
		c.coolUntil = time.Now().Add(10 * time.Second)
	case status == 401 || status == 403:
		c.state, c.lastError = "rejected", "the provider rejected this key"
		c.failures++
		c.coolUntil = time.Now().Add(60 * time.Second)
	case status >= 500:
		c.state, c.lastError = "error", fmt.Sprintf("provider error %d", status)
		c.failures++
		c.coolUntil = time.Now().Add(3 * time.Second)
	default:
		c.state, c.lastError = "ok", ""
	}
}

// SetModels records the models a local server reported.
func (c *Connection) SetModels(models []string) {
	c.mu.Lock()
	c.models = models
	c.mu.Unlock()
}

// Models returns the models a local server reported.
func (c *Connection) Models() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.models...)
}

// Authorize sets a connection's authentication headers on an outgoing request.
func Authorize(c *Connection, h http.Header) { c.authorize(h) }

// authorize sets the provider's authentication headers, and for OpenAI the
// connection's organization and project.
func (c *Connection) authorize(h http.Header) {
	if c.Provider == OpenAI {
		h.Del("OpenAI-Organization")
		h.Del("OpenAI-Project")
		if c.Organization != "" {
			h.Set("OpenAI-Organization", c.Organization)
		}
		if c.Project != "" {
			h.Set("OpenAI-Project", c.Project)
		}
	}
	if c.key == "" {
		return
	}
	switch c.Provider {
	case Anthropic:
		h.Set("x-api-key", c.key)
	default:
		h.Set("Authorization", "Bearer "+c.key)
	}
}

// Registry holds every connection. It is rebuilt when keys change, and the
// state of a connection that survives a rebuild is kept.
type Registry struct {
	mu       sync.RWMutex
	conns    []*Connection
	affinity *affinityMap
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{affinity: newAffinityMap(50000)}
}

// Replace installs a new set of connections, keeping the state of those
// that did not change. A change of region, organization, or project makes a
// new connection, so that it applies at once: a region decides where a pinned
// request may go.
func (r *Registry) Replace(conns []*Connection) {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := map[string]*Connection{}
	for _, c := range r.conns {
		old[c.Name] = c
	}
	for i, c := range conns {
		if o, ok := old[c.Name]; ok && o.Provider == c.Provider && o.BaseURL == c.BaseURL && o.key == c.key &&
			o.Region == c.Region && o.Organization == c.Organization && o.Project == c.Project {
			conns[i] = o
		}
	}
	sort.SliceStable(conns, func(i, j int) bool { return conns[i].Name < conns[j].Name })
	r.conns = conns
}

// All returns every connection.
func (r *Registry) All() []*Connection {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]*Connection(nil), r.conns...)
}

// ByProvider returns the connections of one provider kind.
func (r *Registry) ByProvider(kind string) []*Connection {
	var out []*Connection
	for _, c := range r.All() {
		if c.Provider == kind {
			out = append(out, c)
		}
	}
	return out
}

// ByName returns one connection.
func (r *Registry) ByName(name string) *Connection {
	for _, c := range r.All() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Pin records that a conversation is served by a connection, for example
// after a cache hit, so that its next turn goes to the same account.
func (r *Registry) Pin(conversation, connection string) {
	if conversation != "" {
		r.affinity.set(conversation, connection)
	}
}

// Order returns the connections to try, in order. A conversation stays on the
// connection that served its first turn, because providers keep prompt caches
// per account (architecture §3.7, §4.6). Connections cooling down after a
// failure go last.
func (r *Registry) Order(pool []*Connection, conversation string) []*Connection {
	if len(pool) <= 1 {
		return pool
	}
	now := time.Now()
	pinned := r.affinity.get(conversation)
	var first, ready, cooling []*Connection
	for _, c := range pool {
		switch {
		case c.Name == pinned && c.available(now):
			first = append(first, c)
		case c.available(now):
			ready = append(ready, c)
		default:
			cooling = append(cooling, c)
		}
	}
	if len(first) == 0 && len(ready) > 1 && conversation != "" {
		// Spread new conversations across keys with a stable choice.
		h := fnv(conversation) % uint32(len(ready))
		ready = append(ready[h:], ready[:h]...)
	}
	return append(append(first, ready...), cooling...)
}

func fnv(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// Call is one upstream request.
type Call struct {
	Method       string
	Path         string // for example /v1/chat/completions
	Query        string
	Body         []byte
	Header       http.Header // headers to forward, without authentication
	Conversation string      // affinity key
}

// ErrNoConnection means no connection is configured for the target.
var ErrNoConnection = errors.New("no connection")

// Client sends calls upstream.
type Client struct {
	HTTP     *http.Client
	Registry *Registry
}

// NewClient returns a client with timeouts suited to long model answers.
func NewClient(reg *Registry) *Client {
	tr := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true,
		// Keep as many idle connections as calls can be in flight (serve's
		// --max-concurrency defaults to 1024), so that steady load reuses them.
		// With 64 per host, 1,000 streams to an HTTP/1.1 server (a local model
		// server) closed and dialled again about 900 connections a second, and
		// a few dials were refused (eval/load, 2026-11-19). HTTP/2 providers
		// multiplex and use only a few.
		MaxIdleConns:          2048,
		MaxIdleConnsPerHost:   1024,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Minute,
		DisableCompression:    true,
	}
	return &Client{HTTP: &http.Client{Transport: tr}, Registry: reg}
}

// retryable statuses move on to the next connection before the first byte.
func retryable(status int) bool {
	switch status {
	case 401, 403, 429, 500, 502, 503, 504, 529:
		return true
	}
	return false
}

// Do sends the call to the first connection in the pool that answers,
// trying the next one on a retryable failure before any byte reaches the
// client. It returns the response, the connection that served it, and the
// number of attempts.
func (c *Client) Do(ctx context.Context, pool []*Connection, call Call) (*http.Response, *Connection, int, error) {
	if len(pool) == 0 {
		return nil, nil, 0, ErrNoConnection
	}
	order := c.Registry.Order(pool, call.Conversation)
	var lastResp *http.Response
	var lastConn *Connection
	var lastErr error
	attempts := 0
	for i, conn := range order {
		attempts++
		url := conn.BaseURL + call.Path
		if call.Query != "" {
			url += "?" + call.Query
		}
		req, err := http.NewRequestWithContext(ctx, call.Method, url, bytes.NewReader(call.Body))
		if err != nil {
			return nil, nil, attempts, err
		}
		for k, vs := range call.Header {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		if call.Body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		conn.authorize(req.Header)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, conn, attempts, ctx.Err()
			}
			conn.record(0, err)
			lastErr, lastConn = err, conn
			continue
		}
		conn.record(resp.StatusCode, nil)
		if retryable(resp.StatusCode) && i < len(order)-1 {
			if lastResp != nil {
				lastResp.Body.Close()
			}
			io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			lastResp, lastConn = nil, conn
			continue
		}
		if lastResp != nil {
			lastResp.Body.Close()
		}
		if resp.StatusCode < 400 {
			c.Registry.Pin(call.Conversation, conn.Name)
		}
		return resp, conn, attempts, nil
	}
	if lastResp != nil {
		return lastResp, lastConn, attempts, nil
	}
	return nil, lastConn, attempts, fmt.Errorf("every connection failed; last error: %w", lastErr)
}

// affinityMap is a bounded map from conversation to connection name.
type affinityMap struct {
	mu   sync.Mutex
	max  int
	m    map[string]string
	keys []string
}

func newAffinityMap(max int) *affinityMap {
	return &affinityMap{max: max, m: map[string]string{}}
}

func (a *affinityMap) get(k string) string {
	if k == "" {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.m[k]
}

func (a *affinityMap) set(k, v string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.m[k]; !ok {
		a.keys = append(a.keys, k)
		if len(a.keys) > a.max {
			delete(a.m, a.keys[0])
			a.keys = a.keys[1:]
		}
	}
	a.m[k] = v
}
