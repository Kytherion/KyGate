// Package router picks the target of a request and prices it.
//
// Every request goes to the model it names (architecture §3.7). This file
// holds the hard constraints that do not depend on cost: which connections
// can serve the requested model, and whether that target is local, so that
// local-only data never reaches an external provider. Tiers and difficulty
// are in route.go, in shadow mode (capability OP-4).
package router

import (
	_ "embed"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/Kytherion/KyGate/internal/provider"
)

// Price is US dollars per million tokens.
type Price struct {
	Input       float64 `yaml:"input" json:"input"`
	Output      float64 `yaml:"output" json:"output"`
	CachedInput float64 `yaml:"cached_input" json:"cached_input"`
	CacheWrite  float64 `yaml:"cache_write" json:"cache_write"`
}

// Model is one catalog record. Policies and the router read the catalog;
// nothing else names a model.
type Model struct {
	ID      string `yaml:"id" json:"id"`
	Family  string `yaml:"family" json:"family"`
	Tier    string `yaml:"tier" json:"tier"`
	Kind    string `yaml:"kind" json:"kind,omitempty"` // chat (default) | embedding
	Context int    `yaml:"context" json:"context,omitempty"`
	Price   Price  `yaml:"price" json:"price"`
}

// Catalog is the model catalog.
type Catalog struct {
	mu      sync.RWMutex
	models  []Model // sorted by descending id length, for longest-prefix match
	ordered []Model // in file order (newest first): ties in price keep it
}

//go:embed catalog.yaml
var builtin []byte

// LoadCatalog reads the built-in catalog and, if override is not empty, a
// file whose entries extend or replace built-in ones by id.
func LoadCatalog(override string) (*Catalog, error) {
	models, err := parseCatalog(builtin)
	if err != nil {
		return nil, fmt.Errorf("built-in catalog: %w", err)
	}
	if override != "" {
		data, err := os.ReadFile(override)
		if err != nil {
			return nil, fmt.Errorf("catalog %s: %w", override, err)
		}
		extra, err := parseCatalog(data)
		if err != nil {
			return nil, fmt.Errorf("catalog %s: %w", override, err)
		}
		byID := map[string]int{}
		for i, m := range models {
			byID[m.ID] = i
		}
		for _, m := range extra {
			if i, ok := byID[m.ID]; ok {
				models[i] = m
			} else {
				models = append(models, m)
			}
		}
	}
	ordered := append([]Model(nil), models...)
	sort.SliceStable(models, func(i, j int) bool { return len(models[i].ID) > len(models[j].ID) })
	return &Catalog{models: models, ordered: ordered}, nil
}

func parseCatalog(data []byte) ([]Model, error) {
	var f struct {
		Models []Model `yaml:"models"`
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	for _, m := range f.Models {
		if m.ID == "" {
			return nil, fmt.Errorf("a model has no id")
		}
		if m.Family != "openai" && m.Family != "anthropic" {
			return nil, fmt.Errorf("model %s: family must be openai or anthropic", m.ID)
		}
		if m.Kind != "" && m.Kind != "chat" && m.Kind != "embedding" {
			return nil, fmt.Errorf("model %s: kind must be chat or embedding", m.ID)
		}
	}
	return f.Models, nil
}

// Lookup returns the record that prices a model name, or nil.
func (c *Catalog) Lookup(model string) *Model {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.models {
		if strings.HasPrefix(model, c.models[i].ID) {
			m := c.models[i]
			return &m
		}
	}
	return nil
}

// InOrder returns every catalog record in file order.
func (c *Catalog) InOrder() []Model {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]Model(nil), c.ordered...)
}

// Models returns every catalog record of one family.
func (c *Catalog) Models(family string) []Model {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []Model
	for _, m := range c.models {
		if m.Family == family {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Usage is token usage normalized across providers. Input excludes cached
// and cache-write tokens.
type Usage struct {
	Input       int64 `json:"input"`
	CachedInput int64 `json:"cached_input"`
	CacheWrite  int64 `json:"cache_write"`
	Output      int64 `json:"output"`
}

// Cost prices usage. priced is false for a model the catalog does not know.
// Local models cost nothing per token.
func (c *Catalog) Cost(model, hosting string, u Usage) (usd float64, priced bool) {
	if hosting == "local" {
		return 0, true
	}
	m := c.Lookup(model)
	if m == nil {
		return 0, false
	}
	p := m.Price
	cached := p.CachedInput
	if cached == 0 {
		cached = p.Input
	}
	write := p.CacheWrite
	if write == 0 {
		write = p.Input
	}
	usd = (float64(u.Input)*p.Input + float64(u.CachedInput)*cached + float64(u.CacheWrite)*write + float64(u.Output)*p.Output) / 1e6
	return usd, true
}

// Target is where a request goes.
type Target struct {
	Pool          []*provider.Connection
	Provider      string // openai | anthropic | local
	Hosting       string // local | external
	UpstreamModel string // the model name to send, without a connection prefix
}

// Resolve finds the target for a request of one API family naming a model.
//
// Anthropic-family requests go to Anthropic connections. OpenAI-family
// requests go to the local server that offers the model, or that is named as a
// prefix ("local-ollama/llama3.2"), and to OpenAI otherwise. Translation
// between API families is not supported yet.
func Resolve(reg *provider.Registry, family, model string) (Target, error) {
	if family == "anthropic" {
		pool := reg.ByProvider(provider.Anthropic)
		if len(pool) == 0 {
			return Target{}, fmt.Errorf("no Anthropic key is configured: set ANTHROPIC_API_KEY, or run 'kygate provider add'")
		}
		return Target{Pool: pool, Provider: provider.Anthropic, Hosting: "external", UpstreamModel: model}, nil
	}
	locals := reg.ByProvider(provider.Local)
	if i := strings.IndexByte(model, '/'); i > 0 {
		for _, c := range locals {
			if c.Name == model[:i] {
				return Target{Pool: []*provider.Connection{c}, Provider: provider.Local, Hosting: "local", UpstreamModel: model[i+1:]}, nil
			}
		}
	}
	var serving []*provider.Connection
	for _, c := range locals {
		for _, m := range c.Models() {
			if m == model {
				serving = append(serving, c)
				break
			}
		}
	}
	if len(serving) > 0 {
		return Target{Pool: serving, Provider: provider.Local, Hosting: "local", UpstreamModel: model}, nil
	}
	pool := reg.ByProvider(provider.OpenAI)
	if len(pool) == 0 {
		if len(locals) > 0 {
			return Target{}, fmt.Errorf("model %q is not offered by any local model server, and no OpenAI key is configured", model)
		}
		return Target{}, fmt.Errorf("no OpenAI key is configured: set OPENAI_API_KEY, or run 'kygate provider add'")
	}
	return Target{Pool: pool, Provider: provider.OpenAI, Hosting: "external", UpstreamModel: model}, nil
}
