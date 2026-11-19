// Package telemetry exposes metrics in the Prometheus text format
// (capability OB-5). Metrics carry labels such as data types and outcomes,
// never prompt or answer text.
package telemetry

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Registry holds counters, gauges, and histograms.
type Registry struct {
	mu       sync.Mutex
	counters map[string]*series
	hists    map[string]*histogram
	gauges   map[string]func() float64
	help     map[string]string
}

type series struct {
	values map[string]float64 // label string -> value
}

type histogram struct {
	bounds []float64
	counts map[string][]uint64
	sums   map[string]float64
	totals map[string]uint64
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{counters: map[string]*series{}, hists: map[string]*histogram{}, gauges: map[string]func() float64{}, help: map[string]string{}}
}

// Default is the process registry.
var Default = New()

func labels(kv []string) string {
	if len(kv) == 0 {
		return ""
	}
	parts := make([]string, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		v := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(kv[i+1])
		parts = append(parts, kv[i]+`="`+v+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// Help sets the help text of a metric.
func (r *Registry) Help(name, text string) {
	r.mu.Lock()
	r.help[name] = text
	r.mu.Unlock()
}

// Add increases a counter. kv is label name, value, name, value...
func (r *Registry) Add(name string, v float64, kv ...string) {
	l := labels(kv)
	r.mu.Lock()
	s, ok := r.counters[name]
	if !ok {
		s = &series{values: map[string]float64{}}
		r.counters[name] = s
	}
	s.values[l] += v
	r.mu.Unlock()
}

// Gauge registers a function read at scrape time.
func (r *Registry) Gauge(name string, f func() float64) {
	r.mu.Lock()
	r.gauges[name] = f
	r.mu.Unlock()
}

var latencyBounds = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120}

// Observe records a value in seconds.
func (r *Registry) Observe(name string, seconds float64, kv ...string) {
	l := labels(kv)
	r.mu.Lock()
	h, ok := r.hists[name]
	if !ok {
		h = &histogram{bounds: latencyBounds, counts: map[string][]uint64{}, sums: map[string]float64{}, totals: map[string]uint64{}}
		r.hists[name] = h
	}
	c, ok := h.counts[l]
	if !ok {
		c = make([]uint64, len(h.bounds))
		h.counts[l] = c
	}
	for i, b := range h.bounds {
		if seconds <= b {
			c[i]++
		}
	}
	h.sums[l] += seconds
	h.totals[l]++
	r.mu.Unlock()
}

// Write prints every metric in the Prometheus text format.
func (r *Registry) Write(w io.Writer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	cn := map[string]bool{}
	for k := range r.counters {
		cn[k] = true
	}
	for _, name := range names(cn) {
		r.writeHelp(w, name, "counter")
		s := r.counters[name]
		ls := make([]string, 0, len(s.values))
		for l := range s.values {
			ls = append(ls, l)
		}
		sort.Strings(ls)
		for _, l := range ls {
			fmt.Fprintf(w, "%s%s %s\n", name, l, num(s.values[l]))
		}
	}
	gn := map[string]bool{}
	for k := range r.gauges {
		gn[k] = true
	}
	for _, name := range names(gn) {
		r.writeHelp(w, name, "gauge")
		fmt.Fprintf(w, "%s %s\n", name, num(r.gauges[name]()))
	}
	hn := map[string]bool{}
	for k := range r.hists {
		hn[k] = true
	}
	for _, name := range names(hn) {
		r.writeHelp(w, name, "histogram")
		h := r.hists[name]
		ls := make([]string, 0, len(h.counts))
		for l := range h.counts {
			ls = append(ls, l)
		}
		sort.Strings(ls)
		for _, l := range ls {
			inner := strings.TrimSuffix(strings.TrimPrefix(l, "{"), "}")
			sep := ""
			if inner != "" {
				sep = ","
			}
			for i, b := range h.bounds {
				fmt.Fprintf(w, "%s_bucket{%s%sle=\"%s\"} %d\n", name, inner, sep, num(b), h.counts[l][i])
			}
			fmt.Fprintf(w, "%s_bucket{%s%sle=\"+Inf\"} %d\n", name, inner, sep, h.totals[l])
			fmt.Fprintf(w, "%s_sum%s %s\n", name, l, num(h.sums[l]))
			fmt.Fprintf(w, "%s_count%s %d\n", name, l, h.totals[l])
		}
	}
}

func (r *Registry) writeHelp(w io.Writer, name, typ string) {
	if h, ok := r.help[name]; ok {
		fmt.Fprintf(w, "# HELP %s %s\n", name, h)
	}
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
}

func num(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%g", v)
}

// Handler serves the registry.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		r.Write(w)
	})
}
