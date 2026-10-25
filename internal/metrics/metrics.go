// Package metrics counts what the master does and writes the counts in
// Prometheus' text format.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// Counters are counters with one label each.
type Counters struct {
	mu     sync.Mutex
	counts map[string]map[string]float64
	help   map[string]string
	label  map[string]string
}

// New makes an empty set.
func New() *Counters {
	return &Counters{counts: map[string]map[string]float64{}, help: map[string]string{}, label: map[string]string{}}
}

// Define names a counter, its help and its label ("" for none).
func (c *Counters) Define(name, help, label string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.help[name], c.label[name] = help, label
	if c.counts[name] == nil {
		c.counts[name] = map[string]float64{}
	}
}

// Add counts one for a label's value.
func (c *Counters) Add(name, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts[name] == nil {
		c.counts[name] = map[string]float64{}
	}
	c.counts[name][value]++
}

// Get returns a count (the tests').
func (c *Counters) Get(name, value string) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[name][value]
}

func escape(value string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(value)
}

// Sample is one gauge's value.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// WriteGauge writes a gauge.
func WriteGauge(w io.Writer, name, help string, samples []Sample) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	for _, s := range samples {
		fmt.Fprintf(w, "%s%s %g\n", name, labels(s.Labels), s.Value)
	}
}

func labels(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, escape(m[k])))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// Write writes every counter.
func (c *Counters) Write(w io.Writer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := make([]string, 0, len(c.counts))
	for name := range c.counts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, c.help[name], name)
		values := make([]string, 0, len(c.counts[name]))
		for v := range c.counts[name] {
			values = append(values, v)
		}
		sort.Strings(values)
		if c.label[name] == "" {
			fmt.Fprintf(w, "%s %g\n", name, c.counts[name][""])
			continue
		}
		for _, v := range values {
			fmt.Fprintf(w, "%s%s %g\n", name, labels(map[string]string{c.label[name]: v}), c.counts[name][v])
		}
	}
}
