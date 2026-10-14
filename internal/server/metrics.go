package server

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
)

// metricHelp describes every counter the bridge exports, which are the only names inc accepts
var metricHelp = map[string]string{
	"bridge_authorize_requests_total": "Authorization requests by outcome: consent shown, consent remembered, or why they were refused.",
	"bridge_consent_decisions_total":  "Answers on the consent page.",
	"bridge_callbacks_total":          "Returns from the IdP by outcome.",
	"bridge_token_requests_total":     "Token requests by grant type and outcome, which is ok or the OAuth error returned.",
	"bridge_client_lookups_total":     "Client metadata lookups by outcome: cached, fetched or rejected.",
}

// metrics is a minimal registry of labelled counters in the Prometheus text format
// Label values only ever come from fixed sets, so the number of series stays small
type metrics struct {
	mu     sync.Mutex
	series map[string]map[string]float64
}

func newMetrics() *metrics {
	m := &metrics{series: map[string]map[string]float64{}}
	for name := range metricHelp {
		m.series[name] = map[string]float64{}
	}
	return m
}

// inc adds one to the counter name with labels given as name, value pairs
func (m *metrics) inc(name string, labels ...string) {
	var pairs []string
	for i := 0; i+1 < len(labels); i += 2 {
		pairs = append(pairs, fmt.Sprintf("%s=%q", labels[i], labels[i+1]))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.series[name]; ok {
		s["{"+strings.Join(pairs, ",")+"}"]++
	}
}

func (m *metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder
	for _, name := range slices.Sorted(maps.Keys(m.series)) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", name, metricHelp[name], name)
		for _, labels := range slices.Sorted(maps.Keys(m.series[name])) {
			fmt.Fprintf(&b, "%s%s %g\n", name, strings.TrimSuffix(labels, "{}"), m.series[name][labels])
		}
	}
	_, _ = w.Write([]byte(b.String()))
}
