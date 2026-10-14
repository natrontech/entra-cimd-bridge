package cimd

import (
	"fmt"
	"strings"
)

// Policy decides which hosts may serve the metadata documents of clients the bridge accepts
// An entry is a host name, "*.example.com" for its subdomains, or "*" for any host
type Policy struct {
	patterns []string
}

// NewPolicy validates the host patterns of a policy
func NewPolicy(patterns []string) (Policy, error) {
	if len(patterns) == 0 {
		return Policy{}, fmt.Errorf("at least one client metadata host is required, or \"*\" for any")
	}
	p := Policy{}
	for _, raw := range patterns {
		pattern := strings.ToLower(strings.TrimSpace(raw))
		rest := strings.TrimPrefix(pattern, "*.")
		if pattern != "*" && (rest == "" || strings.ContainsAny(rest, "*/:@ ")) {
			return Policy{}, fmt.Errorf("client metadata host %q must be a host name, *.domain or *", raw)
		}
		p.patterns = append(p.patterns, pattern)
	}
	return p, nil
}

// Allows reports whether host may serve client metadata documents
func (p Policy) Allows(host string) bool {
	host = strings.ToLower(host)
	for _, pattern := range p.patterns {
		switch {
		case pattern == "*", pattern == host:
			return true
		case strings.HasPrefix(pattern, "*.") && strings.HasSuffix(host, pattern[1:]):
			return true
		}
	}
	return false
}
