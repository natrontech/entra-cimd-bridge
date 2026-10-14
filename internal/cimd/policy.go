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
		if !isASCII(pattern) {
			return Policy{}, fmt.Errorf("client metadata host %q must be written in ASCII, with punycode for international names", raw)
		}
		p.patterns = append(p.patterns, pattern)
	}
	return p, nil
}

// Allows reports whether host may serve client metadata documents
// Hosts that aren't ASCII are never allowed, since Unicode lowercasing can turn one into an allowed name while the connection goes to its punycode, a different domain
func (p Policy) Allows(host string) bool {
	if !isASCII(host) {
		return false
	}
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

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
