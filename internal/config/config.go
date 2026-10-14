// Package config loads the bridge's YAML configuration, with secrets taken from the environment
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"gitlab.com/natrontech/applications/entra-cimd-bridge/internal/cimd"
	"gitlab.com/natrontech/applications/entra-cimd-bridge/internal/signing"
)

// Config is the whole configuration of a bridge
type Config struct {
	// Issuer is the bridge's own URL, which MCP servers list as their authorization server
	Issuer string `yaml:"issuer"`
	// Listen is the address of the OAuth endpoints, :8080 by default
	Listen string `yaml:"listen"`
	// MetricsListen is the address of /metrics, :9090 by default, kept apart so the metrics never face the internet
	MetricsListen string `yaml:"metrics_listen"`
	// SigningKeys sign the state and the consent cookie, where the first signs and all verify
	SigningKeys []string `yaml:"signing_keys"`
	// Providers are the IdPs, by the name resources refer to them with
	Providers map[string]Provider `yaml:"providers"`
	Clients   Clients             `yaml:"clients"`
	// ConsentTTL is how long an approval is remembered per client and MCP server, where 0 asks every time
	ConsentTTL time.Duration `yaml:"consent_ttl"`
	Resources  []Resource    `yaml:"resources"`
}

// Provider is an OpenID provider, found through OIDC discovery
type Provider struct {
	Issuer string `yaml:"issuer"`
}

// Clients is the trust policy for MCP clients
type Clients struct {
	// CIMDHosts are the hosts client metadata documents may live on: host names, *.domain, or * for any
	CIMDHosts []string `yaml:"cimd_hosts"`
}

// Resource is an MCP server, with the IdP app registration the bridge uses for it
type Resource struct {
	// URI is the MCP server's canonical URI, which clients send as resource
	URI string `yaml:"uri"`
	// Name is shown on the consent page
	Name     string `yaml:"name"`
	Provider string `yaml:"provider"`
	// ClientID and ClientSecret are the app registration's credentials, which no other resource may share
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	// Scopes are requested from the IdP whatever scope the client asked for
	Scopes []string `yaml:"scopes"`
}

// Load reads, expands and validates the configuration at path
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the operator names the file with --config
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Parse expands and validates a configuration
func Parse(raw []byte) (*Config, error) {
	// Variables are expanded in the parsed values, so a secret full of YAML syntax can't change the document's structure
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := expandEnv(&doc); err != nil {
		return nil, err
	}
	expanded, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, err
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.MetricsListen == "" {
		cfg.MetricsListen = ":9090"
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

var envReference = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces ${NAME} in every scalar value with the variable's value, where an unset variable is an error rather than an empty secret
func expandEnv(node *yaml.Node) error {
	var missing []string
	var walk func(n *yaml.Node, isKey bool)
	walk = func(n *yaml.Node, isKey bool) {
		switch n.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, c := range n.Content {
				walk(c, false)
			}
		case yaml.MappingNode:
			for i, c := range n.Content {
				walk(c, i%2 == 0)
			}
		case yaml.ScalarNode:
			if isKey || !envReference.MatchString(n.Value) {
				return
			}
			n.Value = envReference.ReplaceAllStringFunc(n.Value, func(ref string) string {
				name := envReference.FindStringSubmatch(ref)[1]
				value, ok := os.LookupEnv(name)
				if !ok {
					missing = append(missing, name)
				}
				return value
			})
			// The value is a string whatever it looks like, so a numeric secret isn't turned into a number
			n.Tag = "!!str"
			n.Style = yaml.DoubleQuotedStyle
		}
	}
	walk(node, false)
	if len(missing) > 0 {
		return fmt.Errorf("config refers to unset environment variables: %s", strings.Join(missing, ", "))
	}
	return nil
}

// Validate checks everything that can be checked without contacting the IdPs
func (c *Config) Validate() error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if err := checkIssuer(c.Issuer); err != nil {
		fail("issuer: %w", err)
	}
	if _, err := signing.NewRing(c.SigningKeys); err != nil {
		fail("signing_keys: %w", err)
	}
	if len(c.Providers) == 0 {
		fail("providers: at least one is required")
	}
	for name, p := range c.Providers {
		if u, err := url.Parse(p.Issuer); err != nil || u.Scheme != "https" || u.Host == "" {
			fail("providers.%s.issuer: must be an https URL", name)
		}
	}
	if _, err := cimd.NewPolicy(c.Clients.CIMDHosts); err != nil {
		fail("clients.cimd_hosts: %w", err)
	}
	if c.ConsentTTL < 0 {
		fail("consent_ttl: must not be negative")
	}

	if len(c.Resources) == 0 {
		fail("resources: at least one is required")
	}
	uris := map[string]bool{}
	clientIDs := map[string]string{}
	for i, r := range c.Resources {
		at := fmt.Sprintf("resources[%d]", i)
		if err := CheckResourceURI(r.URI); err != nil {
			fail("%s.uri: %w", at, err)
		}
		if uris[r.URI] {
			fail("%s.uri: %s is listed twice", at, r.URI)
		}
		uris[r.URI] = true
		if strings.TrimSpace(r.Name) == "" {
			fail("%s.name: is required, it is shown on the consent page", at)
		}
		if _, ok := c.Providers[r.Provider]; !ok {
			fail("%s.provider: %q isn't one of the providers", at, r.Provider)
		}
		if r.ClientID == "" || r.ClientSecret == "" {
			fail("%s: client_id and client_secret are required", at)
		}
		if other, ok := clientIDs[r.ClientID]; ok && r.ClientID != "" {
			// A shared app would let a code or refresh token issued for one MCP server be redeemed for the other
			fail("%s.client_id: already used by %s, every MCP server needs its own app registration so its codes and refresh tokens can't be redeemed for another", at, other)
		}
		clientIDs[r.ClientID] = r.URI
		if len(r.Scopes) == 0 {
			fail("%s.scopes: at least one is required", at)
		}
	}
	return errors.Join(errs...)
}

// checkIssuer requires an https origin without a path, since the bridge serves its metadata and endpoints at the root
// Plain http is only allowed on a loopback host, for running the bridge on a developer's machine
func checkIssuer(issuer string) error {
	u, err := url.Parse(issuer)
	switch {
	case err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !isLoopbackHost(u.Hostname()))):
		return errors.New("must be an https URL, or http on localhost, 127.0.0.1 or [::1]")
	case u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil:
		return errors.New("must be just scheme and host, like https://mcp-auth.example.com, without a path or trailing slash")
	case strings.ToLower(u.Host) != u.Host:
		return errors.New("must have a lowercase host")
	}
	return nil
}

// CheckResourceURI requires an MCP server's canonical URI: https (or http on localhost), lowercase scheme and host, no query, fragment or trailing slash
func CheckResourceURI(uri string) error {
	u, err := url.Parse(uri)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return errors.New("must be an absolute URL")
	}
	switch {
	case u.Scheme != "https" && (u.Scheme != "http" || !isLoopbackHost(u.Hostname())):
		return errors.New("must use https")
	case u.RawQuery != "" || u.Fragment != "" || u.User != nil || strings.ContainsAny(uri, "?#"):
		return errors.New("must not have a query, fragment or user info")
	case strings.HasSuffix(u.Path, "/"):
		return errors.New("must not end with a slash")
	case u.String() != uri || strings.ToLower(u.Host) != u.Host:
		return fmt.Errorf("must be in canonical form, with a lowercase host: %s", strings.ToLower(u.Scheme)+"://"+strings.ToLower(u.Host)+u.EscapedPath())
	}
	return nil
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
