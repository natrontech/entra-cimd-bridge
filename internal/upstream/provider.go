// Package upstream talks to the IdPs: OIDC discovery, and token requests made with the credentials of an MCP server's app registration
package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// maxResponseSize caps what the bridge reads of an IdP's token response
const maxResponseSize = 1 << 20

// Provider is an IdP the bridge sends people to and redeems codes at
type Provider struct {
	Name                  string
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string

	// basicAuth sends the app's credentials in the Authorization header rather than the form
	basicAuth bool
	client    *http.Client
}

// Credentials are an app registration's client ID and secret
type Credentials struct {
	ClientID     string
	ClientSecret string
}

// Discover loads a provider through OIDC discovery and checks that it can bind codes to a PKCE challenge with S256
func Discover(ctx context.Context, name, issuer string, client *http.Client) (*Provider, error) {
	if client == nil {
		client = http.DefaultClient
	}
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, client), issuer)
	if err != nil {
		return nil, fmt.Errorf("provider %s: discovery: %w", name, err)
	}
	var claims struct {
		CodeChallengeMethods     []string `json:"code_challenge_methods_supported"`
		TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	}
	if err := p.Claims(&claims); err != nil {
		return nil, fmt.Errorf("provider %s: discovery: %w", name, err)
	}

	// Entra supports S256 without advertising it, so only a list that leaves it out rules a provider out
	if len(claims.CodeChallengeMethods) > 0 && !slices.Contains(claims.CodeChallengeMethods, "S256") {
		return nil, fmt.Errorf("provider %s doesn't support PKCE with S256, it only lists %s", name, strings.Join(claims.CodeChallengeMethods, ", "))
	}
	endpoint := p.Endpoint()
	if endpoint.AuthURL == "" || endpoint.TokenURL == "" {
		return nil, fmt.Errorf("provider %s: discovery lists no authorization or token endpoint", name)
	}

	// Without a list, RFC 8414 makes client_secret_basic the default, while a list without either secret method rules a provider out like one without S256
	methods := claims.TokenEndpointAuthMethods
	if len(methods) > 0 && !slices.Contains(methods, "client_secret_basic") && !slices.Contains(methods, "client_secret_post") {
		return nil, fmt.Errorf("provider %s doesn't accept a client secret, it only lists %s", name, strings.Join(methods, ", "))
	}
	basic := len(methods) == 0 || (slices.Contains(methods, "client_secret_basic") && !slices.Contains(methods, "client_secret_post"))
	return &Provider{
		Name:                  name,
		Issuer:                issuer,
		AuthorizationEndpoint: endpoint.AuthURL,
		TokenEndpoint:         endpoint.TokenURL,
		basicAuth:             basic,
		client:                client,
	}, nil
}

// AuthorizationURL is the provider's authorization endpoint with params added to its query
func (p *Provider) AuthorizationURL(params url.Values) string {
	u, err := url.Parse(p.AuthorizationEndpoint)
	if err != nil {
		return p.AuthorizationEndpoint
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Token is the part of an IdP's token response the bridge relays, which leaves out the ID token
type Token struct {
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    seconds `json:"expires_in,omitempty"`
	RefreshToken string  `json:"refresh_token,omitempty"`
	Scope        string  `json:"scope,omitempty"`
}

// seconds reads expires_in both as a number and as the string some IdPs send, like Entra's v1 endpoint
type seconds int64

func (s *seconds) UnmarshalJSON(b []byte) error {
	n, err := strconv.ParseInt(strings.Trim(string(b), `"`), 10, 64)
	if err != nil {
		return fmt.Errorf("expires_in: %w", err)
	}
	*s = seconds(n)
	return nil
}

// Error is an OAuth error an IdP answered a token request with
type Error struct {
	Status      int
	Code        string
	Description string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s (%d): %s", e.Code, e.Status, e.Description)
}

// Token sends a token request to the provider with the app's credentials added
func (p *Provider) Token(ctx context.Context, creds Credentials, form url.Values) (*Token, error) {
	form.Set("client_id", creds.ClientID)
	if !p.basicAuth {
		form.Set("client_secret", creds.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.basicAuth {
		// RFC 6749 form-encodes both parts before they go into the header
		req.SetBasicAuth(url.QueryEscape(creds.ClientID), url.QueryEscape(creds.ClientSecret))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request to %s: %w", p.Name, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("token response from %s: %w", p.Name, err)
	}

	if resp.StatusCode != http.StatusOK {
		var oauthErr struct {
			Code        string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(body, &oauthErr) != nil || oauthErr.Code == "" {
			return nil, fmt.Errorf("token request to %s: status %d", p.Name, resp.StatusCode)
		}
		return nil, &Error{Status: resp.StatusCode, Code: oauthErr.Code, Description: oauthErr.Description}
	}
	var tok Token
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("token response from %s: %w", p.Name, err)
	}
	if tok.AccessToken == "" {
		return nil, errors.New("token response from " + p.Name + " has no access token")
	}
	if tok.TokenType == "" {
		tok.TokenType = "Bearer"
	}
	return &tok, nil
}
