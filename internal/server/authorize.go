package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"gitlab.com/natrontech/applications/entra-cimd-bridge/internal/cimd"
)

const (
	// csrfCookie binds a consent form to the browser it was shown in
	csrfCookie = "bridge-csrf"
	// consentCookiePrefix starts the name of the cookie that remembers one approval, followed by a hash of the client and the MCP server
	consentCookiePrefix = "bridge-consent-"
)

// pkceValue is a code challenge or verifier as RFC 7636 defines them
var pkceValue = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// authRequest is an authorization request the bridge accepted
type authRequest struct {
	ClientID      string `json:"c"`
	RedirectURI   string `json:"r"`
	State         string `json:"s,omitempty"`
	CodeChallenge string `json:"cc"`
	Resource      string `json:"res"`
}

// consentForm is the request as the consent page posts it back, bound to the browser it was shown in
type consentForm struct {
	authRequest
	Browser string `json:"b"`
}

// flowState is what the bridge needs back at the callback, which the IdP carries in its state parameter
type flowState struct {
	ClientID    string `json:"c"`
	RedirectURI string `json:"r"`
	State       string `json:"s,omitempty"`
	Resource    string `json:"res"`
}

// consentGrant is a remembered approval of one client for one MCP server
type consentGrant struct {
	ClientID string `json:"c"`
	Resource string `json:"r"`
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Until the client and its redirect URI check out, errors go to the person on a page, since a redirect could lead anywhere
	if len(q["client_id"]) > 1 || len(q["redirect_uri"]) > 1 {
		s.rejectClient(w, r, "", "The request repeats client_id or redirect_uri.", nil)
		return
	}
	clientID, redirectURI := q.Get("client_id"), q.Get("redirect_uri")
	doc, err := s.clients.Fetch(r.Context(), clientID)
	if err != nil {
		s.rejectClient(w, r, clientID, cimd.Message(err), err)
		return
	}
	if err := cimd.CheckRedirectURI(redirectURI); err != nil {
		s.rejectClient(w, r, clientID, cimd.Message(err), nil)
		return
	}
	if !doc.AllowsRedirect(redirectURI) {
		s.rejectClient(w, r, clientID, "The redirect_uri isn't registered in the client's metadata document.", nil)
		return
	}

	// From here on errors go back to the client, with its state so it can match them to its request
	state := q.Get("state")
	if code, description := checkAuthorizeParams(q); code != "" {
		s.metrics.inc("bridge_authorize_requests_total", "outcome", "invalid_request")
		s.redirectError(w, r, redirectURI, state, code, description, http.StatusFound)
		return
	}
	res, err := s.resourceFor(q["resource"])
	if err != nil {
		s.metrics.inc("bridge_authorize_requests_total", "outcome", "invalid_target")
		s.redirectError(w, r, redirectURI, state, "invalid_target", err.Error(), http.StatusFound)
		return
	}

	// The client's scope is ignored, since the bridge always requests what the MCP server's entry lists
	req := authRequest{ClientID: clientID, RedirectURI: redirectURI, State: state, CodeChallenge: q.Get("code_challenge"), Resource: res.uri}
	if s.hasConsent(r, req.ClientID, res.uri) {
		s.metrics.inc("bridge_authorize_requests_total", "outcome", "remembered")
		s.redirectToProvider(w, r, req, res, http.StatusFound)
		return
	}
	s.metrics.inc("bridge_authorize_requests_total", "outcome", "consent")
	s.showConsent(w, r, req, doc, res)
}

// checkAuthorizeParams returns the OAuth error for an authorization request the bridge can't serve, or nothing
func checkAuthorizeParams(q url.Values) (code, description string) {
	for _, name := range []string{"response_type", "state", "code_challenge", "code_challenge_method"} {
		if len(q[name]) > 1 {
			return "invalid_request", "The request repeats " + name + "."
		}
	}
	switch {
	case q.Get("response_type") != "code":
		return "unsupported_response_type", "Only the code response type is supported."
	case q.Get("code_challenge_method") != "S256":
		return "invalid_request", "PKCE with code_challenge_method S256 is required."
	case !pkceValue.MatchString(q.Get("code_challenge")):
		return "invalid_request", "The code_challenge must be 43 to 128 characters."
	case len(q.Get("state")) > maxStateLength:
		return "invalid_request", "The state is too long."
	}
	return "", ""
}

// rejectClient shows why a client can't sign in, without ever redirecting to it
func (s *Server) rejectClient(w http.ResponseWriter, r *http.Request, clientID, message string, cause error) {
	s.metrics.inc("bridge_authorize_requests_total", "outcome", "rejected_client")
	attrs := []any{slog.String("client_id", clientID), slog.String("reason", message)}
	if cause != nil && cause.Error() != message {
		attrs = append(attrs, slog.Any("error", cause))
	}
	s.log.InfoContext(r.Context(), "Rejected an authorization request", attrs...)
	s.errorPage(w, http.StatusBadRequest, "This app can't sign in here", message)
}

func (s *Server) showConsent(w http.ResponseWriter, r *http.Request, req authRequest, doc *cimd.Document, res *resource) {
	form, err := s.ring.Sign(purposeConsentForm, consentForm{authRequest: req, Browser: s.browserBinding(w, r)}, flowTTL)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	clientURL, _ := url.Parse(req.ClientID)
	redirectURL, _ := url.Parse(req.RedirectURI)
	s.renderPage(w, http.StatusOK, consentPage, "Allow "+truncate(doc.ClientName, 80)+"?", consentView{
		ClientName:   truncate(doc.ClientName, 80),
		ClientHost:   clientURL.Host,
		RedirectHost: redirectURL.Host,
		Loopback:     cimd.IsLoopbackRedirect(req.RedirectURI),
		ResourceName: res.name,
		ResourceURI:  res.uri,
		Remember:     humanDuration(s.consentTTL),
		Request:      form,
	}, []string{"'self'", origin(res.provider.AuthorizationEndpoint), origin(req.RedirectURI)})
}

func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, http.StatusBadRequest, "Request refused", "The consent form couldn't be read.")
		return
	}
	var form consentForm
	if err := s.ring.Verify(purposeConsentForm, r.PostForm.Get("request"), &form); err != nil {
		s.metrics.inc("bridge_consent_decisions_total", "decision", "invalid")
		s.errorPage(w, http.StatusBadRequest, "This page expired", "Start the sign-in again from your app.")
		return
	}

	// The form must come back to the browser it was shown in, so a page can't post one it fetched itself
	if !s.sameBrowser(r, form.Browser) {
		s.metrics.inc("bridge_consent_decisions_total", "decision", "invalid")
		s.errorPage(w, http.StatusForbidden, "Request refused", "The consent wasn't sent from the page this browser was shown. Start the sign-in again from your app.")
		return
	}
	res, ok := s.byURI[form.Resource]
	if !ok {
		s.errorPage(w, http.StatusBadRequest, "This page expired", "Start the sign-in again from your app.")
		return
	}

	if r.PostForm.Get("decision") != "allow" {
		s.metrics.inc("bridge_consent_decisions_total", "decision", "deny")
		s.redirectError(w, r, form.RedirectURI, form.State, "access_denied", "The user declined access.", http.StatusSeeOther)
		return
	}
	s.metrics.inc("bridge_consent_decisions_total", "decision", "allow")
	s.log.InfoContext(r.Context(), "Consent given", slog.String("client_id", form.ClientID), slog.String("resource", res.uri))
	s.rememberConsent(w, r, form.ClientID, res.uri)
	s.redirectToProvider(w, r, form.authRequest, res, http.StatusSeeOther)
}

// redirectToProvider sends the person to the IdP with the app of the MCP server, the client's own PKCE challenge and the bridge's signed state
func (s *Server) redirectToProvider(w http.ResponseWriter, r *http.Request, req authRequest, res *resource, status int) {
	state, err := s.ring.Sign(purposeState, flowState{ClientID: req.ClientID, RedirectURI: req.RedirectURI, State: req.State, Resource: res.uri}, flowTTL)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	http.Redirect(w, r, res.provider.AuthorizationURL(url.Values{
		"client_id":             {res.creds.ClientID},
		"response_type":         {"code"},
		"response_mode":         {"query"},
		"redirect_uri":          {s.callbackURL},
		"scope":                 {strings.Join(res.scopes, " ")},
		"state":                 {state},
		"code_challenge":        {req.CodeChallenge},
		"code_challenge_method": {"S256"},
	}), status)
}

// browserBinding returns a hash of this browser's CSRF cookie, setting the cookie first if it has none
func (s *Server) browserBinding(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(s.cookieName(csrfCookie)); err == nil && len(c.Value) >= 26 {
		return hashCookie(c.Value)
	}
	value := rand.Text()
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(csrfCookie), Value: value, Path: "/", Secure: s.secureCookies, HttpOnly: true, SameSite: http.SameSiteStrictMode}) //nolint:gosec // Secure is only off for an http issuer on localhost
	return hashCookie(value)
}

// sameBrowser reports whether the request comes with the CSRF cookie a consent form was bound to
func (s *Server) sameBrowser(r *http.Request, binding string) bool {
	c, err := r.Cookie(s.cookieName(csrfCookie))
	return err == nil && binding != "" && subtle.ConstantTimeCompare([]byte(hashCookie(c.Value)), []byte(binding)) == 1
}

func hashCookie(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// cookieName adds the __Host- prefix, which pins a cookie to the bridge's host, whenever the bridge runs on https
// Without https, as on a developer's machine, browsers like Safari refuse secure and prefixed cookies on localhost
func (s *Server) cookieName(name string) string {
	if s.secureCookies {
		return "__Host-" + name
	}
	return name
}

// consentCookieName names the cookie of one client and MCP server, so approvals of different pairs never overwrite each other
func (s *Server) consentCookieName(clientID, resource string) string {
	sum := sha256.Sum256([]byte(clientID + "\x00" + resource))
	return s.cookieName(consentCookiePrefix + hex.EncodeToString(sum[:8]))
}

func (s *Server) hasConsent(r *http.Request, clientID, resource string) bool {
	if s.consentTTL <= 0 {
		return false
	}
	c, err := r.Cookie(s.consentCookieName(clientID, resource))
	if err != nil {
		return false
	}
	var g consentGrant
	return s.ring.Verify(purposeConsent, c.Value, &g) == nil && g.ClientID == clientID && g.Resource == resource
}

// rememberConsent sets the cookie that skips the consent page for this client and MCP server until consent_ttl is up
// It is SameSite=Lax, since the client sends the person here with a top-level navigation from another site
func (s *Server) rememberConsent(w http.ResponseWriter, r *http.Request, clientID, resource string) {
	if s.consentTTL <= 0 {
		return
	}
	value, err := s.ring.Sign(purposeConsent, consentGrant{ClientID: clientID, Resource: resource}, s.consentTTL)
	if err != nil {
		s.log.ErrorContext(r.Context(), "Couldn't remember consent", slog.Any("error", err))
		return
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is only off for an http issuer on localhost
		Name:     s.consentCookieName(clientID, resource),
		Value:    value,
		Path:     "/",
		MaxAge:   int(s.consentTTL.Seconds()),
		Secure:   s.secureCookies,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// redirectError sends an OAuth error back to the client's redirect URI, with its state and the bridge as issuer
func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string, status int) {
	s.redirectToClient(w, r, redirectURI, url.Values{
		"error":             {code},
		"error_description": {cleanDescription(description)},
		"state":             {state},
	}, status)
}

// redirectToClient adds params and the bridge's issuer to the client's redirect URI, keeping any query it has
// The issuer lets the client check where the response came from (RFC 9207)
func (s *Server) redirectToClient(w http.ResponseWriter, r *http.Request, redirectURI string, params url.Values, status int) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	q := u.Query()
	for k, v := range params {
		if len(v) > 0 && v[0] != "" {
			q[k] = v
		}
	}
	q.Set("iss", s.issuer)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), status) //nolint:gosec // the redirect URI is registered in the client's metadata document, or comes from a state the bridge signed after checking that
}

// cleanDescription keeps an error description to the characters RFC 6749 allows in it
func cleanDescription(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return ' '
		}
		return r
	}, s)
}

// origin is the scheme and host of a URL, as CSP needs it
func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "'none'"
	}
	return u.Scheme + "://" + u.Host
}

func truncate(s string, n int) string {
	runes := []rune(strings.TrimSpace(s))
	if len(runes) <= n {
		return string(runes)
	}
	return string(runes[:n-1]) + "…"
}
