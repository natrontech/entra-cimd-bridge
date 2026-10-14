package upstream

import (
	"errors"
	"net/http"
	"strings"
)

// maxDescriptionLength keeps relayed error descriptions to the one useful line
const maxDescriptionLength = 300

// TokenError turns the error of a token request into what the bridge answers the client with
// The client only ever learns about its own grant, while problems with the bridge's own app registration become a server error
func TokenError(err error) (status int, code, description string) {
	e, ok := errors.AsType[*Error](err)
	if !ok {
		return http.StatusServiceUnavailable, "temporarily_unavailable", "The identity provider can't be reached, try again later."
	}
	switch e.Code {
	case "invalid_grant", "interaction_required", "consent_required", "login_required":
		// Whatever the IdP calls it, the client can't use this grant anymore and has to send the person through authorization again
		return http.StatusBadRequest, "invalid_grant", firstLine(e.Description)
	case "invalid_scope", "invalid_request":
		return http.StatusBadRequest, e.Code, firstLine(e.Description)
	case "temporarily_unavailable":
		return http.StatusServiceUnavailable, e.Code, firstLine(e.Description)
	default:
		// invalid_client, unauthorized_client and the like are about the bridge's app registration, not the client's request
		return http.StatusInternalServerError, "server_error", "The identity provider rejected the bridge's own credentials for this MCP server."
	}
}

// AuthorizeError turns an error the IdP redirected back with into the error the client gets
func AuthorizeError(code, description string) (string, string) {
	switch code {
	case "access_denied", "temporarily_unavailable":
		return code, firstLine(description)
	case "login_required", "interaction_required", "consent_required", "account_selection_required":
		return "access_denied", firstLine(description)
	default:
		// Anything else, like an unknown redirect URI, comes from how the bridge's app is registered, which the client can't fix
		return "server_error", firstLine(code + ": " + description)
	}
}

// firstLine keeps the first line of an IdP's description, since Entra appends trace and correlation IDs on further lines
func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	s = strings.TrimSpace(s)
	if len(s) > maxDescriptionLength {
		s = strings.ToValidUTF8(s[:maxDescriptionLength], "")
	}
	return s
}
