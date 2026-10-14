package server

import (
	"net/http"
	"slices"
)

// authorizationServerMetadata is the bridge's RFC 8414 metadata
type authorizationServerMetadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ClientIDMetadataDocumentSupported          bool     `json:"client_id_metadata_document_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

func (s *Server) authorizationServerMetadata() authorizationServerMetadata {
	var scopes []string
	for _, r := range s.resources {
		scopes = append(scopes, r.scopes...)
	}
	slices.Sort(scopes)
	return authorizationServerMetadata{
		Issuer:                                     s.issuer,
		AuthorizationEndpoint:                      s.issuer + "/authorize",
		TokenEndpoint:                              s.issuer + "/token",
		ScopesSupported:                            slices.Compact(scopes),
		ResponseTypesSupported:                     []string{"code"},
		ResponseModesSupported:                     []string{"query"},
		GrantTypesSupported:                        []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethodsSupported:          []string{"none"},
		CodeChallengeMethodsSupported:              []string{"S256"},
		ClientIDMetadataDocumentSupported:          true,
		AuthorizationResponseIssParameterSupported: true,
	}
}

// handleMetadata serves the metadata under both well-known names, readable from browser-based clients too
func (s *Server) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "public, max-age=300")
	h.Set("Access-Control-Allow-Origin", "*")
	_, _ = w.Write(s.metadata)
}
