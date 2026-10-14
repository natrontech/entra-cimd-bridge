package server

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"gitlab.com/natrontech/applications/entra-cimd-bridge/internal/signing"
	"gitlab.com/natrontech/applications/entra-cimd-bridge/internal/upstream"
)

// handleCallback passes the IdP's code on to the client, unchanged, at the redirect URI the signed state names
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Without a genuine state the bridge can't know where the code may go, and an unsigned one would let anyone pick the destination
	var st flowState
	if err := s.ring.Verify(purposeState, q.Get("state"), &st); err != nil {
		s.metrics.inc("bridge_callbacks_total", "outcome", "invalid_state")
		s.log.WarnContext(r.Context(), "Rejected a callback without a valid state", slog.Any("error", err))
		message := "This sign-in can't be completed. Start it again from your app."
		if errors.Is(err, signing.ErrExpired) {
			message = "This sign-in took too long. Start it again from your app."
		}
		s.errorPage(w, http.StatusBadRequest, "Sign-in failed", message)
		return
	}

	if idpError := q.Get("error"); idpError != "" {
		code, description := upstream.AuthorizeError(idpError, q.Get("error_description"))
		s.metrics.inc("bridge_callbacks_total", "outcome", "error")
		s.log.InfoContext(r.Context(), "The IdP returned an error",
			slog.String("client_id", st.ClientID),
			slog.String("resource", st.Resource),
			slog.String("error", idpError),
			slog.String("error_description", q.Get("error_description")),
		)
		s.redirectError(w, r, st.RedirectURI, st.State, code, description, http.StatusFound)
		return
	}
	code := q.Get("code")
	if code == "" {
		s.metrics.inc("bridge_callbacks_total", "outcome", "error")
		s.redirectError(w, r, st.RedirectURI, st.State, "server_error", "The identity provider returned no code.", http.StatusFound)
		return
	}
	s.metrics.inc("bridge_callbacks_total", "outcome", "code")
	s.redirectToClient(w, r, st.RedirectURI, url.Values{"code": {code}, "state": {st.State}}, http.StatusFound)
}
