package server

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

//go:embed templates
var templates embed.FS

var (
	consentPage = template.Must(template.ParseFS(templates, "templates/layout.html", "templates/consent.html"))
	errorPage   = template.Must(template.ParseFS(templates, "templates/layout.html", "templates/error.html"))

	// style is inlined, and the CSP allows exactly it by its hash, so pages need no other request and no unsafe-inline
	style     = mustRead("templates/style.css")
	styleCSS  = template.CSS(style) //nolint:gosec // the style is embedded in the binary, nobody else's input reaches it
	styleHash = func() string {
		sum := sha256.Sum256([]byte(style))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}()
)

func mustRead(name string) string {
	b, err := templates.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// page is what the layout renders around a page's content
type page struct {
	Title string
	Style template.CSS
	Data  any
}

// consentView is what the consent page shows, following the MCP spec's rules for proxies with a static upstream client
type consentView struct {
	ClientName   string
	ClientHost   string
	RedirectHost string
	// Loopback marks a redirect to this computer, where any program could pose as the client
	Loopback     bool
	ResourceName string
	ResourceURI  string
	// Remember is how long an approval is remembered, empty if it isn't
	Remember string
	Request  string
}

type errorView struct {
	Heading string
	Message string
}

// renderPage writes an HTML page whose CSP allows forms to post only to formAction, which must cover where the post redirects
func (s *Server) renderPage(w http.ResponseWriter, status int, tmpl *template.Template, title string, data any, formAction []string) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", page{Title: title, Style: styleCSS, Data: data}); err != nil {
		s.log.Error("Couldn't render a page", slog.Any("error", err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if len(formAction) == 0 {
		formAction = []string{"'none'"}
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", fmt.Sprintf("default-src 'none'; style-src %s; form-action %s; frame-ancestors 'none'; base-uri 'none'", styleHash, strings.Join(formAction, " ")))
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) errorPage(w http.ResponseWriter, status int, heading, message string) {
	s.renderPage(w, status, errorPage, heading, errorView{Heading: heading, Message: message}, nil)
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.ErrorContext(r.Context(), "Internal error", slog.Any("error", err))
	s.errorPage(w, http.StatusInternalServerError, "Something went wrong", "Start the sign-in again from your app.")
}

// humanDuration words how long consent is remembered, empty when it isn't
func humanDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d minutes", max(1, int(d.Minutes())))
	}
}
