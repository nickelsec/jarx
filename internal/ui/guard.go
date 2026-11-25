// Package ui is jarx's dashboard: a server on 127.0.0.1 only, behind a
// guard that every request passes, then the pages.
package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// cookieName is the dashboard's session cookie.
const cookieName = "jarx_session"

// csp lets the page load its own script, style, fonts and images and
// nothing else: no inline script or style, no framing, no other origins.
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; " +
	"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// NewToken is a random one-time token for the URL jarx ui prints.
func NewToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// guard is what every request passes before the dashboard sees it.
type guard struct {
	app     http.Handler
	token   string
	session string
	used    atomic.Bool
	hosts   [2]string
	cop     *http.CrossOriginProtection
}

// Protect puts app behind the guard for a dashboard on port:
//
//   - every answer carries a strict CSP and the other security headers,
//     and never a CORS header
//   - the Host has to be 127.0.0.1:port or localhost:port, which stops DNS
//     rebinding
//   - the token from the printed URL works once: it's traded for an
//     HttpOnly, SameSite=Strict cookie and a 303 to the same page without
//     it, so it leaves the address bar and the history
//   - every other request needs that cookie
//   - writes also pass Go's cross-origin check (Sec-Fetch-Site and Origin)
func Protect(app http.Handler, token string, port int) http.Handler {
	p := strconv.Itoa(port)
	return &guard{
		app: app, token: token, session: NewToken(),
		hosts: [2]string{"127.0.0.1:" + p, "localhost:" + p},
		cop:   http.NewCrossOriginProtection(),
	}
}

func (g *guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	secure(w.Header())
	switch {
	case !g.hostOK(r.Host):
		refuse(w, "this dashboard only answers at 127.0.0.1 or localhost on its own port")
	case r.URL.Query().Has("t"):
		g.signIn(w, r)
	case !g.signedIn(r):
		refuse(w, "open the link jarx ui printed in your terminal")
	case !safeMethod(r.Method) && g.cop.Check(r) != nil:
		refuse(w, "a write has to come from the dashboard itself")
	default:
		g.app.ServeHTTP(w, r)
	}
}

// secure sets the headers every answer carries.
func secure(h http.Header) {
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
}

func (g *guard) hostOK(host string) bool {
	host = strings.ToLower(host)
	return host == g.hosts[0] || host == g.hosts[1]
}

// signIn trades the token for the session cookie, once.
func (g *guard) signIn(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("t")), []byte(g.token)) != 1 || !g.used.CompareAndSwap(false, true) {
		refuse(w, "that link was already used, or isn't this dashboard's; run jarx ui again for a new one")
		return
	}
	// Not Secure: the dashboard is plain http on 127.0.0.1, and some
	// browsers drop a Secure cookie there. HttpOnly and SameSite=Strict
	// keep it from scripts and other sites.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: see above
		Name: cookieName, Value: g.session, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	q.Del("t")
	to := url.URL{Path: r.URL.Path, RawQuery: q.Encode()}
	if to.Path == "" {
		to.Path = "/"
	}
	http.Redirect(w, r, to.String(), http.StatusSeeOther)
}

func (g *guard) signedIn(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(g.session)) == 1
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func refuse(w http.ResponseWriter, why string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, "jarx: "+why+"\n")
}

// Listen listens on 127.0.0.1 only, on port, or a random port for 0.
func Listen(port int) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(context.Background(), "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))) //nolint:wrapcheck // the address is in the error
}

// Server limits: a slow client can't hold a connection, and headers are
// small.
const (
	headerTimeout  = 5 * time.Second
	readTimeout    = 30 * time.Second
	writeTimeout   = 2 * time.Minute // a rescan answers after the scan
	idleTimeout    = 2 * time.Minute
	maxHeaderBytes = 64 << 10
)

// NewServer serves h with timeouts and a header cap.
func NewServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: headerTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}
