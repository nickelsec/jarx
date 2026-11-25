package ui

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nickelsec/jarx/internal/netguard"
)

const port = 49152

// app is what the guard protects in these tests: it answers 200 to any
// method, so a refusal can only come from the guard.
func app() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "dashboard")
	})
}

func guarded(t *testing.T) (http.Handler, string) {
	t.Helper()
	token := NewToken()
	return Protect(app(), token, port), token
}

// answer is what the guard sent back.
type answer struct {
	StatusCode int
	Header     http.Header
	Body       string
	cookies    []*http.Cookie
}

func (a answer) Cookies() []*http.Cookie { return a.cookies }

// do sends one request to h as if from a browser on the dashboard's own
// address.
func do(h http.Handler, method, target string, set func(*http.Request)) answer {
	req := httptest.NewRequestWithContext(context.Background(), method, target, http.NoBody)
	req.Host = "127.0.0.1:" + strconv.Itoa(port)
	if set != nil {
		set(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return answer{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(body), cookies: resp.Cookies()}
}

// session signs in with the token and returns the cookie it trades for.
func session(t *testing.T, h http.Handler, token string) *http.Cookie {
	t.Helper()
	resp := do(h, http.MethodGet, "/?t="+token, nil)
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatalf("no %s cookie after signing in (status %d)", cookieName, resp.StatusCode)
	return nil
}

func TestListenBindsLoopbackOnly(t *testing.T) {
	l, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok || addr.IP.String() != "127.0.0.1" || addr.Port == 0 {
		t.Errorf("listening on %v, want 127.0.0.1 on a random port", l.Addr())
	}
}

func TestTokensAreLongRandomAndURLSafe(t *testing.T) {
	a, b := NewToken(), NewToken()

	if a == b || len(a) < 40 || strings.ContainsAny(a, "+/=") {
		t.Errorf("tokens %q and %q, want two different URL-safe tokens of at least 40 chars", a, b)
	}
}

func TestTheTokenTradesForACookieAndLeavesTheAddressBar(t *testing.T) {
	h, token := guarded(t)

	resp := do(h, http.MethodGet, "/project?p=2&t="+token, nil)

	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/project?p=2" {
		t.Fatalf("status %d, Location %q; want 303 to the same page without the token", resp.StatusCode, resp.Header.Get("Location"))
	}
	assertSessionCookie(t, resp.Cookies(), token)
}

// assertSessionCookie checks the session cookie is HttpOnly, SameSite=Strict
// for the whole site, and holds a value of its own, not the token.
func assertSessionCookie(t *testing.T, cookies []*http.Cookie, token string) {
	t.Helper()
	var c *http.Cookie
	for _, k := range cookies {
		if k.Name == cookieName {
			c = k
		}
	}
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatalf("cookie = %+v, want an HttpOnly, SameSite=Strict cookie for /", c)
	}
	if c.Value == token || strings.Contains(c.Value, token) {
		t.Error("the cookie holds the token, want a session value of its own")
	}
}

func TestTheTokenWorksOnce(t *testing.T) {
	h, token := guarded(t)
	session(t, h, token)

	resp := do(h, http.MethodGet, "/?t="+token, nil)

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("second use of the token = %d, want 403", resp.StatusCode)
	}
}

func TestTheCookieLetsYouIn(t *testing.T) {
	h, token := guarded(t)
	c := session(t, h, token)

	resp := do(h, http.MethodGet, "/", func(r *http.Request) { r.AddCookie(c) })

	if resp.StatusCode != http.StatusOK || resp.Body != "dashboard" {
		t.Errorf("with the cookie: %d %q, want 200 and the page", resp.StatusCode, resp.Body)
	}
}

func TestNothingWithoutTheTokenOrCookie(t *testing.T) {
	h, token := guarded(t)
	for name, set := range map[string]func(*http.Request){
		"no cookie":    nil,
		"wrong cookie": func(r *http.Request) { r.AddCookie(&http.Cookie{Name: cookieName, Value: "guess"}) }, //nolint:gosec // G124: a request cookie
		"token cookie": func(r *http.Request) { r.AddCookie(&http.Cookie{Name: cookieName, Value: token}) },   //nolint:gosec // G124: a request cookie
	} {
		resp := do(h, http.MethodGet, "/", set)

		if resp.StatusCode != http.StatusForbidden || strings.Contains(resp.Body, "dashboard") {
			t.Errorf("%s: %d %q, want 403 without the page", name, resp.StatusCode, resp.Body)
		}
	}
	if resp := do(h, http.MethodGet, "/?t=wrong", nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("a wrong token = %d, want 403", resp.StatusCode)
	}
}

func TestOnlyTheDashboardsOwnHostsGetIn(t *testing.T) {
	h, token := guarded(t)
	c := session(t, h, token)
	p := strconv.Itoa(port)
	for host, want := range map[string]int{
		"127.0.0.1:" + p:          http.StatusOK,
		"localhost:" + p:          http.StatusOK,
		"LOCALHOST:" + p:          http.StatusOK,
		"evil.example:" + p:       http.StatusForbidden, // DNS rebinding
		"127.0.0.1:1":             http.StatusForbidden,
		"127.0.0.1":               http.StatusForbidden,
		"[::1]:" + p:              http.StatusForbidden,
		"localhost.evil.com:" + p: http.StatusForbidden,
	} {
		resp := do(h, http.MethodGet, "/", func(r *http.Request) { r.Host = host; r.AddCookie(c) })

		if resp.StatusCode != want {
			t.Errorf("Host %q = %d, want %d", host, resp.StatusCode, want)
		}
	}
}

func TestAWrongHostCantSignIn(t *testing.T) {
	h, token := guarded(t)

	resp := do(h, http.MethodGet, "/?t="+token, func(r *http.Request) { r.Host = "evil.example:" + strconv.Itoa(port) })

	if resp.StatusCode != http.StatusForbidden || len(resp.Cookies()) != 0 {
		t.Fatalf("sign-in from a wrong host = %d with %d cookies, want 403 and none", resp.StatusCode, len(resp.Cookies()))
	}
	session(t, h, token) // and the token still works from the right host
}

func TestCrossOriginWritesAreRefused(t *testing.T) {
	h, token := guarded(t)
	c := session(t, h, token)
	origin := "http://127.0.0.1:" + strconv.Itoa(port)
	for name, tc := range map[string]struct {
		set  func(*http.Request)
		want int
	}{
		"same origin":       {func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") }, http.StatusOK},
		"same origin, old":  {func(r *http.Request) { r.Header.Set("Origin", origin) }, http.StatusOK},
		"cross site":        {func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, http.StatusForbidden},
		"another origin":    {func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, http.StatusForbidden},
		"same site, sister": {func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }, http.StatusForbidden},
	} {
		resp := do(h, http.MethodPost, "/repos", func(r *http.Request) { r.AddCookie(c); tc.set(r) })

		if resp.StatusCode != tc.want {
			t.Errorf("%s: POST = %d, want %d", name, resp.StatusCode, tc.want)
		}
	}
}

func TestWritesNeedTheCookieToo(t *testing.T) {
	h, _ := guarded(t)

	resp := do(h, http.MethodPost, "/repos", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") })

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST without the cookie = %d, want 403", resp.StatusCode)
	}
}

func TestSecurityHeadersOnEveryAnswer(t *testing.T) {
	h, token := guarded(t)
	c := session(t, h, token)
	answers := map[string]answer{
		"page":     do(h, http.MethodGet, "/", func(r *http.Request) { r.AddCookie(c) }),
		"refusal":  do(h, http.MethodGet, "/", nil),
		"bad host": do(h, http.MethodGet, "/", func(r *http.Request) { r.Host = "evil.example" }),
	}
	h2, token2 := guarded(t)
	answers["sign in"] = do(h2, http.MethodGet, "/?t="+token2, nil)

	for name, resp := range answers {
		csp := resp.Header.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP %q lacks %q", name, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s: CSP %q allows inline or eval", name, csp)
		}
		for header, want := range map[string]string{
			"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
			"Cache-Control": "no-store", "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin",
		} {
			if got := resp.Header.Get(header); got != want {
				t.Errorf("%s: %s = %q, want %q", name, header, got, want)
			}
		}
	}
}

func TestNoCORSHeadersEver(t *testing.T) {
	h, token := guarded(t)
	c := session(t, h, token)

	for _, method := range []string{http.MethodGet, http.MethodOptions} {
		resp := do(h, method, "/", func(r *http.Request) {
			r.AddCookie(c)
			r.Header.Set("Origin", "https://evil.example")
			r.Header.Set("Access-Control-Request-Method", "POST")
		})

		for k := range resp.Header {
			if strings.HasPrefix(k, "Access-Control-") {
				t.Errorf("%s answer has %s", method, k)
			}
		}
	}
}

func TestTheServerHasTimeoutsAndCaps(t *testing.T) {
	s := NewServer(app())

	if s.ReadHeaderTimeout <= 0 || s.ReadTimeout <= 0 || s.WriteTimeout <= 0 || s.IdleTimeout <= 0 || s.MaxHeaderBytes <= 0 || s.MaxHeaderBytes > 1<<20 {
		t.Errorf("server limits = header %v, read %v, write %v, idle %v, header bytes %d; want all set", s.ReadHeaderTimeout, s.ReadTimeout, s.WriteTimeout, s.IdleTimeout, s.MaxHeaderBytes)
	}
	if s.ReadHeaderTimeout > 30*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want a short one", s.ReadHeaderTimeout)
	}
}

func TestARealServerServesThroughTheGuard(t *testing.T) {
	l, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().(*net.TCPAddr) //nolint:forcetypeassert // Listen returns a TCP listener
	s := NewServer(Protect(app(), NewToken(), addr.Port))
	go func() { _ = s.Serve(l) }()
	t.Cleanup(func() { _ = s.Close() })

	// netguard is the only HTTP client jarx has, and it follows no
	// redirects, so this checks the wiring: the real server answers through
	// the guard, which refuses a request without the cookie.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(addr.Port)+"/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := netguard.New().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("Content-Security-Policy") == "" {
		t.Errorf("real server = %d with CSP %q, want the guard's 403", resp.StatusCode, resp.Header.Get("Content-Security-Policy"))
	}
}
