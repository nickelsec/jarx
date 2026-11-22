package netguard

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// get sends a GET and returns the body, which is closed when the test ends.
func get(t *testing.T, c *Client, url string) (io.Reader, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp.Body, nil
}

// rootsOf returns the CA pool that trusts a TLS test server.
func rootsOf(t *testing.T, srv *httptest.Server) *x509.CertPool {
	t.Helper()
	tr, ok := srv.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("test server client has no *http.Transport")
	}
	return tr.TLSClientConfig.RootCAs
}

func flush(w http.ResponseWriter) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// newTestClient is New with both test safety nets on: a fake DNS server that
// answers 127.0.0.1 for every name, so no test ever sends a real lookup, and
// withTestSafety, so a broken policy fails its test instead of connecting
// anywhere real. Later options win, so a test can bring its own resolver.
func newTestClient(t *testing.T, opts ...option) *Client {
	t.Helper()
	dns := startFakeDNS(t, "127.0.0.1")
	return New(append([]option{withResolver(dns.resolver()), withTestSafety()}, opts...)...)
}

func TestHTTPSToALocalServerWorks(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	defer srv.Close()
	c := newTestClient(t, withRootCAs(rootsOf(t, srv)))

	body, err := get(t, c, srv.URL)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if b, _ := io.ReadAll(body); string(b) != "hello" {
		t.Errorf("body = %q, want hello", b)
	}
}

func TestPlainHTTPToLoopbackWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	defer srv.Close()

	body, err := get(t, newTestClient(t), srv.URL)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if b, _ := io.ReadAll(body); string(b) != "hello" {
		t.Errorf("body = %q, want hello", b)
	}
}

func TestPlainHTTPOffLoopbackIsRefusedBeforeConnecting(t *testing.T) {
	// TEST-NET and private addresses: nothing is listening, and the check
	// refuses them before connect is ever called.
	for _, url := range []string{"http://203.0.113.5:9/", "http://10.255.255.1:9/"} {
		if _, err := get(t, newTestClient(t), url); !errors.Is(err, ErrInsecure) {
			t.Errorf("GET %s error = %v, want ErrInsecure", url, err)
		}
	}
}

func TestBlockedAddressesNeverConnect(t *testing.T) {
	for _, url := range []string{
		"https://169.254.169.254/latest/meta-data/",
		"https://[::ffff:169.254.169.254]/",
		"https://100.100.100.200/",
		"http://169.254.169.254/",
		"https://0.0.0.0/",
		"https://[::]/",
		"http://0.0.0.0:8080/",
		"https://metadata.google.internal./computeMetadata/v1/",
		"https://METADATA.goog/",
	} {
		if _, err := get(t, newTestClient(t), url); !errors.Is(err, ErrBlocked) {
			t.Errorf("GET %s error = %v, want ErrBlocked", url, err)
		}
	}
}

func TestOtherSchemesAreRefused(t *testing.T) {
	for _, url := range []string{"ftp://127.0.0.1/", "file:///etc/passwd"} {
		if _, err := get(t, newTestClient(t), url); !errors.Is(err, ErrInsecure) {
			t.Errorf("GET %s error = %v, want ErrInsecure", url, err)
		}
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer src.Close()

	_, err := get(t, newTestClient(t), src.URL)

	if !errors.Is(err, ErrRedirect) {
		t.Errorf("Do() error = %v, want ErrRedirect", err)
	}
	if n := targetHits.Load(); n != 0 {
		t.Errorf("the redirect target got %d requests, want 0", n)
	}
}

func TestNoProxyEver(t *testing.T) {
	// Go's ProxyFromEnvironment skips localhost, so a proxy env var against a
	// local test server proves nothing. The transport field is the real check.
	if New().transport.Proxy != nil {
		t.Error("transport.Proxy is set, want nil so probes always go direct")
	}
}

func TestResponseBodyIsCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := MaxBodySize
		if r.URL.Path == "/over" {
			n++
		}
		// No Content-Length, so the cap has to work while reading.
		w.Header().Set("Content-Type", "application/octet-stream")
		chunk := strings.Repeat("a", 64<<10)
		for n > 0 {
			k := min(n, len(chunk))
			_, _ = io.WriteString(w, chunk[:k])
			flush(w)
			n -= k
		}
	}))
	defer srv.Close()
	c := newTestClient(t)

	body, err := get(t, c, srv.URL+"/at")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(body); err != nil || len(b) != MaxBodySize {
		t.Errorf("at the cap: read %d bytes, %v; want %d bytes", len(b), err, MaxBodySize)
	}

	body, err = get(t, c, srv.URL+"/over")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(body); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over the cap: read error = %v, want ErrTooLarge", err)
	}
}

func TestDeclaredLengthOverTheCapFailsAtOnce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "99999999999")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := get(t, newTestClient(t), srv.URL); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Do() error = %v, want ErrTooLarge", err)
	}
}

func TestNeverEndingResponseIsCutOff(t *testing.T) {
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A slow drip that never ends, like SSE pings.
		for {
			select {
			case <-stop:
				return
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
				_, _ = io.WriteString(w, ": ping\n")
				flush(w)
			}
		}
	}))
	defer srv.Close()
	defer close(stop)
	c := newTestClient(t, withTimeout(300*time.Millisecond))

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		body, err := get(t, c, srv.URL)
		if err == nil {
			_, err = io.ReadAll(body)
		}
		done <- err
	}()

	// A watchdog, so a missing timeout fails fast instead of hanging.
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("reading a never-ending response returned no error")
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Errorf("took %v to cut off, want about the 300ms timeout", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a never-ending response was still being read after 5s, want it cut off")
	}
}

func TestHugeHeadersAreRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Big", strings.Repeat("a", 200<<10))
	}))
	defer srv.Close()

	if _, err := get(t, newTestClient(t), srv.URL); err == nil {
		t.Error("Do() error = nil, want an error for 200 KiB of headers")
	}
}

// fakeDNS answers A queries on loopback UDP. The nth A query gets answers[n],
// or the last answer once they run out. AAAA queries get no answer.
type fakeDNS struct {
	conn    net.PacketConn
	mu      sync.Mutex
	answers []netip.Addr
	queries int
}

func startFakeDNS(t *testing.T, answers ...string) *fakeDNS {
	t.Helper()
	conn, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDNS{conn: conn}
	for _, a := range answers {
		d.answers = append(d.answers, netip.MustParseAddr(a))
	}
	t.Cleanup(func() { _ = conn.Close() })
	go d.serve()
	return d
}

func (d *fakeDNS) serve() {
	buf := make([]byte, 512)
	for {
		n, from, err := d.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if resp := d.answer(buf[:n]); resp != nil {
			_, _ = d.conn.WriteTo(resp, from)
		}
	}
}

func (d *fakeDNS) answer(q []byte) []byte {
	// Header is 12 bytes, then one question: name, type, class.
	if len(q) < 12 {
		return nil
	}
	end := 12
	for end < len(q) && q[end] != 0 {
		end += int(q[end]) + 1
	}
	end++ // the zero byte
	if end+4 > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[end:])
	question := q[12 : end+4]

	resp := make([]byte, 12, 64)
	copy(resp, q[:2])                            // id
	binary.BigEndian.PutUint16(resp[2:], 0x8180) // response, recursion available
	binary.BigEndian.PutUint16(resp[4:], 1)      // one question
	resp = append(resp, question...)
	if qtype != 1 { // not A
		return resp
	}
	d.mu.Lock()
	ip := d.answers[min(d.queries, len(d.answers)-1)]
	d.queries++
	d.mu.Unlock()
	binary.BigEndian.PutUint16(resp[6:], 1) // one answer
	resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4)
	v4 := ip.As4()
	return append(resp, v4[:]...)
}

func (d *fakeDNS) resolver() *net.Resolver {
	addr := d.conn.LocalAddr().String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp4", addr)
		},
	}
}

func portOf(t *testing.T, url string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestRebindingIsCheckedOnEveryConnection(t *testing.T) {
	tests := []struct {
		name    string
		tls     bool
		host    string
		rebind  string
		wantErr error
	}{
		// A name that first resolves to loopback and then to metadata.
		{"https to metadata", true, "example.com", "169.254.169.254", ErrBlocked},
		{"http to metadata", false, "rebind.test", "169.254.169.254", ErrBlocked},
		// Plaintext that first resolves to loopback and then off the machine.
		{"http off loopback", false, "rebind.test", "10.0.0.5", ErrInsecure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
			var srv *httptest.Server
			opts := []option{}
			if tt.tls {
				// httptest's certificate is valid for example.com.
				srv = httptest.NewTLSServer(h)
				opts = append(opts, withRootCAs(rootsOf(t, srv)))
			} else {
				srv = httptest.NewServer(h)
			}
			defer srv.Close()
			dns := startFakeDNS(t, "127.0.0.1", tt.rebind)
			c := newTestClient(t, append(opts, withResolver(dns.resolver()))...)
			scheme := "http"
			if tt.tls {
				scheme = "https"
			}
			url := scheme + "://" + tt.host + ":" + portOf(t, srv.URL) + "/"

			if _, err := get(t, c, url); err != nil {
				t.Fatalf("first request (resolves to loopback) error = %v", err)
			}
			c.http.CloseIdleConnections() // force a new connection and a new lookup
			_, err := get(t, c, url)

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("second request (rebound to %s) error = %v, want %v", tt.rebind, err, tt.wantErr)
			}
		})
	}
}
