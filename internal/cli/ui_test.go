package cli

import (
	"bytes"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nickelsec/jarx/internal/netguard"
)

// urlRe is the link jarx ui prints.
var urlRe = regexp.MustCompile(`http://127\.0\.0\.1:\d+/\?t=[A-Za-z0-9_-]{40,}`)

// watched is stdout that tells the test when the link has been printed.
type watched struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	seen chan string
	sent bool
}

func (w *watched) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, _ := w.buf.Write(p)
	if u := urlRe.FindString(w.buf.String()); u != "" && !w.sent {
		w.sent = true
		w.seen <- u
	}
	return n, nil
}

func (w *watched) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func TestUIServesBehindTheGuardUntilCtrlC(t *testing.T) {
	home := fakeHome(t, "")
	out := &watched{seen: make(chan string, 1)}
	sig := make(chan os.Signal, 1)
	var errw bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- runWith([]string{"ui", "--home", home}, streams{
			in: strings.NewReader(""), out: out, err: &errw,
			interrupt: func() (<-chan os.Signal, func()) { return sig, func() {} },
		}, "v1.2.3-test")
	}()

	var link string
	select {
	case link = <-out.seen:
	case code := <-done:
		t.Fatalf("jarx ui exited %d before printing a link: %s %s", code, out, errw.String())
	case <-time.After(10 * time.Second):
		t.Fatal("no link after 10s")
	}
	assertGuarded(t, link)

	sig <- os.Interrupt
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit %d after ctrl+c, want 0 (stderr %q)", code, errw.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("still running 10s after ctrl+c")
	}
	for _, want := range []string{"jarx dashboard\n", "127.0.0.1 only", "the link works once", "ctrl+c stops it", "\n  " + link + "\n", "dashboard stopped\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout = %q, want it to contain %q", out.String(), want)
		}
	}
}

// assertGuarded checks the server at link is up and behind the guard: no
// cookie, no page.
func assertGuarded(t *testing.T, link string) {
	t.Helper()
	base, _, _ := strings.Cut(link, "?")
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := netguard.New().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("GET / without the cookie = %d, want 403", resp.StatusCode)
	}
}

func TestUIHelpAndUsage(t *testing.T) {
	if got := run("ui", "-h"); got.code != 0 || !strings.Contains(got.stdout, "usage: jarx ui") {
		t.Errorf("ui -h = %d, %q; want 0 with usage", got.code, got.stdout)
	}
	if got := run("-h"); !strings.Contains(got.stdout, "  ui ") {
		t.Errorf("jarx -h = %q, want ui listed", got.stdout)
	}
	if got := run("ui", "--home", fakeHome(t, ""), "extra"); got.code != 2 {
		t.Errorf("ui with an argument = %d, want 2", got.code)
	}
}
