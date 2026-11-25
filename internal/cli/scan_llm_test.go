package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/nickelsec/jarx/internal/llm"
)

// reviewer is an OpenAI-compatible endpoint for scan --llm. It finds one
// thing in every skill, quoting the skill's own text, finds nothing in the
// rest, and keeps every request body.
type reviewer struct {
	mu      sync.Mutex
	status  int // 0 means 200
	bodies  []string
	headers []http.Header
}

func (f *reviewer) serve(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.bodies = append(f.bodies, string(b))
		f.headers = append(f.headers, r.Header.Clone())
		status := f.status
		f.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		reply := `{"findings":[]}`
		if art := userArtifact(b); art.Kind == "skill" && len(strings.TrimSpace(art.Text)) >= 20 {
			quote := strings.TrimSpace(art.Text)[:20]
			out, _ := json.Marshal(map[string]any{"findings": []any{map[string]string{
				"severity": "high", "title": "does more than it says", "quote": quote, "why": "a test reviewer flags every skill",
			}}})
			reply = string(out)
		}
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": reply}}}})
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/v1"
}

func (f *reviewer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

type userArt struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

func userArtifact(body []byte) userArt {
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	var a userArt
	if json.Unmarshal(body, &req) == nil && len(req.Messages) > 1 {
		_ = json.Unmarshal([]byte(req.Messages[1].Content), &a)
	}
	return a
}

// llmDemo is a demo copy with the LLM review set up to point at base.
func llmDemo(t *testing.T, base string) string {
	t.Helper()
	demo := demoCopy(t)
	if got := runIn("", "setup", "llm", "--home", demo, "--url", base, "--model", "m-1", "--key-env", "JARX_LLM_KEY"); got.code != 0 {
		t.Fatalf("setup llm = %d, %q", got.code, got.stderr)
	}
	return demo
}

// withKey is a terminal with the LLM key set.
func withKey() opts { return terminal(map[string]string{"JARX_LLM_KEY": canaryLLMKey}) }

var summaryRe = regexp.MustCompile(`\n\d+ findings? `)

func TestScanLLMRefusesWithoutATerminal(t *testing.T) {
	demo := llmDemo(t, "https://llm.example.com/v1")

	got := opts{keys: withKey().keys}.run("scan", "--llm", "--home", demo)

	if got.code != 2 || !strings.Contains(got.stderr, "jarx scan --llm asks before sending anything, so it needs a terminal. run it in one, or drop --llm") {
		t.Errorf("exit %d, stderr %q; want 2 and why", got.code, got.stderr)
	}
	if strings.Contains(got.stdout, "scanned") {
		t.Error("it scanned before refusing")
	}
}

func TestScanLLMRefusesWhenItIsNotSetUp(t *testing.T) {
	home := fakeHome(t, "")

	got := withKey().ask("", "scan", "--llm", "--home", home)

	if got.code != 1 || !strings.Contains(got.stderr, "llm review isn't set up. run jarx setup llm first") || strings.Contains(got.stdout, "scanned") {
		t.Errorf("exit %d, stderr %q; want 1 before scanning", got.code, got.stderr)
	}
}

func TestScanLLMRefusesWhenTheKeyIsNotSet(t *testing.T) {
	demo := llmDemo(t, "https://llm.example.com/v1")

	got := ask("", "scan", "--llm", "--home", demo)

	for _, want := range []string{"JARX_LLM_KEY isn't set in this terminal", "read -rs JARX_LLM_KEY && export JARX_LLM_KEY", "Read-Host -AsSecureString"} {
		if !strings.Contains(got.stderr, want) {
			t.Errorf("stderr = %q, want it to contain %q", got.stderr, want)
		}
	}
	if got.code != 1 || strings.Contains(got.stdout, "scanned") {
		t.Errorf("exit %d, want 1 before scanning", got.code)
	}
}

func TestScanLLMShowsThePreviewAndSendsNothingOnNo(t *testing.T) {
	f := &reviewer{}
	demo := llmDemo(t, f.serve(t))

	got := withKey().ask("\n", "scan", "--llm", "--home", demo)

	if got.code != 0 || f.count() != 0 {
		t.Fatalf("exit %d with %d requests, want 0 and none (stderr %q)", got.code, f.count(), got.stderr)
	}
	for _, want := range []string{
		"\nllm review\n+- ",
		"+- to             127.0.0.1:",
		" - m-1 - key from JARX_LLM_KEY\n",
		`\- secrets masked before sending - history never sent` + "\n",
		"?  [y/N]\n  >  not sent\n",
	} {
		if !strings.Contains(got.stdout, want) {
			t.Errorf("stdout doesn't contain %q:\n%s", want, got.stdout)
		}
	}
	scanned, preview, summary := strings.Index(got.stdout, "\nscanned\n"), strings.Index(got.stdout, "\nllm review\n"), summaryRe.FindStringIndex(got.stdout)
	if scanned < 0 || preview < scanned || summary == nil || summary[0] < preview {
		t.Errorf("want the scanned block, then the preview, then the summary:\n%s", got.stdout)
	}
	if strings.Contains(got.stdout, "LLM-00") {
		t.Error("LLM findings without a review")
	}
}

func TestScanLLMSendsOnYesAndItsFindingsJoinTheGroups(t *testing.T) {
	f := &reviewer{}
	demo := llmDemo(t, f.serve(t))

	got := withKey().ask("y\n", "scan", "--llm", "--home", demo)

	if got.code != 0 || f.count() == 0 {
		t.Fatalf("exit %d with %d requests, want 0 and some (stderr %q)", got.code, f.count(), got.stderr)
	}
	if !strings.Contains(got.stdout, "  >  reviewed ") || !strings.Contains(got.stdout, "LLM-001") {
		t.Errorf("stdout lacks the review line or the LLM finding:\n%s", got.stdout)
	}
	data, err := readDemoEnv()
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range f.bodies {
		assertDemoNoLeak(t, data, body)
		if strings.Contains(body, canaryLLMKey) {
			t.Error("a request body holds the key")
		}
	}
	assertDemoNoLeak(t, data, got.stdout+got.stderr)
}

func TestScanLLMUsesTheCacheTheSecondTime(t *testing.T) {
	f := &reviewer{}
	demo := llmDemo(t, f.serve(t))
	withKey().ask("y\n", "scan", "--llm", "--home", demo)
	sent := f.count()

	got := withKey().ask("", "scan", "--llm", "--home", demo)

	if f.count() != sent || !regexp.MustCompile(`llm review: all \d+ artifacts are cached, nothing sent\n`).MatchString(got.stdout) {
		t.Errorf("%d more requests, stdout\n%s\nwant none, from the cache", f.count()-sent, got.stdout)
	}
	if strings.Contains(got.stdout, "[y/N]") || !strings.Contains(got.stdout, "LLM-001") {
		t.Errorf("want no question and the cached finding:\n%s", got.stdout)
	}
}

func TestScanLLMFindingsStayOutOfTheSnapshot(t *testing.T) {
	f := &reviewer{}
	demo := llmDemo(t, f.serve(t))
	withKey().ask("y\n", "scan", "--llm", "--home", demo)

	got := run("scan", "--all", "--home", demo)

	if strings.Contains(got.stdout, "JARX-LLM") {
		t.Errorf("a scan without --llm shows LLM findings or their removal:\n%s", got.stdout)
	}
}

func TestScanLLMCtrlCAtTheQuestionSendsNothing(t *testing.T) {
	f := &reviewer{}
	demo := llmDemo(t, f.serve(t))

	got := withKey().askThenCtrlC(t, "", "scan", "--llm", "--home", demo)

	if got.code != 130 || f.count() != 0 || !strings.HasSuffix(got.stdout, "  >  \ncancelled, nothing sent\n") {
		t.Errorf("exit %d with %d requests, stdout %q; want 130, none, cancelled", got.code, f.count(), got.stdout)
	}
}

func TestScanLLMStopsWhenTheKeyIsRejected(t *testing.T) {
	f := &reviewer{status: http.StatusUnauthorized}
	demo := llmDemo(t, f.serve(t))

	got := withKey().ask("y\n", "scan", "--llm", "--home", demo)

	if got.code != 1 || f.count() != 1 || !strings.Contains(got.stdout, "llm review stopped: the endpoint rejected the key (HTTP 401)\n") {
		t.Errorf("exit %d with %d requests, stdout\n%s\nwant 1 after one request, with why", got.code, f.count(), got.stdout)
	}
	if summaryRe.FindStringIndex(got.stdout) == nil {
		t.Error("the rest of the scan didn't print")
	}
}

func TestScanUsageListsLLM(t *testing.T) {
	if got := run("scan", "--help"); !strings.Contains(got.stdout, "--llm") {
		t.Errorf("scan --help = %q, want --llm", got.stdout)
	}
}

// readDemoEnv is the repo demo's .jarx-env, for the leak checks.
func readDemoEnv() (string, error) {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "demo", ".jarx-env"))
	return string(b), err
}

func TestScanLLMNamesJarxAndSendsOneSession(t *testing.T) {
	// OpenCode Go refuses chat requests without a session header, and wants
	// the client's own user agent.
	f := &reviewer{}
	demo := llmDemo(t, f.serve(t))

	withKey().ask("y\n", "scan", "--llm", "--home", demo)

	if len(f.headers) == 0 {
		t.Fatal("no requests")
	}
	session := f.headers[0].Get(llm.SessionHeader)
	for i, h := range f.headers {
		if got := h.Get("User-Agent"); got != "jarx/v1.2.3-test" {
			t.Errorf("request %d User-Agent = %q, want jarx/v1.2.3-test", i, got)
		}
		if got := h.Get(llm.SessionHeader); got == "" || got != session {
			t.Errorf("request %d session = %q, want one session %q for the run", i, got, session)
		}
	}
}
