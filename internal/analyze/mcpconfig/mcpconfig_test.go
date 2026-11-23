package mcpconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

func scrubber(t *testing.T) *redact.Scrubber {
	t.Helper()
	ps, err := catalog.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	s, err := redact.New(ps, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// fixture is one server definition as a fixture file writes it.
type fixture struct {
	Agent         string   `json:"agent"`
	Scope         string   `json:"scope"`
	Transport     string   `json:"transport"`
	GOOS          string   `json:"goos"`
	Command       string   `json:"command"`
	Args          []string `json:"args"`
	URL           string   `json:"url"`
	HeadersHelper string   `json:"headersHelper"`
	ForwardEnv    []string `json:"forwardEnv"`
}

func text(s *redact.Scrubber, v string) redact.Text {
	t, _ := s.Scrub(v)
	return t
}

// load turns a fixture into the env it runs under and one project holding
// the server. Unset fields default to a Claude stdio server in user scope
// on linux.
func load(t *testing.T, s *redact.Scrubber, body []byte) (platform.Env, []model.Project) {
	t.Helper()
	var f fixture
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatal(err)
	}
	def := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	def(&f.Agent, "claude")
	def(&f.Scope, "user")
	def(&f.GOOS, "linux")
	if f.Transport == "" {
		f.Transport = "stdio"
		if f.URL != "" {
			f.Transport = "http"
		}
	}
	home := "/home/dev"
	if f.GOOS == "windows" {
		home = `C:\Users\dev`
	}
	srv := model.Server{
		Name: text(s, "srv"), Transport: model.Transport(f.Transport), Command: text(s, f.Command), URL: text(s, f.URL),
		HeadersHelper: text(s, f.HeadersHelper), Start: model.StartYes,
		Origin: model.Origin{Agent: model.Agent(f.Agent), Scope: model.Scope(f.Scope), File: model.NewPath(s, "/p/.mcp.json"), InEffect: true},
	}
	for _, a := range f.Args {
		srv.Args = append(srv.Args, text(s, a))
	}
	for _, v := range f.ForwardEnv {
		srv.ForwardEnv = append(srv.ForwardEnv, text(s, v))
	}
	return platform.Env{GOOS: f.GOOS, Home: home}, []model.Project{{Path: model.NewPath(s, "/p"), Servers: []model.Server{srv}}}
}

func ids(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func has(fs []finding.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestEveryRuleHasPoisonedAndCleanFixtures(t *testing.T) {
	known := map[string]bool{}
	for _, r := range Rules() {
		known[r.ID] = true
		for _, kind := range []string{"poisoned", "clean"} {
			entries, err := os.ReadDir(filepath.Join("testdata", r.ID, kind))
			if err != nil || len(entries) == 0 {
				t.Errorf("%s has no %s fixtures", r.ID, kind)
			}
		}
	}
	dirs, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dirs {
		if !known[d.Name()] {
			t.Errorf("testdata/%s is for a rule that doesn't exist", d.Name())
		}
	}
}

func TestFixtures(t *testing.T) {
	s := scrubber(t)
	for _, r := range Rules() {
		for _, kind := range []string{"poisoned", "clean"} {
			dir := filepath.Join("testdata", r.ID, kind)
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				t.Run(r.ID+"/"+kind+"/"+e.Name(), func(t *testing.T) {
					body, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // G304: our own fixture dir
					if err != nil {
						t.Fatal(err)
					}
					env, ps := load(t, s, body)
					got := Analyze(s, env, ps)
					if raised := has(got, r.ID); raised != (kind == "poisoned") {
						t.Errorf("findings = %q, want %s raised: %v", ids(got), r.ID, kind == "poisoned")
					}
				})
			}
		}
	}
}

func TestServersThatWontStartAreSkipped(t *testing.T) {
	s := scrubber(t)
	env, ps := load(t, s, []byte(`{"command": "npx", "args": ["-y", "server-files@latest"]}`))
	ps[0].Servers[0].Start = model.StartNo

	if got := Analyze(s, env, ps); len(got) != 0 {
		t.Errorf("findings = %q, want none for a server that's overridden or blocked", ids(got))
	}
}

func TestAServerWaitingOnApprovalIsStillChecked(t *testing.T) {
	s := scrubber(t)
	env, ps := load(t, s, []byte(`{"scope": "project", "command": "npx", "args": ["-y", "server-files@latest"]}`))
	ps[0].Servers[0].Start = model.StartUnknown

	if got := Analyze(s, env, ps); !has(got, UnpinnedRunner().ID) {
		t.Errorf("findings = %q, want the unpinned runner flagged before anyone approves it", ids(got))
	}
}

func TestASharedServerIsReportedOnce(t *testing.T) {
	s := scrubber(t)
	env, ps := load(t, s, []byte(`{"command": "npx", "args": ["-y", "server-files@latest"]}`))
	ps = append(ps, model.Project{Path: model.NewPath(s, "/q"), Servers: ps[0].Servers})

	if got := Analyze(s, env, ps); len(got) != 1 {
		t.Errorf("findings = %q, want one for the user server two projects load", ids(got))
	}
}

func TestEvidenceNamesTheServerAndWhatItRuns(t *testing.T) {
	s := scrubber(t)
	env, ps := load(t, s, []byte(`{"command": "npx", "args": ["-y", "server-files@latest"]}`))

	got := Analyze(s, env, ps)

	if len(got) != 1 || !strings.Contains(got[0].Evidence.String(), "srv") || !strings.Contains(got[0].Evidence.String(), "server-files@latest") {
		t.Errorf("findings = %+v, want evidence naming srv and the package", got)
	}
}

func TestRuleTitlesFitTheReport(t *testing.T) {
	if _, err := finding.NewRegistry(Rules()...); err != nil {
		t.Fatalf("rules don't register: %v", err)
	}
}
