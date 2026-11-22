package claude

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

const canary = "tok_Xq7Lm2Pz9Rw4Tb8Nc1Vd" // made up for tests

// plainSecret matches no pattern, so the scrubber can't mask it. A test that
// uses it shows file content is left out, not just masked.
const plainSecret = "hunter2-plain-secret-no-pattern"

// fakeHome writes files (slash paths relative to the home) and returns a
// Context for it.
func fakeHome(t *testing.T, files map[string]string) agent.Context {
	t.Helper()
	home := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env, err := platform.FromHome(home)
	if err != nil {
		t.Fatal(err)
	}
	f, err := fsys.New(env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	s, err := redact.New([]redact.Pattern{{Kind: "test_token", Re: regexp.MustCompile(`tok_[A-Za-z0-9]{16,}`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return agent.Context{Env: env, Files: f, Scrub: s}
}

func rawPaths(ps []model.Project) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Path.Raw())
	}
	slices.Sort(out)
	return out
}

func TestProjectsComeFromTheProjectsMapKeys(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude.json": `{
			"numStartups": 3,
			"projects": {
				"/projects/app": {"anything": {"nested": [1, 2, {"deep": true}]}},
				"C:\\work\\b": {}
			},
			"mcpServers": {"s": {"env": {"TOKEN": "` + canary + `"}}}
		}`,
	})

	ps, fs := Adapter{}.Projects(c)

	want := []string{
		c.Env.MapPath("/projects/app"),
		c.Env.MapPath(`C:\work\b`),
	}
	slices.Sort(want)
	if got := rawPaths(ps); !slices.Equal(got, want) {
		t.Fatalf("projects = %q, want %q", got, want)
	}
	if len(fs) != 0 {
		t.Errorf("findings = %+v, want none", fs)
	}
	o := ps[0].Origins[0]
	if o.Agent != model.AgentClaude || o.Scope != model.ScopeUser || !o.InEffect ||
		o.File.Raw() != filepath.Join(c.Env.Home, ".claude.json") {
		t.Errorf("origin = %+v, want claude, user scope, in effect, ~/.claude.json", o)
	}
}

func TestNoClaudeJSONMeansNoProjects(t *testing.T) {
	ps, fs := Adapter{}.Projects(fakeHome(t, nil))

	if len(ps) != 0 || len(fs) != 0 {
		t.Errorf("Projects() = %+v, %+v; want nothing", ps, fs)
	}
}

func TestClaudeConfigDirMovesClaudeJSON(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".jarx-env":        "CLAUDE_CONFIG_DIR=/cfg\n",
		"cfg/.claude.json": `{"projects": {"/from/config/dir": {}}}`,
		".claude.json":     `{"projects": {"/from/home": {}}}`,
	})

	ps, _ := Adapter{}.Projects(c)

	if got := rawPaths(ps); !slices.Equal(got, []string{c.Env.MapPath("/from/config/dir")}) {
		t.Errorf("projects = %q, want only the one from CLAUDE_CONFIG_DIR", got)
	}
}

func TestBrokenClaudeJSONIsAFindingWithoutContent(t *testing.T) {
	for name, body := range map[string]string{
		"syntax error":        `{"projects": {"/a": {}}, "token": "` + plainSecret + `" oops}`,
		"projects not a map":  `{"projects": ["` + plainSecret + `"]}`,
		"top level not a map": `["` + plainSecret + `"]`,
		"truncated":           `{"projects": {"/a": {"x": "` + plainSecret,
	} {
		t.Run(name, func(t *testing.T) {
			ps, fs := Adapter{}.Projects(fakeHome(t, map[string]string{".claude.json": body}))

			if len(ps) != 0 {
				t.Errorf("projects = %q, want none from a broken file", rawPaths(ps))
			}
			if len(fs) != 1 || fs[0].RuleID != finding.UnreadableRecord().ID {
				t.Fatalf("findings = %+v, want one %s", fs, finding.UnreadableRecord().ID)
			}
			if out := fmt.Sprintf("%+v", fs); strings.Contains(out, plainSecret) {
				t.Errorf("finding leaks file content: %s", out)
			}
		})
	}
}

func TestProjectKeysStopsAtTheCap(t *testing.T) {
	body := `{"projects": {"/a": {"pad": "` + strings.Repeat("x", 200) + `"}}}`

	_, err := projectKeys(strings.NewReader(body), 100)

	if !errors.Is(err, errTooLarge) {
		t.Errorf("projectKeys() error = %v, want errTooLarge", err)
	}
}

func TestProjectKeysNeverKeepsValues(t *testing.T) {
	body := `{"projects": {"/a": {"env": {"T": "` + canary + `"}}}, "x": "` + canary + `"}`

	keys, err := projectKeys(strings.NewReader(body), 1<<20)

	if err != nil || !slices.Equal(keys, []string{"/a"}) {
		t.Errorf("projectKeys() = %q, %v; want just the key", keys, err)
	}
}
