package codex

import (
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

// trustOf returns each project's raw path and trust level.
func trustOf(ps []model.Project) map[string]model.TrustLevel {
	out := map[string]model.TrustLevel{}
	for _, p := range ps {
		var level model.TrustLevel
		if len(p.Trust) > 0 {
			level = p.Trust[0].Level
		}
		out[p.Path.Raw()] = level
	}
	return out
}

func TestProjectsAndTrustComeFromTheProjectsTable(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml": `
model = "some-model"

[projects."/projects/app"]
trust_level = "trusted"

[projects.'C:\work\b']
trust_level = "untrusted"

[projects."/odd"]
trust_level = "maybe"

[projects."/no-trust"]

[mcp_servers.s.env]
TOKEN = "` + canary + `"
`,
	})

	ps, fs := Adapter{}.Projects(c)

	want := map[string]model.TrustLevel{
		c.Env.MapPath("/projects/app"): model.TrustTrusted,
		c.Env.MapPath(`C:\work\b`):     model.TrustUntrusted,
		c.Env.MapPath("/odd"):          model.TrustUnknown,
		c.Env.MapPath("/no-trust"):     "",
	}
	if got := trustOf(ps); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("projects and trust = %v, want %v", got, want)
	}
	if len(fs) != 0 {
		t.Errorf("findings = %+v, want none", fs)
	}
	for _, p := range ps {
		o := p.Origins[0]
		if o.Agent != model.AgentCodex || o.Scope != model.ScopeUser ||
			o.File.Raw() != filepath.Join(c.Env.Home, ".codex", "config.toml") {
			t.Errorf("origin = %+v, want codex, user scope, ~/.codex/config.toml", o)
		}
	}
}

func TestDottedKeyFormWorksToo(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml": `projects."/dotted".trust_level = "trusted"` + "\n",
	})

	ps, _ := Adapter{}.Projects(c)

	if got := trustOf(ps); got[c.Env.MapPath("/dotted")] != model.TrustTrusted {
		t.Errorf("projects = %v, want /dotted trusted", got)
	}
}

func TestCodexHomeMovesConfig(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".jarx-env":          "CODEX_HOME=/ch\n",
		"ch/config.toml":     `[projects."/from/codex/home"]` + "\n",
		".codex/config.toml": `[projects."/from/default"]` + "\n",
	})

	ps, _ := Adapter{}.Projects(c)

	trust := trustOf(ps)
	got := make([]string, 0, len(trust))
	for p := range trust {
		got = append(got, p)
	}
	if !slices.Equal(got, []string{c.Env.MapPath("/from/codex/home")}) {
		t.Errorf("projects = %q, want only the one from CODEX_HOME", got)
	}
}

func TestNoConfigMeansNoProjects(t *testing.T) {
	ps, fs := Adapter{}.Projects(fakeHome(t, nil))

	if len(ps) != 0 || len(fs) != 0 {
		t.Errorf("Projects() = %+v, %+v; want nothing", ps, fs)
	}
}

func TestBrokenConfigIsAFindingWithTheLineButNoContent(t *testing.T) {
	c := fakeHome(t, map[string]string{
		// BurntSushi's Error() quotes the last key, and ErrorWithPosition()
		// prints the whole line, so the secret sits in both. It matches no
		// pattern, so only leaving content out can keep it out.
		".codex/config.toml": "model = \"m\"\n\n" + plainSecret + " = \"unterminated " + plainSecret + "\n",
	})

	ps, fs := Adapter{}.Projects(c)

	if len(ps) != 0 {
		t.Errorf("projects = %v, want none", trustOf(ps))
	}
	if len(fs) != 1 || fs[0].RuleID != finding.UnreadableRecord().ID || fs[0].Origin.Line != 3 {
		t.Fatalf("findings = %+v, want one %s at line 3", fs, finding.UnreadableRecord().ID)
	}
	if out := fmt.Sprintf("%+v", fs); strings.Contains(out, plainSecret) {
		t.Errorf("finding leaks file content: %s", out)
	}
}
