package discover

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

// pathContext is a fake home whose PATH is dirs (each from the home), with
// a claude command in each of cmds.
func pathContext(t *testing.T, dirs []string, cmds ...string) agent.Context {
	t.Helper()
	home := t.TempDir()
	entries := make([]string, 0, len(dirs))
	for _, d := range dirs {
		entries = append(entries, "~/"+d)
	}
	write := func(rel, content string, mode os.FileMode) {
		p := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(".jarx-env", "PATH="+strings.Join(entries, string(os.PathListSeparator))+"\n", 0o600)
	for _, d := range cmds {
		write(d+"/"+commandFile(), "#!/bin/sh\n", 0o700)
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

// commandFile is how claude's command is named in a PATH dir on this OS.
func commandFile() string {
	if filepath.Separator == '\\' {
		return "claude.cmd"
	}
	return "claude"
}

// installer is an adapter with fixed installs, by bin dir under the home.
type installer struct{ bins map[string]string } // bin dir -> version

func (installer) Agent() model.Agent { return model.AgentClaude }
func (installer) Projects(agent.Context) ([]model.Project, []finding.Finding) {
	return nil, nil
}
func (installer) Command() string { return "claude" }
func (i installer) Installs(c agent.Context) []model.Install {
	out := make([]model.Install, 0, len(i.bins))
	for bin, v := range i.bins {
		dir := filepath.Join(c.Env.Home, filepath.FromSlash(bin))
		out = append(out, model.Install{
			Agent: model.AgentClaude, Method: model.InstallNPM, Path: model.NewPath(c.Scrub, dir), BinDir: model.NewPath(c.Scrub, dir),
			Version: installText(c, v),
		})
	}
	return out
}

func installText(c agent.Context, s string) redact.Text {
	t, _ := c.Scrub.Scrub(s)
	return t
}

// onPath is the version of each install, marking the PATH winner with *.
func onPath(ins []model.Install) map[string]bool {
	out := map[string]bool{}
	for _, in := range ins {
		out[string(in.Method)+" "+in.Version.String()] = in.OnPath
	}
	return out
}

func TestTheFirstInstallOnPathWins(t *testing.T) {
	c := pathContext(t, []string{"empty", "npm", ".local/bin"}, "npm", ".local/bin")
	a := installer{bins: map[string]string{"npm": "2.1.100", ".local/bin": "2.1.200"}}

	got := onPath(Run(c, []agent.Adapter{a}, nil).Installs)

	if want := map[string]bool{"npm 2.1.100": true, "npm 2.1.200": false}; !equalMaps(got, want) {
		t.Errorf("installs on PATH = %v, want %v: npm comes first on PATH", got, want)
	}
}

func TestACommandAtNoKnownInstallIsAnUnknownInstall(t *testing.T) {
	c := pathContext(t, []string{"opt/bin", "npm"}, "opt/bin", "npm")
	a := installer{bins: map[string]string{"npm": "2.1.100"}}

	ins := Run(c, []agent.Adapter{a}, nil).Installs

	got := onPath(ins)
	if want := map[string]bool{"npm 2.1.100": false, "unknown ": true}; !equalMaps(got, want) {
		t.Fatalf("installs on PATH = %v, want %v", got, want)
	}
	for _, in := range ins {
		if in.Method == model.InstallUnknown {
			if want := filepath.Join(c.Env.Home, "opt", "bin", commandFile()); !strings.EqualFold(in.Path.Raw(), want) {
				t.Errorf("unknown install path = %s, want the command %s", in.Path.Raw(), want)
			}
		}
	}
}

func TestADirNamedLikeTheCommandIsntOne(t *testing.T) {
	c := pathContext(t, []string{"tools", "npm"}, "npm")
	if err := os.MkdirAll(filepath.Join(c.Env.Home, "tools", commandFile()), 0o700); err != nil {
		t.Fatal(err)
	}
	a := installer{bins: map[string]string{"npm": "2.1.100"}}

	got := onPath(Run(c, []agent.Adapter{a}, nil).Installs)

	if want := map[string]bool{"npm 2.1.100": true}; !equalMaps(got, want) {
		t.Errorf("installs on PATH = %v, want %v", got, want)
	}
}

func TestNoCommandOnPathMeansNoWinner(t *testing.T) {
	c := pathContext(t, []string{"empty"})
	a := installer{bins: map[string]string{"npm": "2.1.100"}}

	got := onPath(Run(c, []agent.Adapter{a}, nil).Installs)

	if want := map[string]bool{"npm 2.1.100": false}; !equalMaps(got, want) {
		t.Errorf("installs on PATH = %v, want %v", got, want)
	}
}

func equalMaps(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
