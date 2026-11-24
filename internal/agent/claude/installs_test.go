package claude

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/model"
)

// installHome is a fake home whose files may name the home itself as
// $HOME, for an npm prefix that has to be an absolute path.
func installHome(t *testing.T, files map[string]string) agent.Context {
	t.Helper()
	home := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(strings.ReplaceAll(content, "$HOME", home)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return contextFor(t, home)
}

// installLines are the installs as "method version (from) bin-dir", with the
// bin dir relative to the home.
func installLines(c agent.Context, ins []model.Install) []string {
	out := make([]string, 0, len(ins))
	for _, in := range ins {
		bin, _ := filepath.Rel(c.Env.Home, in.BinDir.Raw())
		out = append(out, string(in.Method)+" "+in.Version.String()+" ("+in.VersionFrom.String()+") "+filepath.ToSlash(bin))
	}
	slices.Sort(out)
	return out
}

func launcherName(c agent.Context) string {
	if c.Env.GOOS == "windows" {
		return "claude.exe"
	}
	return "claude"
}

func TestTheNativeLauncherLinkNamesTheVersion(t *testing.T) {
	c := installHome(t, map[string]string{
		".local/share/claude/versions/2.1.100": "old",
		".local/share/claude/versions/2.1.200": "new",
	})
	home := c.Env.Home
	link := filepath.Join(home, ".local", "bin", launcherName(c))
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".local", "share", "claude", "versions", "2.1.200"), link); err != nil {
		t.Skipf("can't make symlinks here: %v", err)
	}

	got := installLines(c, (Adapter{}).Installs(c))

	if want := []string{"native 2.1.200 (launcher link) .local/bin"}; !slices.Equal(got, want) {
		t.Errorf("installs = %q, want %q", got, want)
	}
}

func TestOneNativeVersionIsTheVersion(t *testing.T) {
	c := installHome(t, map[string]string{
		".local/share/claude/versions/2.1.120": "binary",
		".local/bin/" + "claude":               "a copy, not a link",
		".local/bin/" + "claude.exe":           "a copy, not a link",
	})

	got := installLines(c, (Adapter{}).Installs(c))

	if want := []string{"native 2.1.120 (only installed version) .local/bin"}; !slices.Equal(got, want) {
		t.Errorf("installs = %q, want %q", got, want)
	}
}

func TestSeveralNativeVersionsAndNoLinkIsUnknown(t *testing.T) {
	c := installHome(t, map[string]string{
		".local/share/claude/versions/2.1.120": "binary",
		".local/share/claude/versions/2.1.200": "binary",
		".local/bin/claude":                    "a copy",
		".local/bin/claude.exe":                "a copy",
	})

	got := installLines(c, (Adapter{}).Installs(c))

	if want := []string{"native  (2 versions, and the launcher isn't a link to one) .local/bin"}; !slices.Equal(got, want) {
		t.Errorf("installs = %q, want %q", got, want)
	}
}

func TestAnNPMInstallTakesItsVersionFromPackageJSON(t *testing.T) {
	pkgs := "npm/lib/node_modules"
	bin := "npm/bin"
	if c := fakeHome(t, nil); c.Env.GOOS == "windows" {
		pkgs, bin = "npm/node_modules", "npm"
	}
	c := installHome(t, map[string]string{
		".jarx-env": "NPM_CONFIG_PREFIX=$HOME/npm\n",
		pkgs + "/@anthropic-ai/claude-code/package.json": `{"name": "@anthropic-ai/claude-code", "version": "2.1.250"}`,
		pkgs + "/@openai/codex/package.json":             `{"name": "@openai/codex", "version": "0.38.0"}`,
	})

	got := installLines(c, (Adapter{}).Installs(c))

	if want := []string{"npm 2.1.250 (package.json) " + bin}; !slices.Equal(got, want) {
		t.Errorf("installs = %q, want %q", got, want)
	}
}

func TestAPackageThatIsntClaudeCodeIsntAnInstall(t *testing.T) {
	pkgs := "npm/lib/node_modules"
	if c := fakeHome(t, nil); c.Env.GOOS == "windows" {
		pkgs = "npm/node_modules"
	}
	c := installHome(t, map[string]string{
		".jarx-env": "npm_config_prefix=$HOME/npm\n",
		pkgs + "/@anthropic-ai/claude-code/package.json": `{"name": "claude-code-lookalike", "version": "9.9.9"}`,
	})

	if got := (Adapter{}).Installs(c); len(got) != 0 {
		t.Errorf("installs = %q, want none: the package.json names another package", installLines(c, got))
	}
}

func TestNothingInstalledMeansNoInstalls(t *testing.T) {
	c := installHome(t, nil)

	if got := (Adapter{}).Installs(c); len(got) != 0 {
		t.Errorf("installs = %q, want none", installLines(c, got))
	}
	if got := (Adapter{}).Command(); got != "claude" {
		t.Errorf("Command() = %q, want claude", got)
	}
}

func TestALauncherLinkingElsewhereHasNoVersion(t *testing.T) {
	c := installHome(t, map[string]string{
		".local/share/claude/versions/2.1.200": "binary",
		"tools/2.9.9":                          "not one of the versions",
	})
	home := c.Env.Home
	link := filepath.Join(home, ".local", "bin", launcherName(c))
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "tools", "2.9.9"), link); err != nil {
		t.Skipf("can't make symlinks here: %v", err)
	}

	got := installLines(c, (Adapter{}).Installs(c))

	if want := []string{"native  (the launcher links outside the versions dir) .local/bin"}; !slices.Equal(got, want) {
		t.Errorf("installs = %q, want %q: a file name outside the versions dir isn't a version", got, want)
	}
}
