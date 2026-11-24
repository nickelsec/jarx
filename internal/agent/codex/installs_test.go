package codex

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
)

func TestCodexInstallsComeFromNPM(t *testing.T) {
	home := t.TempDir()
	modules, bin := filepath.Join("npm", "lib", "node_modules"), filepath.Join("npm", "bin")
	if (contextFor(t, home)).Env.GOOS == "windows" {
		modules, bin = filepath.Join("npm", "node_modules"), "npm"
	}
	writeFiles(t, home, map[string]string{
		".jarx-env": "NPM_CONFIG_PREFIX=" + filepath.Join(home, "npm") + "\n",
		filepath.Join(modules, "@openai", "codex", "package.json"):             `{"name": "@openai/codex", "version": "0.38.0"}`,
		filepath.Join(modules, "@anthropic-ai", "claude-code", "package.json"): `{"name": "@anthropic-ai/claude-code", "version": "2.1.250"}`,
	})
	c := contextFor(t, home)

	got := Adapter{}.Installs(c)

	if len(got) != 1 {
		t.Fatalf("installs = %+v, want one npm install", got)
	}
	in := got[0]
	if in.Agent != model.AgentCodex || in.Method != model.InstallNPM || in.Version.String() != "0.38.0" {
		t.Errorf("install = %s %s %s, want codex npm 0.38.0", in.Agent, in.Method, in.Version)
	}
	if want := filepath.Join(c.Env.Home, bin); in.BinDir.Raw() != want {
		t.Errorf("bin dir = %s, want %s", in.BinDir.Raw(), want)
	}
	if got := (Adapter{}).Command(); got != "codex" {
		t.Errorf("Command() = %q, want codex", got)
	}
}

func writeFiles(t *testing.T, home string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
