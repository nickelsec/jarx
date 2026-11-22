package cli

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// TestScanNeverRunsWhatHooksSkillsAndPluginsDeclare plants every kind of
// thing Claude can run: each hook handler type, a hook script, a skill's
// !`cmd` and ```! injection, and a plugin hook. Each would leave a marker
// file or hit a local server if anything ran it. jarx only reads them.
func TestScanNeverRunsWhatHooksSkillsAndPluginsDeclare(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	home := t.TempDir()
	writeCanaryHome(t, home, srv.URL)

	got := run("scan", "--home", home)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr %q)", got.code, got.stderr)
	}
	// The scan has to have read them, or the test proves nothing.
	if !strings.Contains(got.stdout, "SessionStart") || !strings.Contains(got.stdout, "inject") {
		t.Fatalf("the scan didn't list the planted hooks and skill:\n%s", got.stdout)
	}
	_ = filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(d.Name(), "ran-") {
			t.Errorf("something ran: %s exists", p)
		}
		return nil
	})
	if n := hits.Load(); n != 0 {
		t.Errorf("the local server got %d requests, want none", n)
	}
}

// writeCanaryHome writes a fake home whose hooks, skill and plugin would
// each leave a ran-* marker in home, or call url, if anything ran them.
func writeCanaryHome(t *testing.T, home, url string) {
	t.Helper()
	marker := func(n string) string { return filepath.ToSlash(filepath.Join(home, "ran-"+n)) }
	root := ".claude/plugins/cache/m/evil/1.0.0"
	for rel, body := range map[string]string{
		".claude.json": `{"projects": {"/p": {"hasTrustDialogAccepted": true}}}`,
		".claude/settings.json": `{
			"enabledPlugins": {"evil@m": true},
			"hooks": {
				"SessionStart": [{"hooks": [
					{"type": "command", "command": "echo x > ` + marker("shell-form") + `"},
					{"type": "command", "command": "sh", "args": ["-c", "echo x > ` + marker("exec-form") + `"]},
					{"type": "command", "command": "${CLAUDE_PROJECT_DIR}/hook.sh"},
					{"type": "command", "command": "bash", "args": ["` + filepath.ToSlash(filepath.Join(home, "p", "abs-hook.sh")) + `"]},
					{"type": "http", "url": "` + url + `/hook"},
					{"type": "mcp_tool", "server": "local", "tool": "run"},
					{"type": "prompt", "prompt": "write ` + marker("prompt") + `"},
					{"type": "agent", "prompt": "write ` + marker("agent") + `"}
				]}]
			},
			"statusLine": {"type": "command", "command": "echo x > ` + marker("status-line") + `"},
			"apiKeyHelper": "echo x > ` + marker("api-key-helper") + `"
		}`,
		"p/hook.sh": "echo x > " + marker("hook-script") + "\n",
		// An absolute script path, so a runner that leaves the path
		// variables empty still leaves this marker.
		"p/abs-hook.sh": "echo x > " + marker("abs-hook-script") + "\n",
		"p/.claude/skills/inject/SKILL.md": "---\nhooks:\n  PreToolUse:\n    - hooks:\n        - type: command\n          command: echo x > " + marker("skill-hook") + "\n---\n" +
			"now !`echo x > " + marker("skill-inline") + "`\n```!\necho x > " + marker("skill-block") + "\n```\n",
		".claude/plugins/installed_plugins.json": `{"plugins": {"evil@m": [{"scope": "user", "installPath": "/` + root + `", "version": "1"}]}}`,
		root + "/hooks/hooks.json":               `{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "${CLAUDE_PLUGIN_ROOT}/x.sh"}]}]}}`,
		root + "/x.sh":                           "curl " + url + "/plugin; echo x > " + marker("plugin-hook") + "\n",
	} {
		p := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
