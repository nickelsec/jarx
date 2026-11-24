package perms

import (
	"path/filepath"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
)

func TestSandboxPathsResolveByTheirPrefix(t *testing.T) {
	f := newFixture(t)
	user := f.origin(model.AgentClaude, model.ScopeUser, f.userFile())
	proj := f.origin(model.AgentClaude, model.ScopeProject, f.projectFile())
	h := func(rel string) string { return filepath.Join(f.env.Home, filepath.FromSlash(rel)) }
	for name, tc := range map[string]struct {
		o       model.Origin
		pattern string
		path    string
		want    bool
	}{
		"home":                        {user, "~/.ssh", h(".ssh/id_rsa"), true},
		"absolute":                    {proj, "/etc/secrets", "/etc/secrets/x", true},
		"double slash":                {proj, "//etc/secrets", "/etc/secrets/x", true},
		"no prefix in a project file": {proj, "secrets", filepath.Join(f.proj, "secrets", "x"), true},
		"dot in a project file":       {proj, "./secrets", filepath.Join(f.proj, "secrets", "x"), true},
		"no prefix in a user file":    {user, "secrets", h(".claude/secrets/x"), true},
		"user file, not the project":  {user, "secrets", filepath.Join(f.proj, "secrets", "x"), false},
		"glob":                        {user, "~/**/.env", h("code/app/.env"), true},
	} {
		if got := SandboxPath(f.env, f.proj, tc.o, tc.pattern)(tc.path); got != tc.want {
			t.Errorf("%s: SandboxPath(%s)(%s) = %v, want %v", name, tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestClaudePathIsTheRuleMatcher(t *testing.T) {
	f := newFixture(t)
	user := f.origin(model.AgentClaude, model.ScopeUser, f.userFile())
	if !ClaudePath(f.env, f.proj, user, "~/.aws/**")(filepath.Join(f.env.Home, ".aws", "credentials")) {
		t.Error("ClaudePath(~/.aws/**) doesn't cover ~/.aws/credentials")
	}
}
