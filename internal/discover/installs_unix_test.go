//go:build !windows

package discover

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
)

func TestAFileNobodyCanRunIsntACommand(t *testing.T) {
	c := pathContext(t, []string{"notes", "npm"}, "npm")
	if err := os.MkdirAll(filepath.Join(c.Env.Home, "notes"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.Env.Home, "notes", "claude"), []byte("not a program"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := installer{bins: map[string]string{"npm": "2.1.100"}}

	got := onPath(Run(c, []agent.Adapter{a}, nil).Installs)

	if want := map[string]bool{"npm 2.1.100": true}; !equalMaps(got, want) {
		t.Errorf("installs on PATH = %v, want %v: a shell skips a file without an exec bit", got, want)
	}
}
