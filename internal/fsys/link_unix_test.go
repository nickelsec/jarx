//go:build !windows

package fsys

import (
	"os"
	"testing"
)

// makeLink creates a symlink. On unix that never looks at the target.
func makeLink(t *testing.T, target, link string, _ bool) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("can't make symlinks here: %v", err)
	}
}
