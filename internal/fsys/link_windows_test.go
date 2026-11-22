package fsys

import (
	"testing"

	"golang.org/x/sys/windows"
)

// makeLink creates a symlink without looking at its target. os.Symlink stats
// the target on Windows to pick a file or dir link, which for a network
// target means waiting on a connection in test setup.
func makeLink(t *testing.T, target, link string, dir bool) {
	t.Helper()
	from, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	flags := uint32(allowUnprivilegedCreate)
	if dir {
		flags |= windows.SYMBOLIC_LINK_FLAG_DIRECTORY
	}
	if err := windows.CreateSymbolicLink(from, to, flags); err != nil {
		t.Skipf("can't make symlinks here: %v", err)
	}
}

// allowUnprivilegedCreate is SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
// which lets Developer Mode make links without admin. x/sys doesn't name it.
const allowUnprivilegedCreate = 0x2
