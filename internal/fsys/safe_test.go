package fsys

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNetworkPaths(t *testing.T) {
	for _, tc := range []struct {
		goos, path string
		want       bool
	}{
		{"windows", `\\host\share\CLAUDE.md`, true},
		{"windows", `//host/share/CLAUDE.md`, true},
		{"windows", `\\?\UNC\host\share\x`, true},
		{"windows", `\\.\pipe\x`, true}, // device namespace, not a file
		{"windows", `\\?\GLOBALROOT\Device\x`, true},
		{"windows", `\\wsl$\Ubuntu\home\x`, false}, // the docs say \\wsl$ isn't a network path
		{"windows", `\\wsl.localhost\Ubuntu\x`, false},
		{"windows", `\\?\C:\work\x`, false},
		{"windows", `C:\work\x`, false},
		{"linux", "/net/host/share/x", true},
		{"linux", "/net", true},
		{"linux", "/network/x", false},
		{"linux", "/home/me/x", false},
		{"linux", `\\host\share`, false}, // just an odd file name on unix
		{"darwin", "/Network/Servers/x", true},
		{"darwin", "/net/host/x", true},
		{"darwin", "/Users/me/x", false},
	} {
		if got := networkPath(tc.goos, tc.path); got != tc.want {
			t.Errorf("networkPath(%s, %q) = %v, want %v", tc.goos, tc.path, got, tc.want)
		}
	}
}

func TestRealMachineRefusesNetworkPaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("UNC paths are a Windows thing")
	}
	// 192.0.2.0/24 is TEST-NET-1 and never routed, so even a broken check
	// can't reach a real host.
	f := &FS{}
	for _, p := range []string{`\\192.0.2.1\share\CLAUDE.md`, `\\?\UNC\192.0.2.1\share\x`} {
		if _, err := f.ReadFile(p); !errors.Is(err, ErrNetworkPath) {
			t.Errorf("ReadFile(%q) error = %v, want ErrNetworkPath", p, err)
		}
		if _, err := f.Stat(p); !errors.Is(err, ErrNetworkPath) {
			t.Errorf("Stat(%q) error = %v, want ErrNetworkPath", p, err)
		}
	}
}

func TestSymlinksToNetworkPathsAreRefused(t *testing.T) {
	target := "/net/192.0.2.1/share"
	if runtime.GOOS == "windows" {
		target = `\\192.0.2.1\share`
	}
	dir := t.TempDir()
	fileLink := filepath.Join(dir, "CLAUDE.md")
	dirLink := filepath.Join(dir, "linked")
	for _, l := range []struct {
		link, to string
		dir      bool
	}{{fileLink, target + "/CLAUDE.md", false}, {dirLink, target, true}} {
		makeLink(t, filepath.FromSlash(l.to), l.link, l.dir)
	}
	f := &FS{}

	for _, p := range []string{fileLink, filepath.Join(dirLink, "CLAUDE.md")} {
		if _, err := f.ReadFile(p); !errors.Is(err, ErrNetworkPath) {
			t.Errorf("ReadFile(%q) error = %v, want ErrNetworkPath", p, err)
		}
	}
}

func TestSymlinkChainsToLocalFilesStillRead(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.md")
	write(t, target, []byte("hi"))
	mid := filepath.Join(dir, "mid.md")
	link := filepath.Join(dir, "CLAUDE.md")
	if err := os.Symlink(target, mid); err != nil {
		t.Skipf("can't make symlinks here: %v", err)
	}
	if err := os.Symlink("mid.md", link); err != nil {
		t.Fatal(err)
	}

	got, err := (&FS{}).ReadFile(link)

	if err != nil || string(got) != "hi" {
		t.Errorf("ReadFile() = %q, %v; want the linked file", got, err)
	}
}

func TestReadFileRefusesDirs(t *testing.T) {
	f, home := fakeFS(t)
	dir := filepath.Join(home, "CLAUDE.md")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	for name, fs := range map[string]*FS{"fake home": f, "real machine": {}} {
		if _, err := fs.ReadFile(dir); !errors.Is(err, ErrNotRegular) {
			t.Errorf("%s: ReadFile(dir) error = %v, want ErrNotRegular", name, err)
		}
		if _, err := fs.Open(dir); !errors.Is(err, ErrNotRegular) {
			t.Errorf("%s: Open(dir) error = %v, want ErrNotRegular", name, err)
		}
	}
}
