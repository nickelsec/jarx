// Package proc starts an MCP stdio server so that killing it kills
// everything it started too. On Windows the server starts suspended, goes
// into a job object that kills its whole tree when closed, and only then
// resumes. On unix it gets its own process group, and a kill goes to the
// group. See "Windows process trees" in docs/design.md.
//
// proc only starts what probe hands it, with exactly the env it's given.
// It's one of two packages allowed to run a process; discover is the other.
package proc

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// StderrCap is how much of a server's stderr is kept.
const StderrCap = 64 << 10

// waitDelay is how long Wait lets output pipes drain after the server exits,
// so a grandchild holding them open can't stall it.
const waitDelay = 2 * time.Second

// Errors Start and Find return.
var (
	ErrBatchArgs = errors.New("refusing to pass arguments with cmd.exe metacharacters to a .bat or .cmd file")
	ErrFakeHome  = errors.New("not run under --home: the demo and tests never start a program from a fake PATH")
	ErrNotFound  = errors.New("not found on PATH")
)

// Spec is what to start: an absolute program path, its args, the working
// dir and the whole env. Nothing else from jarx's env goes along.
type Spec struct {
	Path string
	Args []string
	Dir  string
	Env  []string
}

// Process is a running server and everything it started.
type Process struct {
	Stdin  io.WriteCloser
	Stdout io.ReadCloser

	cmd      *exec.Cmd
	tree     *tree
	stderr   *capBuffer
	done     chan struct{}
	exitCode int
	killOnce sync.Once
	killErr  error
}

// Start starts the server. A .bat or .cmd file with an argument cmd.exe
// would read as syntax is refused before anything runs.
func Start(s Spec) (*Process, error) {
	if err := checkBatchArgs(s.Path, s.Args); err != nil {
		return nil, err
	}
	cmd := exec.Command(s.Path, s.Args...) //nolint:gosec,noctx // G204: probe passes the command the agent would run; the tree is killed through Kill, not a context
	cmd.Dir = s.Dir
	cmd.Env = append([]string{}, s.Env...) // never nil: nil would hand the server jarx's whole env
	cmd.WaitDelay = waitDelay
	p := &Process{cmd: cmd, stderr: &capBuffer{limit: StderrCap}, done: make(chan struct{}), exitCode: -1}
	cmd.Stderr = p.stderr
	var err error
	if p.Stdin, err = cmd.StdinPipe(); err != nil {
		return nil, fmt.Errorf("proc: stdin: %w", err)
	}
	if p.Stdout, err = cmd.StdoutPipe(); err != nil {
		return nil, fmt.Errorf("proc: stdout: %w", err)
	}
	if p.tree, err = startTree(cmd); err != nil {
		return nil, fmt.Errorf("proc: start: %w", err)
	}
	go func() {
		_ = cmd.Wait()
		p.exitCode = cmd.ProcessState.ExitCode()
		close(p.done)
	}()
	return p, nil
}

// Done is closed once the server itself has exited.
func (p *Process) Done() <-chan struct{} { return p.done }

// ExitCode is the server's exit code, or -1 while it runs or when it was
// killed.
func (p *Process) ExitCode() int {
	select {
	case <-p.done:
		return p.exitCode
	default:
		return -1
	}
}

// Stderr is what the server wrote to stderr, up to StderrCap. It's raw:
// the caller masks it before it goes anywhere.
func (p *Process) Stderr() []byte { return p.stderr.bytes() }

// Kill kills the server and everything it started, then waits for the
// server to be gone. Calling it again does nothing.
func (p *Process) Kill() error {
	p.killOnce.Do(func() {
		p.killErr = p.tree.kill()
		select {
		case <-p.done:
		case <-time.After(waitDelay + time.Second):
			p.killErr = errors.Join(p.killErr, errors.New("proc: the server didn't exit after the kill"))
		}
	})
	return p.killErr
}

// batchChars are what cmd.exe reads as syntax in a .bat or .cmd file's
// command line. Go quotes arguments for CreateProcess, not for cmd.exe, so
// any of these could make cmd run something the config never named.
const batchChars = "&|<>^%!\"()\r\n"

// checkBatchArgs refuses cmd.exe syntax in the args of a .bat or .cmd file.
func checkBatchArgs(path string, args []string) error {
	if ext := strings.ToLower(filepath.Ext(path)); ext != ".bat" && ext != ".cmd" {
		return nil
	}
	for _, a := range args {
		if strings.ContainsAny(a, batchChars) {
			return ErrBatchArgs
		}
	}
	return nil
}

// capBuffer keeps the first limit bytes written to it and drops the rest.
type capBuffer struct {
	mu    sync.Mutex
	limit int
	buf   []byte
}

func (c *capBuffer) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.limit - len(c.buf); room > 0 {
		c.buf = append(c.buf, b[:min(room, len(b))]...)
	}
	return len(b), nil
}

func (c *capBuffer) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}
