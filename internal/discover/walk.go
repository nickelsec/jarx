package discover

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
)

// Limits for listing one project.
const (
	maxFiles       = 200_000          // files listed per project; past it the walk stops with a finding
	maxGitOutput   = 64 << 20         // bytes of ls-files output
	gitWalkTimeout = 10 * time.Second // per project
	scanBufSize    = 64 << 10
)

type walked struct {
	files     []string // slash-separated, relative to the project
	method    model.WalkMethod
	truncated bool
}

// walkRepo lists what the agent can see in root: hardened git ls-files when
// git is on PATH and the dir is a repo, jarx's own walk otherwise. Both apply
// the skip list, which keeps agent files.
func walkRepo(ctx context.Context, c agent.Context, root string, limit int) walked {
	if bin, ok := findGit(c); ok {
		if files, truncated, err := gitLsFiles(ctx, c, bin, root, limit); err == nil {
			return walked{files: files, method: model.WalkGit, truncated: truncated}
		}
	}
	files, truncated := fallbackWalk(c.Files, root, limit)
	return walked{files: files, method: model.WalkFallback, truncated: truncated}
}

// findGit looks for git on the Env's PATH, through fsys. Under --home it
// never finds one: the demo and tests never run a binary from a fake PATH.
func findGit(c agent.Context) (string, bool) {
	if c.Env.Fake() {
		return "", false
	}
	name := "git"
	if c.Env.GOOS == goosWindows {
		name = "git.exe"
	}
	for _, dir := range c.Env.Path {
		bin := filepath.Join(dir, name)
		info, err := c.Files.Stat(bin)
		if err != nil || info.IsDir() {
			continue
		}
		if c.Env.GOOS != goosWindows && info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return bin, true
	}
	return "", false
}

// gitArgs is the exact command line. The -c flags beat anything in the
// repo's own config (including files it pulls in with include.path):
//
//   - core.fsmonitor, core.useBuiltinFSMonitor: a plain ls-files runs the
//     configured fsmonitor command, or starts the fsmonitor daemon
//   - core.untrackedCache, core.hooksPath: no index write, and no hook to
//     run even if one happened
//   - core.excludesFile: no reading an arbitrary file named by the repo
//   - safe.bareRepository=explicit: the dir itself can't act as a git dir
//   - --work-tree: core.worktree can't point the listing at another dir
//   - --no-pager: never run a pager (git only pages to a terminal anyway)
//
// ls-files without -m, -s or --eol never reads file content, so filter,
// diff and textconv drivers never run.
func gitArgs(root string) []string {
	return []string{
		"--no-pager",
		"--work-tree=" + root,
		"-c", "core.fsmonitor=false",
		"-c", "core.useBuiltinFSMonitor=false",
		"-c", "core.untrackedCache=false",
		"-c", "core.hooksPath=" + os.DevNull,
		"-c", "core.excludesFile=" + os.DevNull,
		"-c", "safe.bareRepository=explicit",
		"ls-files", "-z", "--cached", "--others", "--exclude-standard",
	}
}

// gitEnv is built from scratch: nothing from jarx's own environment comes
// along, so GIT_DIR, GIT_TRACE, GIT_EXEC_PATH and the like can't get in.
// System and global git config are off, and git can't climb past root to a
// parent repo.
func gitEnv(c agent.Context, root string) []string {
	env := []string{
		"PATH=" + strings.Join(c.Env.Path, string(os.PathListSeparator)),
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CEILING_DIRECTORIES=" + filepath.Dir(root),
		"LC_ALL=C",
	}
	if c.Env.GOOS == goosWindows {
		if root, ok := c.Env.Lookup("SystemRoot"); ok {
			env = append(env, "SystemRoot="+root)
		}
	}
	return env
}

var errTooMuchOutput = errors.New("git output over the limit")

// gitLsFiles runs hardened ls-files in root. Any failure (not a repo, git
// refusing, a timeout, output that isn't plain paths inside root) is an
// error, and the caller falls back to its own walk.
func gitLsFiles(ctx context.Context, c agent.Context, bin, root string, limit int) ([]string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, gitWalkTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, gitArgs(root)...) //nolint:gosec // G204: bin is git found on PATH, args are fixed
	cmd.Dir = root
	cmd.Env = gitEnv(c, root)
	cmd.Stdin = nil
	cmd.Stderr = io.Discard // can quote config values; never shown
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false, fmt.Errorf("git: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, false, fmt.Errorf("git: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(out, maxGitOutput+1))
	if len(data) > maxGitOutput {
		readErr = errTooMuchOutput
		cancel()
	}
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, false, readErr
	}
	if waitErr != nil {
		return nil, false, fmt.Errorf("git: %w", waitErr)
	}
	files, err := parseLsFiles(data)
	if err != nil {
		return nil, false, err
	}
	kept := make([]string, 0, min(len(files), limit))
	for _, f := range files {
		if fsys.Skipped(f) {
			continue
		}
		if len(kept) == limit {
			return kept, true, nil
		}
		kept = append(kept, f)
	}
	return kept, false, nil
}

// parseLsFiles splits ls-files -z output and checks every entry is a plain
// relative path inside the repo. One bad entry throws the whole output away.
func parseLsFiles(data []byte) ([]string, error) {
	var files []string
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Buffer(make([]byte, 0, scanBufSize), maxGitOutput)
	s.Split(splitNUL)
	for s.Scan() {
		f := s.Text()
		if !filepath.IsLocal(filepath.FromSlash(f)) || strings.Contains(f, ":") {
			return nil, fmt.Errorf("git listed %q, which isn't a path inside the repo", f)
		}
		files = append(files, f)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("reading git output: %w", err)
	}
	return files, nil
}

func splitNUL(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

var errStop = errors.New("stop")

// fallbackWalk lists files with fsys, which applies the skip list and never
// follows symlinked dirs.
func fallbackWalk(files *fsys.FS, root string, limit int) ([]string, bool) {
	var out []string
	truncated := false
	_ = files.Walk(root, func(path string, _ fs.DirEntry) error {
		if len(out) == limit {
			truncated = true
			return errStop
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil //nolint:nilerr // a path that isn't under root is skipped
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	return out, truncated
}
