package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/jarxdir"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/report"
)

const setupUsage = `usage: jarx setup [--home <dir>]
       jarx setup [--home <dir>] repo add|rm <path>

Shows jarx's own settings, or adds or removes an extra project path that
every scan includes. jarx only ever writes its own state dir.

flags:
  --home <dir>  use <dir> as the home dir instead of the real one
  -h, --help    show this help
`

func setupHelp(s *report.Stream) { s.Printf(setupUsage) }

func runSetup(p *report.Printer, plain *redact.Scrubber, args []string) int {
	home, rest, code, ok := parseSetup(p, plain, args)
	if !ok {
		return code
	}
	env, files, scrub, err := openEnv(home)
	if err != nil {
		p.Error(err)
		return exitError
	}
	defer func() { _ = files.Close() }()
	cfg, err := jarxdir.LoadConfig(env)
	if err != nil {
		p.Error(err)
		return exitError
	}

	if len(rest) == 0 {
		showSetup(p.Out, scrub, env, files, cfg)
		return exitOK
	}
	if err := changeRepos(p.Out, scrub, env, files, cfg, rest[1], rest[2]); err != nil {
		p.Error(err)
		return exitError
	}
	return exitOK
}

// parseSetup checks the flags and the topic. rest is empty (show settings)
// or exactly repo, add or rm, and a path. When ok is false, the caller
// returns code.
func parseSetup(p *report.Printer, plain *redact.Scrubber, args []string) (string, []string, int, bool) {
	fs := newFlagSet("setup")
	home := fs.String("home", "", "")
	if code, ok := parse(p, plain, fs, args, setupHelp); !ok {
		return "", nil, code, false
	}
	if emptyHome(fs, *home) {
		return "", nil, usageError(p, setupHelp, scrubbed(plain, "--home needs a directory")), false
	}
	rest := fs.Args()
	switch {
	case len(rest) == 0:
		return *home, rest, exitOK, true
	case rest[0] != "repo":
		return "", nil, usageError(p, setupHelp, scrubbed(plain, fmt.Sprintf("unknown setup topic %q", rest[0]))), false
	case len(rest) != 3 || (rest[1] != "add" && rest[1] != "rm"):
		return "", nil, usageError(p, setupHelp, scrubbed(plain, "want: setup repo add|rm <path>")), false
	}
	return *home, rest, exitOK, true
}

func changeRepos(out *report.Stream, s *redact.Scrubber, env platform.Env, files *fsys.FS, cfg jarxdir.Config, verb, arg string) error {
	path, err := filepath.Abs(arg)
	if err != nil {
		return fmt.Errorf("can't make %s absolute: %w", arg, err)
	}
	if verb == "add" {
		return addRepo(out, s, env, files, cfg, path)
	}
	return rmRepo(out, s, env, cfg, path)
}

func showSetup(out *report.Stream, s *redact.Scrubber, env platform.Env, files *fsys.FS, cfg jarxdir.Config) {
	stateStatus := pathStatus(files, env.StateDir)
	if stateStatus == statusMissing {
		stateStatus = "not created yet"
	}
	out.Printf("jarx settings\n")
	out.Printf("  %-12s %s  (%s)\n", scrubbed(s, "state dir"), scrubbed(s, env.StateDir), scrubbed(s, stateStatus))
	out.Printf("repos (%s)\n", scrubbed(s, strconv.Itoa(len(cfg.Repos))))
	for _, r := range cfg.Repos {
		out.Printf("  %s  (%s)\n", scrubbed(s, r), scrubbed(s, pathStatus(files, r)))
	}
	out.Printf("llm          not set up\n")
}

func addRepo(out *report.Stream, s *redact.Scrubber, env platform.Env, files *fsys.FS, cfg jarxdir.Config, path string) error {
	info, err := files.Stat(path)
	switch {
	case errors.Is(err, fsys.ErrOutsideHome):
		return fmt.Errorf("%s is outside the fake home", path)
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s doesn't exist", path)
	case err != nil:
		return fmt.Errorf("can't check %s", path)
	case !info.IsDir():
		return fmt.Errorf("%s isn't a directory", path)
	}
	if slices.ContainsFunc(cfg.Repos, func(r string) bool { return samePath(r, path, env.GOOS) }) {
		out.Printf("already saved %s\n", scrubbed(s, path))
		return nil
	}
	cfg.Repos = append(cfg.Repos, path)
	if err := save(env, cfg); err != nil {
		return err
	}
	out.Printf("added %s\n", scrubbed(s, path))
	return nil
}

func rmRepo(out *report.Stream, s *redact.Scrubber, env platform.Env, cfg jarxdir.Config, path string) error {
	i := slices.IndexFunc(cfg.Repos, func(r string) bool { return samePath(r, path, env.GOOS) })
	if i < 0 {
		return fmt.Errorf("%s isn't saved", path)
	}
	cfg.Repos = slices.Delete(cfg.Repos, i, i+1)
	if err := save(env, cfg); err != nil {
		return err
	}
	out.Printf("removed %s\n", scrubbed(s, path))
	return nil
}

func save(env platform.Env, cfg jarxdir.Config) error {
	d, err := jarxdir.Open(env)
	if err != nil {
		return fmt.Errorf("saving config: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.SaveConfig(cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}
	return nil
}

// samePath matches two paths the way the OS does: Windows ignores case.
func samePath(a, b, goos string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if goos == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
