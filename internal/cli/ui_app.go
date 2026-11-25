package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/jarxdir"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/report"
	"github.com/nickelsec/jarx/internal/snapshot"
	"github.com/nickelsec/jarx/internal/ui"
)

// uiApp is what the dashboard shows and does: the last scan, a rescan, the
// saved repos, and comparing with an older snapshot. The only things it
// writes are jarx's own: the snapshot, the run log and config.json.
type uiApp struct {
	mu       sync.RWMutex // guards d, ss.cfg, state and since
	d        ui.Data
	ss       scanSetup
	st       streams
	state    ui.ScanState
	since    map[string]comparison // worked out once per snapshot, until the next scan
	quiet    *report.Printer       // a rescan's progress goes nowhere: the terminal only shows the link
	scanning sync.Mutex            // held while a rescan runs
}

// comparison is the current scan diffed against an older snapshot.
type comparison struct {
	taken   time.Time
	changes []snapshot.Change
}

// browseLimit is how many folders the folder browser lists.
const browseLimit = 300

// newUIApp runs the first scan, with its progress line in the terminal.
func newUIApp(p *report.Printer, ss scanSetup, st streams) (*uiApp, error) {
	d, err := uiData(p, ss, st)
	if err != nil {
		return nil, err
	}
	a := &uiApp{d: d, ss: ss, st: st, quiet: report.New(io.Discard, io.Discard, ss.scrub)}
	a.quiet.Watch = a.watch
	return a, nil
}

func (a *uiApp) Data() ui.Data {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.d
}

// Rescan starts a scan in the background with the saved repos as they are
// now. The pages keep showing the last scan and say one is running, and
// ScanState says when it's done. One runs at a time.
func (a *uiApp) Rescan() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.Running {
		return ui.ErrBusy
	}
	a.state = ui.ScanState{Running: true, Done: a.state.Done, Steps: scanSteps}
	go a.rescan(a.ss)
	return nil
}

// ScanState says whether a rescan is running and how the last one went.
func (a *uiApp) ScanState() ui.ScanState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.state
}

// AddRepo saves a folder typed in Settings. It has to be a full path or
// start with ~, and be a folder jarx can see.
func (a *uiApp) AddRepo(typed string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	path, err := fullPath(a.ss.env, typed)
	if err != nil {
		return err
	}
	if err := checkRepo(a.ss.files, path); err != nil {
		return err
	}
	if slices.ContainsFunc(a.ss.cfg.Repos, func(r string) bool { return samePath(r, path, a.ss.env.GOOS) }) {
		return ui.ErrRepoSaved
	}
	cfg := a.ss.cfg
	cfg.Repos = append(slices.Clone(cfg.Repos), path)
	return a.saveRepos(cfg)
}

// RemoveRepo drops the saved repo at index i, as Settings lists them.
func (a *uiApp) RemoveRepo(i int) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if i < 0 || i >= len(a.ss.cfg.Repos) {
		return ui.ErrRepoNotSaved
	}
	cfg := a.ss.cfg
	cfg.Repos = slices.Delete(slices.Clone(cfg.Repos), i, i+1)
	return a.saveRepos(cfg)
}

// ChangesSince diffs the newest snapshot, which is the scan on show,
// against the older one with this ID. Snapshots don't change once saved,
// so each comparison is worked out once and kept until the next scan.
func (a *uiApp) ChangesSince(id string) (time.Time, []snapshot.Change, error) {
	a.mu.RLock()
	c, ok := a.since[id]
	a.mu.RUnlock()
	if ok {
		return c.taken, c.changes, nil
	}
	c, err := compare(a.ss.env, a.ss.scrub, id)
	if err != nil {
		return time.Time{}, nil, err
	}
	a.mu.Lock()
	if a.since == nil {
		a.since = map[string]comparison{}
	}
	a.since[id] = c
	a.mu.Unlock()
	return c.taken, c.changes, nil
}

// Folders lists the folders in dir for the folder browser: folder names
// only, never files, and no dot-folders. With --home it stays inside the
// fake home.
func (a *uiApp) Folders(dir string) (ui.Folder, error) {
	env, files := a.ss.env, a.ss.files
	path, err := fullPath(env, dir)
	if err != nil {
		return ui.Folder{}, err
	}
	if err := checkRepo(files, path); err != nil {
		return ui.Folder{}, err
	}
	entries, err := files.ReadDir(path)
	if err != nil {
		return ui.Folder{}, ui.ErrRepoMissing
	}
	f := ui.Folder{Path: a.shown(path)}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if len(f.Subs) == browseLimit {
			f.More = true
			break
		}
		f.Subs = append(f.Subs, ui.FolderEntry{Name: e.Name(), Path: a.shown(filepath.Join(path, e.Name()))})
	}
	slices.SortFunc(f.Subs, func(x, y ui.FolderEntry) int {
		return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name))
	})
	if parent := filepath.Dir(path); parent != path && checkRepo(files, parent) == nil {
		f.Parent = a.shown(parent)
	}
	return f, nil
}

// watch hears a rescan's progress: which step and how far along.
func (a *uiApp) watch(step string, done, total int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.Running {
		a.state.Step, a.state.StepDone, a.state.StepTotal = step, done, total
	}
}

// rescan runs one scan in the background and swaps the result in.
func (a *uiApp) rescan(ss scanSetup) {
	a.scanning.Lock()
	defer a.scanning.Unlock()
	d, err := uiData(a.quiet, ss, a.st)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err == nil {
		d.Repos = a.d.Repos // the list as it is now, if one was added or removed meanwhile
		a.d, a.since = d, nil
	}
	a.state = ui.ScanState{Done: a.state.Done + 1, Failed: err != nil}
}

// shown is a path as the folder browser shows and sends it back: from ~
// inside the home dir, masked like every path on the page.
func (a *uiApp) shown(path string) string {
	home := a.ss.env.Home
	if rel, err := filepath.Rel(home, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		if rel == "." {
			path = "~"
		} else {
			path = "~/" + filepath.ToSlash(rel)
		}
	}
	return scrubbed(a.ss.scrub, path).String()
}

// compare diffs the newest snapshot against the older one with this ID.
func compare(env platform.Env, scrub *redact.Scrubber, id string) (comparison, error) {
	d, err := jarxdir.Open(env)
	if err != nil {
		return comparison{}, fmt.Errorf("state dir: %w", err)
	}
	defer func() { _ = d.Close() }()
	older, err := snapshot.Load(d, scrub, id)
	if err != nil {
		return comparison{}, err //nolint:wrapcheck // ErrNoSnapshot is checked by the pages
	}
	cur, note, err := snapshot.Latest(d, scrub)
	if err != nil || note != "" {
		return comparison{}, errors.Join(err, errors.New("couldn't read the newest snapshot")) //nolint:err113 // a one-off
	}
	return comparison{taken: older.Taken, changes: snapshot.Diff(scrub, older, cur)}, nil
}

// saveRepos writes cfg and shows its repos. The caller holds mu.
func (a *uiApp) saveRepos(cfg jarxdir.Config) error {
	if err := save(a.ss.env, cfg); err != nil {
		return err
	}
	a.ss.cfg = cfg
	a.d.Repos = a.d.Repos[:0:0]
	for _, r := range cfg.Repos {
		a.d.Repos = append(a.d.Repos, scrubbed(a.ss.scrub, r))
	}
	return nil
}

// olderSnapshots is the saved snapshots but the newest, which is this
// scan's own, for Changes to compare against.
func olderSnapshots(env platform.Env) []snapshot.Info {
	d, err := jarxdir.Open(env)
	if err != nil {
		return nil
	}
	defer func() { _ = d.Close() }()
	list, err := snapshot.List(d)
	if err != nil || len(list) < 2 { // this scan and at least one before it
		return nil
	}
	return list[1:]
}

// fullPath turns a folder typed in Settings into an absolute path. ~ is
// the home dir (the fake one with --home). Anything else has to be
// absolute already: the dashboard has no working dir to be relative to.
func fullPath(env platform.Env, typed string) (string, error) {
	typed = strings.TrimSpace(typed)
	switch {
	case typed == "~":
		typed = env.Home
	case strings.HasPrefix(typed, "~/"), strings.HasPrefix(typed, `~\`):
		typed = filepath.Join(env.Home, typed[2:])
	}
	if typed == "" || !filepath.IsAbs(typed) {
		return "", ui.ErrRepoRelative
	}
	return filepath.Clean(typed), nil
}

// checkRepo says whether path is a folder jarx can see, the same check for
// jarx setup repo add and the dashboard.
func checkRepo(files *fsys.FS, path string) error {
	info, err := files.Stat(path)
	switch {
	case errors.Is(err, fsys.ErrOutsideHome):
		return ui.ErrRepoOutside
	case errors.Is(err, fs.ErrNotExist):
		return ui.ErrRepoMissing
	case err != nil:
		return errRepoCheck
	case !info.IsDir():
		return ui.ErrRepoNotDir
	}
	return nil
}

// errRepoCheck is a folder jarx couldn't look at, for a reason other than
// it not being there.
var errRepoCheck = errors.New("can't check it")
