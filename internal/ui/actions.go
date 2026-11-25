package ui

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nickelsec/jarx/internal/snapshot"
)

// App is what the pages show and what they can ask for. The pages only
// read through Data; every write goes through one of the other methods,
// behind the guard's cookie and cross-origin check.
type App interface {
	// Data is the scan to show.
	Data() Data
	// Rescan scans again and swaps in the result. ErrBusy says one is
	// running already.
	Rescan() error
	// AddRepo saves an extra repo, as typed in Settings. It returns one of
	// the ErrRepo errors when the path won't do.
	AddRepo(path string) error
	// RemoveRepo drops the saved repo at index i of Data().Repos.
	RemoveRepo(i int) error
	// ChangesSince diffs the current scan against an older snapshot, and
	// says when that one was taken.
	ChangesSince(id string) (time.Time, []snapshot.Change, error)
	// ScanState says whether a rescan is running, how many have finished,
	// and whether the last one failed.
	ScanState() ScanState
	// Folders lists the folders in dir, as typed or picked in Settings'
	// folder browser. It returns one of the ErrRepo errors when dir won't do.
	Folders(dir string) (Folder, error)
}

// ScanState is where the rescans are. Done counts the finished ones, so a
// page can tell one finished while it waited.
type ScanState struct {
	Running bool `json:"running"`
	Done    int  `json:"done"`
	Failed  bool `json:"failed"`
	// While one runs: the scan's steps in order, the one it's on, and that
	// step's count when it has one. Only jarx's own step names.
	Steps     []string `json:"steps,omitempty"`
	Step      string   `json:"step,omitempty"`
	StepDone  int      `json:"stepDone,omitempty"`
	StepTotal int      `json:"stepTotal,omitempty"`
}

// Folder is one folder in Settings' folder browser: its path, the one
// above it (empty at the top), and the folders in it.
type Folder struct {
	Path, Parent string
	Subs         []FolderEntry
	More         bool // there were more than the browser lists
}

// FolderEntry is a folder in a Folder.
type FolderEntry struct{ Name, Path string }

// Errors an App gives back, each with its own notice.
var (
	ErrBusy         = errors.New("a scan is running")
	ErrRepoRelative = errors.New("not a full path")
	ErrRepoMissing  = errors.New("no such folder")
	ErrRepoNotDir   = errors.New("not a folder")
	ErrRepoOutside  = errors.New("outside the fake home")
	ErrRepoSaved    = errors.New("already saved")
	ErrRepoNotSaved = errors.New("not saved")
)

// notice is the line a page shows after an action, picked by the msg query
// value. Only these fixed texts ever show, so the URL can't put words on
// the page.
type notice struct {
	Text string
	Bad  bool
}

//nolint:gochecknoglobals // fixed table, read only
var notices = map[string]notice{
	"rescan-busy":   {Text: "A scan is already running."},
	"rescan-failed": {Text: "The scan couldn't start.", Bad: true},
	"repo-added":    {Text: "Added."},
	"repo-saved":    {Text: "That folder is already in the list."},
	"repo-missing":  {Text: "That folder doesn't exist.", Bad: true},
	"repo-notdir":   {Text: "That's a file, not a folder.", Bad: true},
	"repo-outside":  {Text: "That folder is outside the fake home.", Bad: true},
	"repo-relative": {Text: "Use a full path, like ~/work/api.", Bad: true},
	"repo-removed":  {Text: "Removed."},
	msgNotSaved:     {Text: "That folder isn't in the list.", Bad: true},
	"save-failed":   {Text: "Couldn't save jarx's settings.", Bad: true},
}

// keyMsg is the query key a notice comes in.
const keyMsg = "msg"

// msgNotSaved is the notice for a repo that isn't in the list.
const msgNotSaved = "repo-notsaved"

// formLimit caps a form's body. The forms only hold a path or an index.
const formLimit = 16 << 10

func noticeOf(r *http.Request) *notice {
	if n, ok := notices[r.URL.Query().Get(keyMsg)]; ok {
		return &n
	}
	return nil
}

// here is the page's own URL without its notice, for a form to come back
// to.
func here(r *http.Request) string {
	q := r.URL.Query()
	q.Del(keyMsg)
	if enc := q.Encode(); enc != "" {
		return r.URL.Path + "?" + enc
	}
	return r.URL.Path
}

// backTo is where a form goes back to: a dashboard page given as a path,
// or the overview. Anything that could leave the dashboard, or land on a
// file, goes to the overview instead.
func backTo(s string) string {
	u, err := url.Parse(s)
	switch {
	case err != nil, s == "", u.Scheme != "", u.Host != "", u.Opaque != "",
		!strings.HasPrefix(u.Path, "/"), strings.HasPrefix(s, "//"),
		strings.Contains(s, `\`), strings.HasPrefix(u.Path, "/static/"):
		return "/"
	}
	q := u.Query()
	q.Del(keyMsg)
	if enc := q.Encode(); enc != "" {
		return u.Path + "?" + enc
	}
	return u.Path
}

// withMsg is back with a notice added.
func withMsg(back, msg string) string {
	u, err := url.Parse(back)
	if err != nil {
		return "/?" + keyMsg + "=" + msg
	}
	q := u.Query()
	q.Set(keyMsg, msg)
	u.RawQuery = q.Encode()
	return u.String()
}

func form(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, formLimit)
	_ = r.ParseForm() // a bad body reads as an empty form, which does nothing
}

func rescan(app App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		form(w, r)
		// The scan runs in the background: the page it lands on shows it
		// running, and says when it's done.
		back := backTo(r.PostFormValue("back"))
		switch err := app.Rescan(); {
		case errors.Is(err, ErrBusy):
			back = withMsg(back, "rescan-busy")
		case err != nil:
			back = withMsg(back, "rescan-failed")
		}
		http.Redirect(w, r, back, http.StatusSeeOther) //nolint:gosec // G710: backTo keeps it to a path on the dashboard, tested with absolute, //, backslash and javascript: values
	}
}

func repos(app App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		form(w, r)
		msg := msgNotSaved
		switch r.PostFormValue("action") {
		case "add":
			msg = repoMsg(app.AddRepo(strings.TrimSpace(r.PostFormValue("path"))), "repo-added")
		case "remove":
			if i, err := strconv.Atoi(r.PostFormValue("i")); err == nil {
				msg = repoMsg(app.RemoveRepo(i), "repo-removed")
			}
		}
		http.Redirect(w, r, "/scan?"+keyMsg+"="+msg, http.StatusSeeOther)
	}
}

// repoMsg is the notice for a repo change's result.
func repoMsg(err error, ok string) string {
	for e, msg := range map[error]string{
		ErrRepoSaved: "repo-saved", ErrRepoMissing: "repo-missing", ErrRepoNotDir: "repo-notdir",
		ErrRepoOutside: "repo-outside", ErrRepoRelative: "repo-relative", ErrRepoNotSaved: msgNotSaved,
	} {
		if errors.Is(err, e) {
			return msg
		}
	}
	if err != nil {
		return "save-failed"
	}
	return ok
}

// scanStatus answers a page that's waiting for a rescan to finish.
func scanStatus(app App) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(app.ScanState())
	}
}

// browseView is Settings' folder browser: the folder, links up and into
// its folders, or why it couldn't open.
type browseView struct {
	Folder     Folder
	ParentHref string
	Subs       []browseLink
	Failed     bool
}

type browseLink struct{ Name, Href string }

func browseHref(dir string) string {
	return "/scan?" + url.Values{keyBrowse: {dir}}.Encode()
}

// keyBrowse is the query key that opens the folder browser on a folder.
const keyBrowse = "browse"

func browseOf(app App, dir string) *browseView {
	f, err := app.Folders(dir)
	if err != nil {
		return &browseView{Failed: true, ParentHref: browseHref("~")}
	}
	b := &browseView{Folder: f}
	if f.Parent != "" {
		b.ParentHref = browseHref(f.Parent)
	}
	for _, s := range f.Subs {
		b.Subs = append(b.Subs, browseLink{Name: s.Name, Href: browseHref(s.Path)})
	}
	return b
}
