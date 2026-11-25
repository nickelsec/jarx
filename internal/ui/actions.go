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
	Scans
	Reviews
}

// Scans is what the Scan and Changes pages do: scan again, keep the extra
// repos, and compare with an older snapshot.
type Scans interface {
	// Rescan starts a scan in the background. ErrBusy says one is running
	// already.
	Rescan() error
	// ScanState says whether a rescan is running, how many have finished,
	// whether the last one failed, and how a review is going.
	ScanState() ScanState
	// AddRepo saves an extra repo, as typed or picked. It returns one of
	// the ErrRepo errors when the path won't do.
	AddRepo(path string) error
	// RemoveRepo drops the saved repo at index i of Data().Repos.
	RemoveRepo(i int) error
	// Folders lists the folders in dir for the folder browser. It returns
	// one of the ErrRepo errors when dir won't do.
	Folders(dir string) (Folder, error)
	// ChangesSince diffs the current scan against an older snapshot, and
	// says when that one was taken.
	ChangesSince(id string) (time.Time, []snapshot.Change, error)
}

// Reviews is what the LLM review page and its settings do.
type Reviews interface {
	// SaveLLM checks and saves the LLM review's settings as typed, the way
	// jarx setup llm does. It returns one of the ErrLLM errors, or
	// ErrLooksLikeKey, when a field won't do.
	SaveLLM(f LLMForm) error
	// LLMOff turns the LLM review off.
	LLMOff() error
	// TestLLM sends the one fixed request jarx setup llm's test sends.
	TestLLM() error
	// Review starts sending the artifacts with these keys (llm.KeyOf) in
	// the background. ScanState's Review says how it's going.
	Review(keys []string) error
	// Skip skips the artifacts with these keys, or unskips them. A skip
	// lasts until the artifact changes.
	Skip(keys []string, skip bool) error
}

// LLMForm is the LLM settings as typed in Settings, not checked yet.
type LLMForm struct{ BaseURL, Model, KeyEnv, Parallel string }

// ReviewState is how a review sent from the dashboard is going. Finished
// counts the reviews that ended, so a page can tell one ended while it
// waited, and Stopped says why one ended early.
type ReviewState struct {
	Running  bool   `json:"running"`
	Done     int    `json:"done"`
	Total    int    `json:"total"`
	Waiting  int    `json:"waiting,omitempty"`
	Finished int    `json:"finished"`
	Stopped  string `json:"stopped,omitempty"` // a notice key, like review-rejected
	Note     string `json:"note,omitempty"`    // that notice's text, for the toast
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
	// Review is the LLM review sent from the dashboard, once there's been
	// one.
	Review *ReviewState `json:"review,omitempty"`
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

	ErrLLMOff        = errors.New("the llm review is off")
	ErrLLMURL        = errors.New("that base url won't do")
	ErrLLMModel      = errors.New("that model won't do")
	ErrLLMVar        = errors.New("that env var name won't do")
	ErrLLMParallel   = errors.New("parallel requests won't do")
	ErrLooksLikeKey  = errors.New("that looks like a key")
	ErrKeyNotSet     = errors.New("the key's env var isn't set")
	ErrKeyRejected   = errors.New("the endpoint rejected the key")
	ErrUnreachable   = errors.New("the endpoint can't be reached")
	ErrNothingToSend = errors.New("nothing to send")
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

	"llm-saved":       {Text: "Saved."},
	"llm-url":         {Text: "That base URL won't do. Use https, or http to this machine, with no user, password or query.", Bad: true},
	"llm-model":       {Text: "Add a model name, with no spaces.", Bad: true},
	"llm-var":         {Text: "An env var name is letters, digits and _, and doesn't start with a digit.", Bad: true},
	"llm-parallel":    {Text: "Parallel requests is a number from 1 to 16.", Bad: true},
	"llm-key":         {Text: "That looks like a key. jarx won't save one.", Bad: true},
	"llm-ok":          {Text: "Connected."},
	"llm-nokey":       {Text: "The key's env var isn't set in the terminal that started jarx ui.", Bad: true},
	"llm-rejected":    {Text: "The endpoint rejected the key.", Bad: true},
	"llm-unreachable": {Text: "Couldn't reach the endpoint.", Bad: true},
	msgLLMFailed:      {Text: "That didn't work.", Bad: true},
	"llm-off":         {Text: "LLM review is off."},

	"review-busy":     {Text: "A review is already running."},
	"review-nokey":    {Text: "The key's env var isn't set in the terminal that started jarx ui.", Bad: true},
	"review-none":     {Text: "Nothing is checked to send.", Bad: true},
	"review-off":      {Text: "The LLM review is off. Turn it on in Settings.", Bad: true},
	"review-failed":   {Text: "The review couldn't start.", Bad: true},
	"review-rejected": {Text: "Review stopped: the endpoint rejected the key.", Bad: true},
	"review-unreach":  {Text: "Review stopped: couldn't reach the endpoint.", Bad: true},
	"review-stopped":  {Text: "Review stopped early.", Bad: true},
	"skipped":         {Text: "Skipped."},
	"unskipped":       {Text: "Unskipped."},
	"skip-failed":     {Text: "Couldn't save that.", Bad: true},
	"save-failed":     {Text: "Couldn't save jarx's settings.", Bad: true},
}

// keyMsg is the query key a notice comes in.
const keyMsg = "msg"

// msgLLMFailed is the notice for an LLM settings action that didn't work.
const msgLLMFailed = "llm-failed"

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
		st := app.ScanState()
		if st.Review != nil && st.Review.Stopped != "" {
			r := *st.Review
			r.Note = notices[r.Stopped].Text
			st.Review = &r
		}
		_ = json.NewEncoder(w).Encode(st)
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

// llmSettings changes the LLM review's settings from Settings: save, test
// the connection, or turn it off.
func llmSettings(app App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		form(w, r)
		var msg string
		switch r.PostFormValue("action") {
		case "save":
			msg = llmMsg(app.SaveLLM(LLMForm{
				BaseURL: r.PostFormValue("url"), Model: r.PostFormValue("model"),
				KeyEnv: r.PostFormValue("keyenv"), Parallel: r.PostFormValue("parallel"),
			}), "llm-saved")
		case "test":
			msg = llmMsg(app.TestLLM(), "llm-ok")
		case "off":
			msg = llmMsg(app.LLMOff(), "llm-off")
		default:
			msg = msgLLMFailed
		}
		http.Redirect(w, r, "/settings?"+keyMsg+"="+msg, http.StatusSeeOther)
	}
}

// llmMsg is the notice for an LLM settings action's result.
func llmMsg(err error, ok string) string {
	for e, msg := range map[error]string{
		ErrLLMURL: "llm-url", ErrLLMModel: "llm-model", ErrLLMVar: "llm-var", ErrLLMParallel: "llm-parallel",
		ErrLooksLikeKey: "llm-key", ErrKeyNotSet: "llm-nokey", ErrKeyRejected: "llm-rejected", ErrUnreachable: "llm-unreachable",
	} {
		if errors.Is(err, e) {
			return msg
		}
	}
	if err != nil {
		return msgLLMFailed
	}
	return ok
}

// review starts the LLM review of the checked artifacts and goes back to
// the LLM page, which shows it running.
func review(app App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		form(w, r)
		back := "/llm"
		switch err := app.Review(r.PostForm["a"]); {
		case err == nil:
		case errors.Is(err, ErrBusy):
			back += "?" + keyMsg + "=review-busy"
		case errors.Is(err, ErrKeyNotSet):
			back += "?" + keyMsg + "=review-nokey"
		case errors.Is(err, ErrNothingToSend):
			back += "?" + keyMsg + "=review-none"
		case errors.Is(err, ErrLLMOff):
			back += "?" + keyMsg + "=review-off"
		default:
			back += "?" + keyMsg + "=review-failed"
		}
		http.Redirect(w, r, back, http.StatusSeeOther)
	}
}

// skip skips or unskips the checked artifacts.
func skip(app App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		form(w, r)
		on := r.PostFormValue("action") != "unskip"
		msg := "skipped"
		if !on {
			msg = "unskipped"
		}
		if err := app.Skip(r.PostForm["a"], on); err != nil {
			msg = "skip-failed"
		}
		http.Redirect(w, r, "/llm?"+keyMsg+"="+msg, http.StatusSeeOther)
	}
}
