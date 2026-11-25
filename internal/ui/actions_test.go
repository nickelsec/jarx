package ui

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nickelsec/jarx/internal/snapshot"
)

// fakeApp is an App that records what the pages asked it to do.
type fakeApp struct {
	d         Data
	rescans   int
	rescanErr error
	added     []string
	addErr    error
	removed   []int
	removeErr error
	since     map[string][]snapshot.Change
	state     ScanState
	folders   map[string]Folder
	llm       LLMForm
	llmErr    error
	reviewed  []string
	reviewErr error
	skipped   []string
	skipOn    bool
	skipErr   error
}

func (a *fakeApp) SaveLLM(f LLMForm) error { a.llm = f; return a.llmErr }

func (a *fakeApp) LLMOff() error { return a.llmErr }

func (a *fakeApp) TestLLM() error { return a.llmErr }

func (a *fakeApp) Review(keys []string) error { a.reviewed = keys; return a.reviewErr }

func (a *fakeApp) Skip(keys []string, skip bool) error {
	a.skipped, a.skipOn = keys, skip
	return a.skipErr
}

func (a *fakeApp) Data() Data { return a.d }

func (a *fakeApp) Rescan() error { a.rescans++; return a.rescanErr }

func (a *fakeApp) AddRepo(path string) error { a.added = append(a.added, path); return a.addErr }

func (a *fakeApp) RemoveRepo(i int) error { a.removed = append(a.removed, i); return a.removeErr }

func (a *fakeApp) ScanState() ScanState { return a.state }

func (a *fakeApp) Folders(dir string) (Folder, error) {
	f, ok := a.folders[dir]
	if !ok {
		return Folder{}, ErrRepoMissing
	}
	return f, nil
}

func (a *fakeApp) ChangesSince(id string) (time.Time, []snapshot.Change, error) {
	c, ok := a.since[id]
	if !ok {
		return time.Time{}, nil, snapshot.ErrNoSnapshot
	}
	return time.Date(2026, 11, 24, 18, 30, 0, 0, time.UTC), c, nil
}

// sent is what the pages answered a form with.
type sent struct {
	StatusCode int
	Location   string
}

// post sends a form to the pages, as the browser would after the guard let
// it through.
func post(t *testing.T, a App, target string, form url.Values) sent {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	Pages(a).ServeHTTP(rec, req)
	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()
	return sent{StatusCode: resp.StatusCode, Location: resp.Header.Get("Location")}
}

func TestRescanStartsAScanAndGoesBack(t *testing.T) {
	a := &fakeApp{d: newFixture(t).data()}

	resp := post(t, a, "/rescan", url.Values{"back": {"/projects/0?sev=high"}})

	if a.rescans != 1 || resp.StatusCode != http.StatusSeeOther || resp.Location != "/projects/0?sev=high" {
		t.Errorf("rescans %d, %d to %q; want one scan started and a 303 back", a.rescans, resp.StatusCode, resp.Location)
	}
}

func TestRescanOnlyGoesBackToADashboardPage(t *testing.T) {
	for _, back := range []string{"", "https://evil.example/", "//evil.example/x", `/\evil.example`, "javascript:alert(1)", "/static/app.js"} {
		a := &fakeApp{d: newFixture(t).data()}

		resp := post(t, a, "/rescan", url.Values{"back": {back}})

		if got := resp.Location; got != "/" {
			t.Errorf("back %q: went to %q, want the overview", back, got)
		}
	}
}

func TestAFailedOrBusyRescanSaysSo(t *testing.T) {
	for err, msg := range map[error]string{ErrBusy: "rescan-busy", errors.New("disk on fire"): "rescan-failed"} {
		a := &fakeApp{d: newFixture(t).data(), rescanErr: err}

		resp := post(t, a, "/rescan", url.Values{"back": {"/"}})

		if got := resp.Location; got != "/?msg="+msg {
			t.Errorf("%v: went to %q, want msg=%s", err, got, msg)
		}
	}
}

func TestAGetCantRescan(t *testing.T) {
	a := &fakeApp{d: newFixture(t).data()}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/rescan", http.NoBody)
	rec := httptest.NewRecorder()

	Pages(a).ServeHTTP(rec, req)

	if a.rescans != 0 || rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /rescan = %d after %d scans, want 405 and none", rec.Code, a.rescans)
	}
}

func TestACrossSiteRescanNeverReachesTheApp(t *testing.T) {
	a := &fakeApp{d: newFixture(t).data()}
	token := NewToken()
	h := Protect(Pages(a), token, port)
	c := session(t, h, token)

	resp := do(h, http.MethodPost, "/rescan", func(r *http.Request) {
		r.AddCookie(c)
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	})

	if resp.StatusCode != http.StatusForbidden || a.rescans != 0 {
		t.Errorf("cross-site rescan = %d after %d scans, want 403 and none", resp.StatusCode, a.rescans)
	}
}

func TestANoticeIsAToastForAKnownMessageOnly(t *testing.T) {
	d := newFixture(t).data()

	_, known, _ := get(t, d, "/scan?msg=repo-added")
	_, bad, _ := get(t, d, "/scan?msg=repo-missing")
	_, unknown, _ := get(t, d, "/?msg=%3Cb%3Ehi%3C%2Fb%3E")

	if !order(known, `<div class="toast" role="status">`, `<span class="toast-text">Added.</span>`, `<button type="button" class="toast-x" aria-label="Dismiss">`) {
		t.Error("a known message shows no toast with a dismiss button")
	}
	if !strings.Contains(bad, `<div class="toast bad" role="status">`) {
		t.Error("a problem isn't marked as one")
	}
	if strings.Contains(unknown, `class="toast`) || strings.Contains(unknown, "hi</b>") {
		t.Error("an unknown message shows something")
	}
}

func TestEveryPageShowsARunningScan(t *testing.T) {
	a := &fakeApp{d: newFixture(t).data(), state: ScanState{Running: true, Done: 2}}
	for _, page := range []string{"/", "/scan", "/changes", "/settings", "/llm", "/projects/0"} {
		body := getApp(t, a, page)

		if !strings.Contains(body, `<span hidden data-scan="running" data-done="2"></span>`) {
			t.Errorf("%s doesn't say a scan is running", page)
		}
	}
	if body := getApp(t, a, "/scan"); !strings.Contains(body, `<button type="submit" class="btn primary busy" disabled>`) || !strings.Contains(body, "<span>Scanning…</span>") {
		t.Error("the rescan button doesn't show the scan running")
	}
	idle := &fakeApp{d: newFixture(t).data()}
	if strings.Contains(getApp(t, idle, "/"), "data-scan=") {
		t.Error("a page says a scan is running when none is")
	}
}

func TestTheScanStateIsJSON(t *testing.T) {
	a := &fakeApp{d: newFixture(t).data(), state: ScanState{Running: false, Done: 3, Failed: true}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/rescan/status", http.NoBody)
	rec := httptest.NewRecorder()

	Pages(a).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" || strings.TrimSpace(rec.Body.String()) != `{"running":false,"done":3,"failed":true}` {
		t.Errorf("GET /rescan/status = %d %q %q", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
}

func TestTheScanPageCanBrowseForAFolder(t *testing.T) {
	a := &fakeApp{d: newFixture(t).data(), folders: map[string]Folder{
		"~/work": {Path: "~/work", Parent: "~", Subs: []FolderEntry{{Name: "api", Path: "~/work/api"}}},
	}}

	plain := getApp(t, a, "/scan")
	browsing := getApp(t, a, "/scan?browse=~/work")
	missing := getApp(t, a, "/scan?browse=~/nope")

	if !strings.Contains(plain, `<a class="btn" href="/scan?browse=~">`) || strings.Contains(plain, `class="modal browse"`) {
		t.Error("the Scan page has no Browse button, or opens the browser unasked")
	}
	if !order(browsing, `<dialog class="modal browse"`, "data-autoopen", "~/work", `href="/scan?browse=~"`, `href="/scan?browse=~%2Fwork%2Fapi"`, "api",
		`<input type="hidden" name="path" value="~/work">`, "Use this folder") {
		t.Errorf("the folder browser lacks its folder, parent, subfolders or Use this folder:\n%s", browsing)
	}
	if !strings.Contains(missing, "Can't open that folder.") {
		t.Error("a folder that won't open doesn't say so")
	}
}

func TestOnlyTheScanPageHasRescan(t *testing.T) {
	d := newFixture(t).data()
	for _, page := range []string{"/", "/changes", "/settings"} {
		if _, body, _ := get(t, d, page); strings.Contains(body, `action="/rescan"`) {
			t.Errorf("%s still has a rescan button", page)
		}
	}

	_, scan, _ := get(t, d, "/scan")

	if !order(scan, "<h1>Scan</h1>", `<form class="rescan" method="post" action="/rescan"`, `<input type="hidden" name="back" value="/scan">`, "Rescan") {
		t.Error("the Scan page has no rescan button")
	}
	if strings.Contains(scan, `class="scanned"`) {
		t.Error("the Scan page still shows when it scanned under the button")
	}
}

func TestTheScanPageIsInTheMenuAfterOverview(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/scan")

	side, _, _ := strings.Cut(body, "</aside>")
	if !order(side, `<a href="/"`, `<a href="/scan" aria-current="page">`, "Scan</a>", `<a href="/changes"`) {
		t.Error("Scan isn't in the menu right after Overview, marked current")
	}
}

func TestTheScanPageSaysHowTheLastScanWent(t *testing.T) {
	d := newFixture(t).data()
	d.History = snapshot.RunLog{Total: 7}

	_, body, _ := get(t, d, "/scan")

	if !order(body, "Last scan", "09:00 UTC", `<span class="stat-n">4</span>`, "findings", `<span class="stat-n">2</span>`, "projects", `<span class="stat-n">1</span>`, "new") {
		t.Errorf("the Scan page doesn't sum up the last scan:\n%s", body)
	}
	if !order(body, `href="/changes#scan-history"`, "<span>7 scans</span>") {
		t.Error("the Scan page doesn't point to the scan history")
	}
	_, changes, _ := get(t, d, "/changes")
	if !strings.Contains(changes, `id="scan-history"`) {
		t.Error("the scan history on Changes has no anchor to land on")
	}
}

func TestTheScanPageShowsProgressWhileItRuns(t *testing.T) {
	a := &fakeApp{d: newFixture(t).data(), state: ScanState{Running: true, Done: 1,
		Steps: []string{"reading session history", "walking projects", "checking findings"},
		Step:  "walking projects", StepDone: 3, StepTotal: 8}}

	body := getApp(t, a, "/scan")

	if !order(body, `data-progress`, `<li class="step done" data-step="reading session history">`, `<li class="step now" data-step="walking projects">`, `<span class="step-count">3/8</span>`, `<li class="step" data-step="checking findings">`) {
		t.Errorf("the Scan page doesn't show the steps, done, now and to come:\n%s", body)
	}
	if strings.Contains(getApp(t, &fakeApp{d: a.d}, "/scan"), "data-progress") {
		t.Error("the Scan page shows progress with no scan running")
	}
}

func TestReposAreAddedAndRemovedOnTheScanPage(t *testing.T) {
	for name, tc := range map[string]struct {
		form   url.Values
		addErr error
		want   string
	}{
		"add":           {url.Values{"action": {"add"}, "path": {"~/work/new"}}, nil, "repo-added"},
		"add, saved":    {url.Values{"action": {"add"}, "path": {"~/work/api"}}, ErrRepoSaved, "repo-saved"},
		"add, missing":  {url.Values{"action": {"add"}, "path": {"~/nope"}}, ErrRepoMissing, "repo-missing"},
		"add, a file":   {url.Values{"action": {"add"}, "path": {"~/a.txt"}}, ErrRepoNotDir, "repo-notdir"},
		"add, outside":  {url.Values{"action": {"add"}, "path": {"/etc"}}, ErrRepoOutside, "repo-outside"},
		"add, relative": {url.Values{"action": {"add"}, "path": {"work"}}, ErrRepoRelative, "repo-relative"},
		"add, other":    {url.Values{"action": {"add"}, "path": {"~/x"}}, errors.New("disk full"), "save-failed"},
		"remove":        {url.Values{"action": {"remove"}, "i": {"0"}}, nil, "repo-removed"},
		"remove, bad i": {url.Values{"action": {"remove"}, "i": {"x"}}, nil, "repo-notsaved"},
		"no action":     {url.Values{}, nil, "repo-notsaved"},
	} {
		a := &fakeApp{d: newFixture(t).data(), addErr: tc.addErr}

		resp := post(t, a, "/scan/repos", tc.form)

		if got := resp.Location; resp.StatusCode != http.StatusSeeOther || got != "/scan?msg="+tc.want {
			t.Errorf("%s: %d to %q, want 303 to msg=%s", name, resp.StatusCode, got, tc.want)
		}
		if name == "add" && (len(a.added) != 1 || a.added[0] != "~/work/new") {
			t.Errorf("add: added %q, want the path as typed", a.added)
		}
		if name == "remove" && (len(a.removed) != 1 || a.removed[0] != 0) {
			t.Errorf("remove: removed %v, want [0]", a.removed)
		}
	}
}

func TestTheScanPageHasTheRepoForms(t *testing.T) {
	d := newFixture(t).data()
	_, body, _ := get(t, d, "/scan")

	if _, settings, _ := get(t, d, "/settings"); strings.Contains(settings, "Extra repos") {
		t.Error("Settings still lists the extra repos")
	}
	if !order(body, "~/work/api", `<form class="inline" method="post" action="/scan/repos">`, `<input type="hidden" name="action" value="remove">`, `<input type="hidden" name="i" value="0">`, "Remove") {
		t.Error("a saved repo has no remove form")
	}
	if !order(body, `<form class="repo-add" method="post" action="/scan/repos">`, `<input type="hidden" name="action" value="add">`, `name="path"`, "Add") {
		t.Error("settings has no form to add a repo")
	}
}

func TestChangesCanCompareWithAnOlderSnapshot(t *testing.T) {
	d := newFixture(t).data()
	d.Snapshots = []snapshot.Info{
		{ID: "b", Taken: time.Date(2026, 11, 24, 18, 30, 0, 0, time.UTC)},
		{ID: "a", Taken: time.Date(2026, 11, 23, 8, 0, 0, 0, time.UTC)},
	}
	a := &fakeApp{d: d, since: map[string][]snapshot.Change{"b": {d.Scan.Changes[1]}}}

	picked := getApp(t, a, "/changes?since=b")
	unknown := getApp(t, a, "/changes?since=zz")

	if !order(picked, `<select name="since" data-autosubmit`, `<option value="">Previous scan</option>`, `<option value="b" selected>2026-11-24 18:30:00 UTC</option>`, `<option value="a">2026-11-23 08:00:00 UTC</option>`) {
		t.Error("the picker doesn't list the snapshots with the picked one selected")
	}
	if n := strings.Count(picked, `<div class="crow">`); n != 1 || !strings.Contains(picked, "Compared with") || !strings.Contains(picked, `href="/changes?change=removed&amp;since=b"`) {
		t.Errorf("comparing with b shows %d changes, or the boxes drop the pick", n)
	}
	if n := strings.Count(unknown, `<div class="crow">`); n != len(d.Scan.Changes) || !strings.Contains(unknown, "Previous scan") {
		t.Errorf("an unknown snapshot shows %d changes, want the usual %d", n, len(d.Scan.Changes))
	}
}

// getApp is get for an App with its own behavior.
func getApp(t *testing.T, a App, target string) string {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	rec := httptest.NewRecorder()
	Pages(a).ServeHTTP(rec, req)
	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d", target, rec.Code)
	}
	return string(body)
}

func TestTheAddRowComesFirstAndRemoveAsksFirst(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/scan")

	if !order(body, `<form class="repo-add"`, `<ul class="repos">`) {
		t.Error("the add row isn't above the saved repos")
	}
	if !order(body, `<ul class="repos">`, "~/work/api", `<button type="button" class="btn small ghost" data-open="rm-0" aria-haspopup="dialog">Remove</button>`,
		`<dialog class="modal confirm" id="rm-0"`, "Remove this folder?", "~/work/api",
		`<form method="dialog">`, "Cancel", `<form class="inline" method="post" action="/scan/repos">`, `<input type="hidden" name="i" value="0">`, "Remove") {
		t.Errorf("Remove doesn't ask first:\n%s", body)
	}
}
