package ui

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"html/template"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/llm"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/report"
	"github.com/nickelsec/jarx/internal/snapshot"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed assets
var assetFS embed.FS

// Data is one scan as the dashboard shows it. Every text in it is masked
// already; the pages only lay it out, and html/template escapes it.
type Data struct {
	Scan     report.ScanView
	Scanned  time.Time
	Version  string
	StateDir redact.Text
	Repos    []redact.Text
	LLM      LLM
	// History is the scan log, newest first. HistoryNote says why it's
	// empty when it couldn't be read.
	History     snapshot.RunLog
	HistoryNote string
	// Snapshots is the saved snapshots before this scan, newest first, for
	// Changes to compare against.
	Snapshots []snapshot.Info
}

// LLM is the LLM review's settings and what it would send. It holds the
// key's env var name and whether it's set, never the key.
type LLM struct {
	On        bool
	BaseURL   redact.Text
	Model     redact.Text
	KeyEnv    redact.Text
	KeySet    bool
	Parallel  int
	Artifacts []llm.Artifact
	States    []llm.State // one per artifact
	Skipped   int         // how many the user skipped
	Plan      llm.Preview
}

// Pages serves the dashboard's pages, its actions and its embedded files.
// app.Data is called once per request for the scan to show.
func Pages(app App) http.Handler {
	t := template.Must(template.New("").Funcs(template.FuncMap{"dict": dict}).ParseFS(templateFS, "templates/*.html"))
	mux := http.NewServeMux()
	render := func(w http.ResponseWriter, r *http.Request, name string, p page) {
		p.Notice, p.Here, p.Scan = noticeOf(r), here(r), app.ScanState()
		var buf bytes.Buffer
		if err := t.ExecuteTemplate(&buf, name, p); err != nil {
			http.Error(w, "jarx: couldn't render the page", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(buf.Bytes())
	}
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		d := app.Data()
		render(w, r, "overview.html", newPage(d, "overview", "Overview", -1, overviewOf(d, r.URL.Query())))
	})
	mux.HandleFunc("GET /projects/{n}", func(w http.ResponseWriter, r *http.Request) {
		d := app.Data()
		n, err := strconv.Atoi(r.PathValue("n"))
		if err != nil || n < 0 || n >= len(d.Scan.Projects) {
			http.NotFound(w, r)
			return
		}
		render(w, r, "project.html", newPage(d, "project", d.Scan.Projects[n].Path.Text().String(), n, projectOf(d, n, r.URL.Query())))
	})
	mux.HandleFunc("GET /changes", func(w http.ResponseWriter, r *http.Request) {
		d := app.Data()
		q := r.URL.Query()
		picked := q.Get(keySince)
		if picked != "" {
			// An ID that isn't a saved snapshot shows the usual changes.
			if since, changes, err := app.ChangesSince(picked); err == nil {
				d.Scan.Since, d.Scan.Changes, d.Scan.Note = since, changes, ""
			} else {
				picked = ""
			}
		}
		render(w, r, "changes.html", newPage(d, "changes", "Changes", -1, changesOf(d, q.Get(keyChange), picked)))
	})
	simplePages(mux, app, render)
	actions(mux, app)
	mux.HandleFunc("GET /static/{file...}", serveAsset)
	return mux
}

// renderer renders one page.
type renderer func(w http.ResponseWriter, r *http.Request, name string, p page)

// simplePages adds the pages that only read: LLM review, Inventory,
// Settings and Scan.
func simplePages(mux *http.ServeMux, app App, render renderer) {
	mux.HandleFunc("GET /llm", func(w http.ResponseWriter, r *http.Request) {
		d := app.Data()
		b := llmOf(d, r.URL.Query())
		b.Review = app.ScanState().Review
		render(w, r, "llm.html", newPage(d, "llm", "LLM review", -1, b))
	})
	mux.HandleFunc("GET /inventory", func(w http.ResponseWriter, r *http.Request) {
		d := app.Data()
		render(w, r, "inventory.html", newPage(d, "inventory", "Inventory", -1, inventoryOf(d)))
	})
	mux.HandleFunc("GET /settings", func(w http.ResponseWriter, r *http.Request) {
		d := app.Data()
		render(w, r, "settings.html", newPage(d, "settings", "Settings", -1, settingsOf(d)))
	})
	mux.HandleFunc("GET /scan", func(w http.ResponseWriter, r *http.Request) {
		d := app.Data()
		b := scanOf(d, app.ScanState())
		if q := r.URL.Query(); q.Has(keyBrowse) {
			b.Browse = browseOf(app, q.Get(keyBrowse))
		}
		render(w, r, "scan.html", newPage(d, "scan", "Scan", -1, b))
	})
}

// actions adds the routes that do things: scan, repos, LLM settings and
// review. Every write is a POST, behind the guard's cookie and
// cross-origin check.
func actions(mux *http.ServeMux, app App) {
	mux.HandleFunc("POST /rescan", rescan(app))
	mux.HandleFunc("GET /rescan/status", scanStatus(app))
	mux.HandleFunc("POST /scan/repos", repos(app))
	mux.HandleFunc("POST /settings/llm", llmSettings(app))
	mux.HandleFunc("POST /llm/review", review(app))
	mux.HandleFunc("POST /llm/skip", skip(app))
}

// dict makes a map from key and value pairs, so a template can hand a
// partial more than one value.
func dict(kv ...any) map[string]any {
	m := make(map[string]any, len(kv)/2) //nolint:mnd // pairs
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			m[k] = kv[i+1]
		}
	}
	return m
}

// assetTypes are the embedded files' content types, set here so they don't
// depend on the OS's MIME table.
//
//nolint:gochecknoglobals // fixed table, read only
var assetTypes = map[string]string{
	".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
	".svg": "image/svg+xml", ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8",
}

func serveAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	kind, ok := assetTypes[path.Ext(name)]
	if !ok || !fs.ValidPath(name) {
		http.NotFound(w, r)
		return
	}
	data, err := assetFS.ReadFile("assets/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", kind)
	_, _ = w.Write(data) //nolint:gosec // G705: an embedded file, nothing from the request
}

// page is what every template gets: the sidebar and the page's own part.
type page struct {
	Nav      string
	Title    string
	Here     string  // this page's URL, for a form to come back to
	Notice   *notice // what the last action did, if anything
	Scan     ScanState
	Projects []navProject // shown
	More     []navProject // behind View all
	AllCount int
	User     navProject
	Body     any
}

type navProject struct {
	Name, Full, Href, Count string
	Active                  bool
	Status                  bool // Count is a status, like stale, not a number
	User                    bool // the user config, set apart from the projects
}

// sidebarProjects is how many projects show before View all.
const sidebarProjects = 6

const userConfig = "User config"

// userConfigNote is what User config means, on hover.
const userConfigNote = "settings and installs outside any project"

// whereOf says what was scanned: this machine or a fake home, and the OS.
func whereOf(d Data) string {
	if d.Scan.Fake {
		return "Fake home · " + osName(d.Scan.GOOS)
	}
	return "This machine · " + osName(d.Scan.GOOS)
}

// osName is a GOOS as people write it.
func osName(goos string) string {
	switch goos {
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	default:
		return capital(goos)
	}
}

func newPage(d Data, nav, title string, current int, body any) page {
	p := page{Nav: nav, Title: title, Body: body}
	type scored struct {
		i     int
		count [4]int
	}
	list := make([]scored, 0, len(d.Scan.Projects))
	user := [4]int{}
	for i := range d.Scan.Projects {
		list = append(list, scored{i: i})
	}
	for _, f := range d.Scan.Findings {
		k := sevIndex(f.Severity)
		if i := projectIndex(d.Scan.Projects, f); i >= 0 {
			list[i].count[k]++
		} else {
			user[k]++
		}
	}
	// Worst first, without saying so: the sidebar stays quiet.
	slices.SortStableFunc(list, func(a, b scored) int {
		for k := range 4 {
			if a.count[k] != b.count[k] {
				return b.count[k] - a.count[k]
			}
		}
		return 0
	})
	home := d.Scan.Home.Text().String()
	for n, s := range list {
		proj := d.Scan.Projects[s.i]
		full := tilde(proj.Path.Text().String(), home)
		np := navProject{Name: base(full), Full: full, Href: "/projects/" + strconv.Itoa(s.i), Count: strconv.Itoa(sum(s.count)), Active: s.i == current}
		if proj.Status != model.ProjectOK {
			np.Count, np.Status = string(proj.Status), true
		}
		if n < sidebarProjects {
			p.Projects = append(p.Projects, np)
		} else {
			p.More = append(p.More, np)
		}
	}
	p.AllCount = len(list)
	p.User = navProject{Name: userConfig, Full: userConfigNote, Href: "/?project=user", Count: strconv.Itoa(sum(user)), User: true}
	return p
}

// base is a path's last folder, on either kind of separator.
func base(p string) string {
	p = strings.TrimRight(p, `/\`)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func sum(c [4]int) int { return c[0] + c[1] + c[2] + c[3] }

// sevKeys are the severities worst first, as the pages and queries name
// them.
//
//nolint:gochecknoglobals // fixed table, read only
var sevKeys = [4]string{"crit", "high", "med", "info"}

//nolint:gochecknoglobals // fixed table, read only
var sevWords = [4]string{"CRIT", "HIGH", "MED", "INFO"}

//nolint:gochecknoglobals // fixed table, read only
var sevLabels = [4]string{"Critical", "High", "Medium", "Info"}

func sevIndex(s finding.Severity) int {
	switch s {
	case finding.Critical:
		return 0
	case finding.High:
		return 1
	case finding.Medium:
		return 2 //nolint:mnd // medium's place
	case finding.Info:
		return 3 //nolint:mnd // info's place
	default:
		return 3 //nolint:mnd // anything else counts as info
	}
}

// projectIndex is the project a finding's file is in, the deepest one when
// projects nest, or -1 for the user config.
func projectIndex(ps []model.Project, f finding.Finding) int {
	file := f.Origin.File.Raw()
	best, bestLen := -1, 0
	for i, p := range ps {
		dir := p.Path.Raw()
		if dir == "" || len(dir) < bestLen {
			continue
		}
		if file == dir || strings.HasPrefix(file, dir) && (file[len(dir)] == '/' || file[len(dir)] == '\\') {
			best, bestLen = i, len(dir)
		}
	}
	return best
}

// tilde shows path from ~ when it's in the home dir.
func tilde(p, home string) string {
	if home == "" || len(p) <= len(home) || !strings.EqualFold(p[:len(home)], home) {
		return p
	}
	if c := p[len(home)]; c == '/' || c == '\\' {
		return "~" + p[len(home):]
	}
	return p
}

// areaOf is a rule's area, the middle of JARX-AREA-001.
func areaOf(rule string) string {
	parts := strings.Split(rule, "-")
	if len(parts) != 3 { //nolint:mnd // JARX, area, number
		return rule
	}
	return parts[1]
}

func shortRule(rule string) string { return strings.TrimPrefix(rule, "JARX-") }

// Query keys.
const (
	keySev     = "sev"
	keyProject = "project"
	keyAgent   = "agent"
	keyArea    = "area"
	keyNew     = "new"
	keyQ       = "q"
	keyPage    = "page"
	keyPer     = "per"
	keyUser    = "user"
	keyFinding = "finding"
	keyChange  = "change"
	keySince   = "since"
)

// filters is what the findings table is narrowed to.
type filters struct {
	sev, project, agent, area []string
	newOnly                   bool
	q                         string
	id                        string // one finding, from a link on the changes page
}

func filtersOf(q url.Values) filters {
	return filters{sev: q[keySev], project: q[keyProject], agent: q[keyAgent], area: q[keyArea], newOnly: q.Get(keyNew) == "1", q: strings.TrimSpace(q.Get(keyQ)), id: q.Get(keyFinding)}
}

func (f filters) any() bool {
	return len(f.sev)+len(f.project)+len(f.agent)+len(f.area) > 0 || f.newOnly || f.q != "" || f.id != ""
}

func one(list []string, v string) bool { return len(list) == 0 || slices.Contains(list, v) }

// keeps says whether a finding with these facts passes every filter.
func (f filters) keeps(sev, project, agent, area string, isNew bool, text string) bool {
	switch {
	case !one(f.sev, sev), !one(f.project, project), !one(f.agent, agent), !one(f.area, area):
		return false
	case f.newOnly && !isNew:
		return false
	case f.q != "" && !strings.Contains(strings.ToLower(text), strings.ToLower(f.q)):
		return false
	}
	return true
}

// row is one finding in a table.
type row struct {
	Sev, SevKey, Title, Evidence, Short, Project, ProjectFull, ProjectHref, Loc, Rule string
	New, Open                                                                         bool   // Open: shown alone from a link, so it opens by itself
	Why, Fix, Meta, File                                                              string // Meta: agent and scope
}

// rows is the findings worst first, narrowed by f, each with its project.
func rows(d Data, f filters, newKeys map[string]bool) []row {
	sorted := slices.Clone(d.Scan.Findings)
	finding.Sort(sorted)
	var out []row
	for _, fd := range sorted {
		r, keep := rowFor(d, fd, f, newKeys)
		if keep {
			out = append(out, r)
		}
	}
	return out
}

// rowFor is one finding as a row, and whether f keeps it.
func rowFor(d Data, fd finding.Finding, f filters, newKeys map[string]bool) (row, bool) {
	home := d.Scan.Home.Text().String()
	k := sevIndex(fd.Severity)
	pi := projectIndex(d.Scan.Projects, fd)
	projKey, projName, projHref := keyUser, userConfig, "/?project=user"
	if pi >= 0 {
		projKey = strconv.Itoa(pi)
		projName = tilde(d.Scan.Projects[pi].Path.Text().String(), home)
		projHref = "/projects/" + projKey
	}
	key := snapshot.FindingKey(fd)
	if f.id != "" && findingID(key) != f.id {
		return row{}, false
	}
	isNew := newKeys[key]
	rule, _ := d.Scan.Rules.Lookup(fd.RuleID)
	title := cmp.Or(rule.Title, fd.RuleID)
	text := title + " " + fd.Evidence.String() + " " + fd.Origin.File.Text().String() + " " + fd.RuleID
	if !f.keeps(sevKeys[k], projKey, string(fd.Origin.Agent), areaOf(fd.RuleID), isNew, text) {
		return row{}, false
	}
	loc := relTo(fd.Origin.File.Text().String(), projDir(d, pi), home)
	if fd.Origin.Line > 0 {
		loc += ":" + strconv.Itoa(fd.Origin.Line)
	}
	evidence := shortenAll(fd.Evidence.String(), home)
	return row{
		Sev: sevWords[k], SevKey: sevKeys[k], Title: capital(title), Evidence: evidence, Short: cut(evidence),
		Project: base(projName), ProjectFull: projName, ProjectHref: projHref, Loc: loc, Rule: shortRule(fd.RuleID), New: isNew,
		Why: sentence(cmp.Or(rule.Detail, rule.Title)), Fix: sentence(rule.Fix), Open: f.id != "",
		Meta: metaOf(fd.Origin), File: fd.Origin.File.Text().String(),
	}, true
}

// metaOf is where a finding applies, as "claude · project scope".
func metaOf(o model.Origin) string {
	if o.Scope == "" {
		return string(o.Agent)
	}
	return string(o.Agent) + " · " + string(o.Scope) + " scope"
}

// findingID is a short, stable id for a finding, from the key the
// snapshot keeps it by, so a link can point at it.
func findingID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:6])
}

func projDir(d Data, i int) string {
	if i < 0 {
		return ""
	}
	return d.Scan.Projects[i].Path.Text().String()
}

// relTo shows file inside dir relative to it, else from ~.
func relTo(file, dir, home string) string {
	if dir != "" && len(file) > len(dir) && strings.EqualFold(file[:len(dir)], dir) {
		if c := file[len(dir)]; c == '/' || c == '\\' {
			return file[len(dir)+1:]
		}
	}
	if file == dir && dir != "" {
		return "the project"
	}
	return tilde(file, home)
}

func shortenAll(s, home string) string {
	if home == "" {
		return s
	}
	for _, sep := range []string{"/", `\`} {
		s = strings.ReplaceAll(s, home+sep, "~"+sep)
	}
	return s
}

// evidenceCut is how much evidence a table row shows; the modal shows it
// all.
const evidenceCut = 72

// cut is s up to evidenceCut characters, with an ellipsis when it's
// longer.
func cut(s string) string {
	r := []rune(s)
	if len(r) <= evidenceCut {
		return s
	}
	return string(r[:evidenceCut]) + "…"
}

// sentence is s capitalized, ending in a period, so rule text reads as a
// sentence in the modal.
func sentence(s string) string {
	s = capital(strings.TrimSpace(s))
	if s == "" || strings.HasSuffix(s, ".") || strings.HasSuffix(s, "?") || strings.HasSuffix(s, "!") {
		return s
	}
	return s + "."
}

func capital(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// newFindings is the keys of the findings added since the last scan.
func newFindings(d Data) map[string]bool {
	out := map[string]bool{}
	for _, c := range d.Scan.Changes {
		if c.Change == snapshot.Added && c.Item.Kind == snapshot.KindFinding {
			out[c.Item.Key.String()] = true
		}
	}
	return out
}

// summary is the card at the top of the overview. It counts; it never
// filters, so the toolbar is the one place filters live.
type summary struct {
	Total, New, Changed, Projects, Servers int
	Since, NewLabel                        string
	Segs                                   []seg
	Legend                                 []legend
}

// seg is one severity's share of the summary bar, drawn as an SVG rect so
// the page needs no inline style.
type seg struct {
	Class string
	X, W  int
}

type legend struct {
	Key, Label string
	N          int
}

func summaryOf(d Data) summary {
	counts := [4]int{}
	for _, fd := range d.Scan.Findings {
		counts[sevIndex(fd.Severity)]++
	}
	s := summary{Total: len(d.Scan.Findings), New: len(newFindings(d)), Changed: len(d.Scan.Changes), Projects: len(d.Scan.Projects)}
	s.NewLabel = plural(s.New, "new issue")
	if !d.Scan.Since.IsZero() {
		s.Since = d.Scan.Since.UTC().Format("15:04 UTC")
	}
	servers := map[string]bool{}
	for _, p := range d.Scan.Projects {
		for _, sv := range p.Servers {
			servers[sv.Origin.File.Raw()+"\x00"+sv.Name.String()] = true
		}
	}
	s.Servers = len(servers)
	x := 0
	for k := range 4 {
		s.Legend = append(s.Legend, legend{Key: sevKeys[k], Label: sevLabels[k], N: counts[k]})
		if counts[k] == 0 || s.Total == 0 {
			continue
		}
		w := max(counts[k]*1000/s.Total, 6) //nolint:mnd // per mille, and a sliver for one finding
		s.Segs = append(s.Segs, seg{Class: "f-" + sevKeys[k], X: x, W: w})
		x += w
	}
	return s
}

// hidden is a query value a form carries over unchanged.
type hidden struct{ Name, Value string }

// hiddenExcept is every value in q but those under the drop keys, in a
// stable order.
func hiddenExcept(q url.Values, drop ...string) []hidden {
	keys := make([]string, 0, len(q))
	for k := range q {
		if !slices.Contains(drop, k) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	var out []hidden
	for _, k := range keys {
		for _, v := range q[k] {
			out = append(out, hidden{Name: k, Value: v})
		}
	}
	return out
}

// link is base with q's values, minus drop, plus set.
func link(base string, q url.Values, set url.Values, drop ...string) string {
	next := url.Values{}
	for k, vs := range q {
		if !slices.Contains(drop, k) {
			next[k] = slices.Clone(vs)
		}
	}
	maps.Copy(next, set)
	if enc := next.Encode(); enc != "" {
		return base + "?" + enc
	}
	return base
}

// choice is one checkbox in a facet.
type choice struct {
	Name, Value, Label, Title string
	On                        bool
}

// facet is one filter dropdown: its button's label with what's picked, its
// checkboxes, the other filters its form carries, and a link that clears
// it.
type facet struct {
	Key, Label, Summary, ClearHref string
	On                             bool
	Options                        []choice
	Hidden                         []hidden
}

// toolbar is the findings table's search, facets, "new only" and clear
// all.
type toolbar struct {
	Base, Query  string
	SearchHidden []hidden
	Facets       []facet
	NewOn        bool
	NewHref      string
	Active       bool
	ClearHref    string
}

func toolbarOf(d Data, q url.Values, f filters, baseURL string, withProject bool) toolbar {
	home := d.Scan.Home.Text().String()
	tb := toolbar{Base: baseURL, Query: f.q, SearchHidden: hiddenExcept(q, keyQ, keyPage), NewOn: f.newOnly, Active: f.any(), ClearHref: baseURL}
	if f.newOnly {
		tb.NewHref = link(baseURL, q, nil, keyNew, keyPage)
	} else {
		tb.NewHref = link(baseURL, q, url.Values{keyNew: {"1"}}, keyPage)
	}
	mk := func(key, label string, picked []string, opts []choice) facet {
		var names []string
		for i := range opts {
			opts[i].Name, opts[i].On = key, slices.Contains(picked, opts[i].Value)
			if opts[i].On {
				names = append(names, opts[i].Label)
			}
		}
		fc := facet{Key: key, Label: label, Summary: label, On: len(names) > 0, Options: opts,
			Hidden: hiddenExcept(q, key, keyPage), ClearHref: link(baseURL, q, nil, key, keyPage)}
		if len(names) > 0 {
			fc.Summary = label + ": " + strings.Join(names, ", ")
		}
		return fc
	}
	sev := make([]choice, 0, len(sevKeys))
	for k := range sevKeys {
		sev = append(sev, choice{Value: sevKeys[k], Label: sevLabels[k]})
	}
	tb.Facets = append(tb.Facets, mk(keySev, "Severity", f.sev, sev))
	if withProject {
		tb.Facets = append(tb.Facets, mk(keyProject, "Project", f.project, projectChoices(d, home)))
	}
	tb.Facets = append(tb.Facets, mk(keyAgent, "Agent", f.agent, []choice{{Value: "claude", Label: "Claude"}, {Value: "codex", Label: "Codex"}}))
	tb.Facets = append(tb.Facets, mk(keyArea, "Category", f.area, areaChoices(d)))
	return tb
}

// projectChoices is each project by its folder name, the full path as its
// title, and the user config.
func projectChoices(d Data, home string) []choice {
	out := make([]choice, 0, len(d.Scan.Projects)+1)
	for i, p := range d.Scan.Projects {
		full := tilde(p.Path.Text().String(), home)
		out = append(out, choice{Value: strconv.Itoa(i), Label: base(full), Title: full})
	}
	return append(out, choice{Value: keyUser, Label: userConfig, Title: userConfigNote})
}

// areaChoices is each rule area that has a finding, sorted.
func areaChoices(d Data) []choice {
	var areas []string
	for _, fd := range d.Scan.Findings {
		if a := areaOf(fd.RuleID); !slices.Contains(areas, a) {
			areas = append(areas, a)
		}
	}
	slices.Sort(areas)
	out := make([]choice, 0, len(areas))
	for _, a := range areas {
		out = append(out, choice{Value: a, Label: a}) // areas are short codes like MCP, so they stay in capitals
	}
	return out
}

// Rows per page.
const defaultPer = 20

//nolint:gochecknoglobals // fixed list, read only
var perOptions = []int{20, 30, 50}

// pager is the findings table's footer: what's shown, rows per page and
// the page links.
type pager struct {
	From, To, Total int
	Pages           []pageLink
	PrevHref        string
	NextHref        string
	Base            string
	Per             []perOption
	PerHidden       []hidden
	Many            bool // more than one page
}

type pageLink struct {
	N       int
	Href    string
	Current bool
	Gap     bool
}

type perOption struct {
	N        int
	Selected bool
}

// paginate cuts rs to the page q asks for, clamped to the pages there are,
// and builds the links. Every link keeps the filters.
func paginate[T any](rs []T, q url.Values, baseURL string) ([]T, pager) {
	per := defaultPer
	if n, err := strconv.Atoi(q.Get(keyPer)); err == nil && slices.Contains(perOptions, n) {
		per = n
	}
	pages := max(1, (len(rs)+per-1)/per)
	cur := 1
	if n, err := strconv.Atoi(q.Get(keyPage)); err == nil {
		cur = min(max(n, 1), pages)
	}
	from, to := (cur-1)*per, min(cur*per, len(rs))
	p := pager{Total: len(rs), Base: baseURL, PerHidden: hiddenExcept(q, keyPer, keyPage), Many: pages > 1}
	if len(rs) > 0 {
		p.From, p.To = from+1, to
	}
	at := func(n int) string { return link(baseURL, q, url.Values{keyPage: {strconv.Itoa(n)}}) }
	if cur > 1 {
		p.PrevHref = at(cur - 1)
	}
	if cur < pages {
		p.NextHref = at(cur + 1)
	}
	p.Pages = pageLinks(cur, pages, at)
	for _, n := range perOptions {
		p.Per = append(p.Per, perOption{N: n, Selected: n == per})
	}
	return rs[from:to], p
}

// pageLinks is the page numbers worth a link, with a gap where some are
// skipped.
func pageLinks(cur, pages int, at func(int) string) []pageLink {
	var out []pageLink
	last := 0
	for _, n := range pageNumbers(cur, pages) {
		if last > 0 && n > last+1 {
			out = append(out, pageLink{Gap: true})
		}
		out = append(out, pageLink{N: n, Href: at(n), Current: n == cur})
		last = n
	}
	return out
}

// pageNumbers is the pages worth a link: all of them when there are few,
// else the first, the last and the ones around the current page, with
// enough at either end that a gap never hides a single page.
func pageNumbers(cur, pages int) []int {
	const all, edge = 7, 5
	if pages <= all {
		out := make([]int, pages)
		for i := range out {
			out[i] = i + 1
		}
		return out
	}
	set := map[int]bool{1: true, pages: true, cur - 1: true, cur: true, cur + 1: true}
	if cur <= edge-1 {
		for n := 1; n <= edge; n++ {
			set[n] = true
		}
	}
	if cur >= pages-edge+2 {
		for n := pages - edge + 1; n <= pages; n++ {
			set[n] = true
		}
	}
	var out []int
	for n := range set {
		if n >= 1 && n <= pages {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

type overview struct {
	Summary summary
	Toolbar toolbar
	Rows    []row
	Pager   pager
	Total   int
}

func overviewOf(d Data, q url.Values) overview {
	f := filtersOf(q)
	all := rows(d, f, newFindings(d))
	shown, pg := paginate(all, q, "/")
	return overview{Summary: summaryOf(d), Toolbar: toolbarOf(d, q, f, "/", true), Rows: shown, Pager: pg, Total: len(d.Scan.Findings)}
}

type projectBody struct {
	overview

	Path   string
	Trust  []trustPill
	Walk   string
	Counts [4]int
}

func projectOf(d Data, n int, q url.Values) projectBody {
	p := d.Scan.Projects[n]
	key := strconv.Itoa(n)
	baseURL := "/projects/" + key
	q.Del(keyProject)
	f := filtersOf(q)
	f.project = []string{key}
	b := projectBody{Path: tilde(p.Path.Text().String(), d.Scan.Home.Text().String())}
	b.Trust = trustOf(p)
	switch p.Walk {
	case model.WalkGit:
		b.Walk = "Files from git · " + plural(len(p.Files), "file")
	case model.WalkFallback:
		b.Walk = "Files found on disk · " + plural(len(p.Files), "file")
	}
	mine := rows(d, filters{project: []string{key}}, nil)
	for _, r := range mine {
		b.Counts[slices.Index(sevKeys[:], r.SevKey)]++
	}
	all := rows(d, f, newFindings(d))
	b.Rows, b.Pager = paginate(all, q, baseURL)
	b.Toolbar = toolbarOf(d, q, f, baseURL, false)
	b.Total = len(mine)
	return b
}

type llmRow struct {
	Key, Kind, Name, File, Project, State, StateKey string
	Checked                                         bool
	Tokens                                          int // what sending it costs, about; 0 when the cache answers it
}

type llmBody struct {
	Pager                                        pager
	Total                                        int
	Review                                       *ReviewState // a review sent from the dashboard, once there's been one
	On                                           bool
	Host, Model, KeyEnv                          string
	KeySet                                       bool
	Parallel, Send, Cached, Failed, New, Skipped int
	Rows                                         []llmRow
	// Arts is every artifact, on every page, as "key:tokens:state" with a
	// space between, so the page can keep what's checked as you page.
	Arts string
}

// trustPill is an agent's trust in a project. Only trusted shows as
// trusted; untrusted and unknown are plain.
type trustPill struct {
	Text    string
	Trusted bool
}

func trustOf(p model.Project) []trustPill {
	out := make([]trustPill, 0, len(p.Trust))
	for _, t := range p.Trust {
		out = append(out, trustPill{Text: string(t.Origin.Agent) + " " + string(t.Level), Trusted: t.Level == model.TrustTrusted})
	}
	return out
}

// tokensOf is about what sending a, in state st, costs. The cache answers
// a cached one, so it costs nothing.
func tokensOf(a llm.Artifact, st llm.State) int {
	if st == llm.StateCached || st == llm.StateSkipped {
		return 0
	}
	return llm.Estimate(a)
}

// stateWord is a state as one word, for the page's script.
func stateWord(st llm.State) string {
	if st == llm.StateFailed {
		return "failed"
	}
	return string(st)
}

// artifactName is what a checklist row calls an artifact. An instruction
// file is named by its path, which the row shows under it anyway, so the
// name is just the file's.
func artifactName(a llm.Artifact) string {
	name := a.Name.String()
	if name == a.Origin.File.Text().String() {
		return base(name)
	}
	return name
}

func llmOf(d Data, q url.Values) llmBody {
	l := d.LLM
	b := llmBody{On: l.On, Model: l.Model.String(), KeyEnv: l.KeyEnv.String(), KeySet: l.KeySet, Parallel: l.Parallel,
		Host: l.Plan.Host, Send: l.Plan.Send, Cached: l.Plan.Cached, Failed: l.Plan.Failed, New: l.Plan.New, Skipped: l.Skipped}
	arts := make([]string, 0, len(l.Artifacts))
	home := d.Scan.Home.Text().String()
	for i, a := range l.Artifacts {
		st := llm.StateNew
		if i < len(l.States) {
			st = l.States[i]
		}
		pi := projectIndex(d.Scan.Projects, finding.Finding{Origin: a.Origin})
		proj := userConfig
		if pi >= 0 {
			proj = tilde(d.Scan.Projects[pi].Path.Text().String(), home)
		}
		b.Rows = append(b.Rows, llmRow{
			Key: llm.KeyOf(a), Kind: capital(string(a.Kind)), Name: artifactName(a),
			File: relTo(a.Origin.File.Text().String(), projDir(d, pi), home), Project: proj,
			State: string(st), StateKey: strings.ReplaceAll(string(st), " ", "-"), Tokens: tokensOf(a, st),
			Checked: st == llm.StateNew || st == llm.StateFailed, // what a review sends unless you change it
		})
		arts = append(arts, llm.KeyOf(a)+":"+strconv.Itoa(tokensOf(a, st))+":"+stateWord(st))
	}
	b.Arts = strings.Join(arts, " ")
	b.Total = len(b.Rows)
	b.Rows, b.Pager = paginate(b.Rows, q, "/llm")
	return b
}

// changeRow is one change, tagged added, removed or changed. A finding
// that's still there shows as the finding, and opens its modal.
type changeRow struct {
	Tag, TagKey, Kind, Title, Sub, Sev, SevKey string
	Modal                                      string // the modal's id, for a finding that's still there
}

// pick is one snapshot in the Changes picker.
type pick struct {
	ID, When string
	Selected bool
}

// changeBox is a summary count that filters the list to its kind.
type changeBox struct {
	Label, Href string
	N           int
	On          bool
}

// modal is a finding's modal and its id.
type modal struct {
	ID string
	R  row
}

type changesBody struct {
	SinceDate, SinceTime, Note string
	Compared                   bool   // against a picked snapshot, not the previous scan
	Picks                      []pick // the snapshots to compare against
	ClearHref                  string
	Boxes                      []changeBox
	Filtered                   bool
	Rows                       []changeRow
	Modals                     []modal
	Runs                       []runRow
	TotalRuns, HistoryNote     string
}

// runRow is one scan in the history: when, how many findings were new,
// and what changed.
type runRow struct {
	When, Summary string
	NewFindings   int
	First         bool
}

//nolint:gochecknoglobals // fixed list, read only
var changeKinds = []snapshot.ChangeKind{snapshot.Added, snapshot.Removed, snapshot.Changed}

func changesOf(d Data, only, picked string) changesBody {
	b := changesBody{Note: d.Scan.Note, HistoryNote: d.HistoryNote, Compared: picked != "", ClearHref: changesHref("", picked), Picks: picksOf(d.Snapshots, picked)}
	if !d.Scan.Since.IsZero() {
		b.SinceDate, b.SinceTime = d.Scan.Since.UTC().Format("2006-01-02"), d.Scan.Since.UTC().Format("15:04 UTC")
	}
	if !slices.Contains(changeKinds, snapshot.ChangeKind(only)) {
		only = ""
	}
	b.Filtered = only != ""
	counts := map[snapshot.ChangeKind]int{}
	current := map[string]finding.Finding{}
	for _, fd := range d.Scan.Findings {
		current[snapshot.FindingKey(fd)] = fd
	}
	newKeys := newFindings(d)
	for _, c := range d.Scan.Changes {
		counts[c.Change]++
		if only != "" && string(c.Change) != only {
			continue
		}
		r := changeRowOf(d, c)
		if fd, ok := current[c.Item.Key.String()]; ok && c.Item.Kind == snapshot.KindFinding && c.Change != snapshot.Removed {
			fr, _ := rowFor(d, fd, filters{}, newKeys)
			r = findingChange(r, fr, fd)
			r.Modal = "c-" + strconv.Itoa(len(b.Modals))
			b.Modals = append(b.Modals, modal{ID: r.Modal, R: fr})
		}
		b.Rows = append(b.Rows, r)
	}
	b.Boxes = changeBoxes(counts, only, picked)
	b.Runs, b.TotalRuns = runsOf(d.History)
	return b
}

// picksOf is the snapshots to compare against, the picked one selected.
func picksOf(snaps []snapshot.Info, picked string) []pick {
	out := make([]pick, 0, len(snaps))
	for _, sn := range snaps {
		// To the second: scans minutes apart would read the same otherwise.
		out = append(out, pick{ID: sn.ID, When: sn.Taken.UTC().Format("2006-01-02 15:04:05 UTC"), Selected: sn.ID == picked})
	}
	return out
}

// changeBoxes is the summary counts, each a link that filters to its kind.
func changeBoxes(counts map[snapshot.ChangeKind]int, only, picked string) []changeBox {
	out := make([]changeBox, 0, len(changeKinds))
	for _, k := range changeKinds {
		out = append(out, changeBox{Label: string(k), N: counts[k], Href: changesHref(string(k), picked), On: string(k) == only})
	}
	return out
}

// changesHref is the Changes page filtered to one kind and compared with a
// picked snapshot, either of them left out when empty.
func changesHref(only, picked string) string {
	q := url.Values{}
	if only != "" {
		q.Set(keyChange, only)
	}
	if picked != "" {
		q.Set(keySince, picked)
	}
	return link("/changes", q, nil)
}

func changeRowOf(d Data, c snapshot.Change) changeRow {
	home := d.Scan.Home.Text().String()
	key := c.Item.Key.String()
	r := changeRow{Tag: capital(string(c.Change)), TagKey: string(c.Change), Kind: capital(string(c.Item.Kind)), Title: shortenAll(key, home), Sub: capital(c.What.String())}
	if c.Item.Kind != snapshot.KindFinding {
		return r
	}
	r.Kind = "Finding"
	if id, _, _ := strings.Cut(key, " "); id != "" {
		if rule, ok := d.Scan.Rules.Lookup(id); ok {
			r.Title, r.Sub = capital(rule.Title), cut(shortenAll(key, home))
		}
	}
	return r
}

// findingChange shows a change to a finding that's still there as the
// finding.
func findingChange(r changeRow, fr row, fd finding.Finding) changeRow {
	k := sevIndex(fd.Severity)
	r.Title, r.Sev, r.SevKey = fr.Title, sevWords[k], sevKeys[k]
	r.Sub = cut(fr.Rule + " · " + fr.Evidence)
	return r
}

// runsOf is the scan history as rows, and how many scans there were.
func runsOf(log snapshot.RunLog) ([]runRow, string) {
	out := make([]runRow, 0, len(log.Runs))
	for _, r := range log.Runs {
		out = append(out, runRow{When: r.Taken.UTC().Format("2006-01-02 15:04 UTC"), NewFindings: r.NewFindings, First: r.First, Summary: runSummary(r)})
	}
	return out, plural(log.Total, "scan")
}

func runSummary(r snapshot.Run) string {
	if r.First {
		return "First scan"
	}
	var parts []string
	if r.NewFindings > 0 {
		parts = append(parts, plural(r.NewFindings, "new finding"))
	}
	switch other := r.Added - r.NewFindings; {
	case other > 0 && r.NewFindings > 0:
		parts = append(parts, strconv.Itoa(other)+" other added")
	case other > 0:
		parts = append(parts, strconv.Itoa(other)+" added")
	}
	if r.Removed > 0 {
		parts = append(parts, strconv.Itoa(r.Removed)+" removed")
	}
	if r.Changed > 0 {
		parts = append(parts, strconv.Itoa(r.Changed)+" changed")
	}
	if len(parts) == 0 {
		return "No changes"
	}
	return strings.Join(parts, " · ")
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

type settingsBody struct {
	Where    string
	Scanned  string
	LLM      llmBody
	BaseURL  string
	Version  string
	StateDir string
}

func settingsOf(d Data) settingsBody {
	home := d.Scan.Home.Text().String()
	return settingsBody{Where: whereOf(d), Scanned: d.Scanned.UTC().Format("2006-01-02 15:04 UTC"),
		LLM: llmOf(d, nil), BaseURL: d.LLM.BaseURL.String(), Version: d.Version, StateDir: tilde(d.StateDir.String(), home)}
}

// scanBody is the Scan page: the last scan in numbers, a running scan's
// steps, the extra repos, and the way to the scan history.
type scanBody struct {
	When                    string
	Findings, Projects, New int
	TotalRuns               string
	Running                 bool
	Steps                   []stepView
	Repos                   []string
	Browse                  *browseView // the folder browser, when it's open
}

// stepView is one of a running scan's steps: done, the one it's on (with
// its count), or still to come.
type stepView struct {
	Name, Class, Count string
}

func scanOf(d Data, st ScanState) scanBody {
	home := d.Scan.Home.Text().String()
	b := scanBody{When: d.Scanned.UTC().Format("2006-01-02 15:04 UTC"), Findings: len(d.Scan.Findings), Projects: len(d.Scan.Projects),
		New: len(newFindings(d)), TotalRuns: plural(d.History.Total, "scan"), Running: st.Running}
	for _, r := range d.Repos {
		b.Repos = append(b.Repos, tilde(r.String(), home))
	}
	if st.Running {
		b.Steps = stepsOf(st)
	}
	return b
}

// stepsOf marks each step done, now or to come, by where the scan is.
func stepsOf(st ScanState) []stepView {
	at := slices.Index(st.Steps, st.Step)
	out := make([]stepView, 0, len(st.Steps))
	for i, name := range st.Steps {
		v := stepView{Name: name}
		switch {
		case i < at:
			v.Class = "done"
		case i == at:
			v.Class = "now"
			if st.StepTotal > 0 {
				v.Count = strconv.Itoa(st.StepDone) + "/" + strconv.Itoa(st.StepTotal)
			}
		}
		out = append(out, v)
	}
	return out
}
