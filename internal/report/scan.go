package report

import (
	"strconv"
	"strings"
	"time"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/snapshot"
)

// AgentInfo is one agent for the agents block. Name is jarx's own.
type AgentInfo struct {
	Agent     model.Agent
	Name      string
	ConfigDir model.Path
	Found     bool
	Installs  []model.Install // where it's installed, found on disk
}

// ScanView is everything the scan report shows.
type ScanView struct {
	Fake   bool // --home: a fake home, not this machine
	Home   model.Path
	GOOS   string
	Agents []AgentInfo

	Projects     []model.Project
	Sessions     []model.Session     // from history (observed, not documented)
	HistoryFiles int                 // history files looked at
	Instructions []model.Instruction // not tied to a project
	Unknown      []model.Unknown
	Findings     []finding.Finding
	Rules        *finding.Registry
	Credentials  []model.Credential // the machine's; a project's own are on it

	Since   time.Time // when the last snapshot was taken, zero for none
	Note    string    // why there's nothing to compare against, if not a first scan
	Changes []snapshot.Change
	SaveErr error

	All bool // --all: every finding, and the full inventory after
}

// maxChanges is how many changes the summary lists before the rest become
// a count.
const maxChanges = 8

// Scan prints the scan report: what jarx checked, then what it found.
func (p *Printer) Scan(v ScanView) {
	p.header(v)
	p.blank()
	p.agents(v)
	p.blank()
	p.scanned(v)
	p.blank()
	p.summary(v)
	p.changes(v)
	p.groups(v)
	p.blank()
	if v.All {
		p.inventory(v)
		return
	}
	p.emit(line{{text: "all findings and the full inventory: ", tone: dim}, {text: "jarx scan --all"}})
}

func (p *Printer) blank() { _, _ = p.Out.w.Write([]byte("\n")) }

// own escapes jarx's own words, like every other text, for one rule.
func own(s string) string { return escape(s) }

// sep is the list separator, with spaces.
func (p *Printer) sep() string { return " " + p.Style.glyphs().dot + " " }

func (p *Printer) header(v ScanView) {
	where := "this machine"
	if v.Fake {
		where = "fake home"
	}
	one := line{
		{text: own(where + " ~ = ")},
		{text: escape(v.Home.Text().String())},
		{text: own(p.sep() + v.GOOS)},
	}
	if one.cells() <= p.Style.width() {
		p.emit(one)
		return
	}
	// Too long for one line: the home dir gets its own, so it isn't the
	// part that's cut.
	p.emit(line{{text: own(where + p.sep() + v.GOOS)}})
	p.emit(line{{text: "~ = ", tone: dim}, {text: escape(v.Home.Text().String())}})
}

// summary is one line: the findings by severity, then what changed.
func (p *Printer) summary(v ScanView) {
	l := p.findingCounts(v.Findings)
	ch := line{{text: "changes: ", tone: dim}, {text: own(p.changeSummary(v))}}
	if l.cells()+len(wideGap)+ch.cells() <= p.Style.width() {
		p.emit(append(append(l, seg{text: wideGap}), ch...))
	} else {
		p.emit(l)
		p.emit(ch)
	}
	if v.SaveErr != nil {
		p.emit(line{{text: "couldn't save this scan's snapshot: ", tone: yellow}, {text: escape(p.scrubbed(v.SaveErr.Error()))}})
	}
}

// findingCounts is how many findings there are, by severity.
func (p *Printer) findingCounts(fs []finding.Finding) line {
	if len(fs) == 0 {
		return line{{text: "no findings", tone: bold}}
	}
	bySev := map[finding.Severity]int{}
	for _, f := range fs {
		bySev[f.Severity]++
	}
	l := line{{text: own(plural(len(fs), "finding", "findings")), tone: bold}}
	gap := wideGap
	for _, s := range severities {
		if bySev[s] == 0 {
			continue
		}
		label, t := sevLabel(s)
		l = append(l, seg{text: gap + strconv.Itoa(bySev[s]) + " "}, seg{text: strings.TrimSpace(label), tone: t})
		gap = own(p.sep())
	}
	return l
}

func (p *Printer) scrubbed(s string) string {
	if p.scrub == nil {
		return s
	}
	t, _ := p.scrub.Scrub(s)
	return t.String()
}

func since(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04") + " UTC"
}

func (p *Printer) changeSummary(v ScanView) string {
	switch {
	case v.Since.IsZero() && v.Note == "":
		return "first scan"
	case v.Since.IsZero():
		return v.Note
	case len(v.Changes) == 0:
		return "none since " + since(v.Since)
	}
	n := map[snapshot.ChangeKind]int{}
	for _, c := range v.Changes {
		n[c.Change]++
	}
	return strconv.Itoa(len(v.Changes)) + " since " + since(v.Since) +
		" (+" + strconv.Itoa(n[snapshot.Added]) + " -" + strconv.Itoa(n[snapshot.Removed]) + " ~" + strconv.Itoa(n[snapshot.Changed]) + ")"
}

// changes lists what changed since the last scan, when anything did.
func (p *Printer) changes(v ScanView) {
	if len(v.Changes) == 0 {
		return
	}
	p.blank()
	p.emit(line{{text: "changed since the last scan", tone: bold}})
	marks := map[snapshot.ChangeKind]string{snapshot.Added: "+", snapshot.Removed: "-", snapshot.Changed: "~"}
	shown := v.Changes
	if !v.All && len(shown) > maxChanges {
		shown = shown[:maxChanges]
	}
	nodes := make([]node, 0, len(shown)+1)
	for _, c := range shown {
		key := shortenIn(c.Item.Key.String(), model.Path{}, v.Home)
		l := line{{text: marks[c.Change] + " "}, {text: own(string(c.Item.Kind) + "  "), tone: dim}, {text: escape(key)}}
		if !c.What.IsZero() {
			l = append(l, seg{text: ": " + escape(shortenIn(c.What.String(), model.Path{}, v.Home)), tone: dim})
		}
		nodes = append(nodes, node{l})
	}
	if rest := len(v.Changes) - len(shown); rest > 0 {
		nodes = append(nodes, node{line{{text: own(p.Style.glyphs().ell + " " + strconv.Itoa(rest) + " more  (jarx scan --all)"), tone: dim}}})
	}
	p.tree(nodes)
}

// inventory is the full lists, for --all.
func (p *Printer) inventory(v ScanView) {
	p.emit(line{{text: "full inventory", tone: bold}})
	p.Wrapped(v.Home, func() {
		p.Installs(v.Agents)
		p.Projects(v.Projects)
		p.Credentials(v.Credentials)
		p.Unknown(v.Unknown)
		p.Instructions(v.Instructions)
	})
}
