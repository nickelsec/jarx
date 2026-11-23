package report

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
)

// Finding layout, in columns.
const (
	// maxShown is how many findings a group shows before the rest become a
	// count. Critical and high findings always show.
	maxShown = 10
	// wideLayout is the width from which a finding's file and evidence
	// share a line.
	wideLayout = 80
)

// severities lists the severities worst first.
//
//nolint:gochecknoglobals // fixed list, read only
var severities = []finding.Severity{finding.Critical, finding.High, finding.Medium, finding.Info}

// sevLabel is a severity as the report writes it, four columns wide.
func sevLabel(s finding.Severity) (string, tone) {
	switch s {
	case finding.Critical:
		return "CRIT", brightRed
	case finding.High:
		return "HIGH", red
	case finding.Medium:
		return "MED ", yellow
	case finding.Info:
		return "INFO", cyan
	}
	return "    ", plain
}

// group is the findings under one heading: a project, or the user-level
// config every project shares.
type group struct {
	project  *model.Project // nil for the user-level group
	findings []finding.Finding
}

// grouped puts each finding under the project its file is in, and the rest
// (user and managed settings, the agents' own dirs) in one group of their
// own, so they show once instead of under every project.
func grouped(v ScanView) (group, []group) {
	user := group{}
	byProject := make([]group, len(v.Projects))
	for i := range v.Projects {
		byProject[i].project = &v.Projects[i]
	}
	for _, f := range v.Findings {
		if i := projectOf(v.Projects, f.Origin.File.Raw()); i >= 0 {
			byProject[i].findings = append(byProject[i].findings, f)
		} else {
			user.findings = append(user.findings, f)
		}
	}
	finding.Sort(user.findings)
	for i := range byProject {
		finding.Sort(byProject[i].findings)
	}
	// Projects with the worst findings first; then by path.
	slices.SortStableFunc(byProject, func(a, b group) int {
		return cmp.Or(cmp.Compare(worst(b.findings), worst(a.findings)), cmp.Compare(a.project.Path.Raw(), b.project.Path.Raw()))
	})
	return user, byProject
}

// projectOf is the index of the innermost project file is in, or -1.
func projectOf(projects []model.Project, file string) int {
	best, bestLen := -1, 0
	for i, proj := range projects {
		dir := proj.Path.Raw()
		if _, ok := cutPathPrefix(file, dir); ok && len(dir) > bestLen {
			best, bestLen = i, len(dir)
		}
	}
	return best
}

func worst(fs []finding.Finding) finding.Severity {
	w := finding.Severity(-1)
	for _, f := range fs {
		w = max(w, f.Severity)
	}
	return w
}

func (p *Printer) groups(v ScanView) {
	user, projects := grouped(v)
	if len(user.findings) > 0 {
		p.blank()
		p.emit(line{{text: "your user config", tone: bold}, {text: own(p.sep() + "applies to every project"), tone: dim}})
		p.spacedTree(p.findingNodes(v, user.findings, model.Path{}))
	}
	for _, g := range projects {
		p.blank()
		p.projectGroup(v, g)
	}
}

func (p *Printer) projectGroup(v ScanView, g group) {
	proj := *g.project
	head := line{{text: escape(p.short(proj.Path, model.Path{}, v.Home)), tone: bold}, {text: "  "}}
	var agents []model.Agent
	for _, o := range proj.Origins {
		if o.Agent != model.AgentJarx && !slices.Contains(agents, o.Agent) {
			agents = append(agents, o.Agent)
		}
	}
	for i, a := range agents {
		if i > 0 {
			head = append(head, seg{text: own(p.sep())})
		}
		level := trustOf(proj, a)
		head = append(head, seg{text: own(string(a) + " ")}, seg{text: own(level), tone: trustTone(level)})
	}
	if proj.Status != model.ProjectOK {
		p.emit(append(head, seg{text: own(p.sep() + string(proj.Status) + ", not scanned"), tone: dim}))
		return
	}
	if len(g.findings) == 0 {
		head = append(head, seg{text: own(p.sep() + "no findings"), tone: dim})
	}
	p.emit(head)
	nodes := p.findingNodes(v, g.findings, proj.Path)
	if loads := p.loads(proj); loads != nil {
		nodes = append(nodes, loads)
	}
	p.spacedTree(nodes)
}

// capped picks the findings to show. Unless --all, a long list keeps every
// critical and high finding and fills up to maxShown with the rest.
func capped(fs []finding.Finding, all bool) ([]finding.Finding, []finding.Finding) {
	if all || len(fs) <= maxShown {
		return fs, nil
	}
	var shown, hidden []finding.Finding
	for _, f := range fs {
		if f.Severity >= finding.High || len(shown) < maxShown {
			shown = append(shown, f)
		} else {
			hidden = append(hidden, f)
		}
	}
	return shown, hidden
}

// findingNodes lays out findings worst first, with a count of any the cap
// left out.
func (p *Printer) findingNodes(v ScanView, fs []finding.Finding, base model.Path) []node {
	shown, hidden := capped(fs, v.All)
	nodes := make([]node, 0, len(shown)+1)
	for _, f := range shown {
		nodes = append(nodes, p.findingNode(v, f, base))
	}
	if len(hidden) > 0 {
		nodes = append(nodes, p.moreNode(hidden))
	}
	return nodes
}

// moreNode counts the findings left out, by severity.
func (p *Printer) moreNode(hidden []finding.Finding) node {
	left := map[finding.Severity]int{}
	for _, f := range hidden {
		left[f.Severity]++
	}
	var parts []string
	for _, s := range severities {
		if left[s] > 0 {
			label, _ := sevLabel(s)
			parts = append(parts, strconv.Itoa(left[s])+" "+strings.TrimSpace(label))
		}
	}
	text := p.Style.glyphs().ell + " " + strconv.Itoa(len(hidden)) + " more: " + strings.Join(parts, p.sep()) + "  (jarx scan --all)"
	return node{line{{text: own(text), tone: dim}}}
}

// shortID drops the JARX- prefix, which every rule has.
func shortID(id string) string { return strings.TrimPrefix(id, "JARX-") }

// capital starts s with a capital letter, as a headline.
func capital(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[n:]
}

// findingParts is a finding's pieces, ready to lay out.
type findingParts struct {
	head  line
	id    seg
	where string
	ev    string
	rule  finding.Rule
	known bool
}

func (p *Printer) parts(v ScanView, f finding.Finding, base model.Path) findingParts {
	label, t := sevLabel(f.Severity)
	rule, known := v.Rules.Lookup(f.RuleID)
	title := f.RuleID
	if known {
		title = capital(rule.Title)
	}
	where := p.short(f.Origin.File, base, v.Home)
	if f.Origin.Line > 0 {
		where += ":" + strconv.Itoa(f.Origin.Line)
	}
	return findingParts{
		head:  line{{text: label, tone: t}, {text: "  " + own(title)}},
		id:    seg{text: own(shortID(f.RuleID)), tone: dim},
		where: escape(where),
		ev:    escape(shortenIn(f.Evidence.String(), base, v.Home)),
		rule:  rule, known: known,
	}
}

func (p *Printer) findingNode(v ScanView, f finding.Finding, base model.Path) node {
	fp := p.parts(v, f, base)
	head := fp.head
	// The rule ID sits right after the title, as close as the severity is.
	// When the line has no room for it, it moves down next to the file.
	where := line{{text: fp.where, tone: dim}}
	if branchCells+head.cells()+minGap+cells(fp.id.text) <= p.Style.width() {
		head = append(head, seg{text: "  "}, fp.id)
	} else {
		where = line{fp.id, {text: "  " + fp.where, tone: dim}}
	}
	var detail []line
	switch {
	case v.All:
		detail = p.fullDetail(where, fp)
	case fp.ev == "":
		detail = []line{where}
	case p.Style.width() >= wideLayout:
		detail = []line{append(where, seg{text: "  " + fp.ev})}
	default:
		detail = []line{where, {{text: fp.ev}}}
	}
	return p.branch(head, detail)
}

// branch hangs detail lines off a finding's title line: the first one on a
// tree branch, the rest under it.
func (p *Printer) branch(head line, detail []line) node {
	g := p.Style.glyphs()
	n := make(node, 0, 1+len(detail))
	n = append(n, head)
	for i, l := range detail {
		prefix := g.space
		if i == 0 {
			prefix = g.last
		}
		n = append(n, append(line{{text: prefix}}, l...))
	}
	return n
}

// fullDetail is a finding's detail for --all: nothing cut, so the evidence
// wraps instead, then the rule's full reason and its fix.
func (p *Printer) fullDetail(where line, fp findingParts) []line {
	room := p.Style.width() - 2*branchCells //nolint:mnd // the tree, then the finding's branch
	detail := []line{where}
	for _, w := range wrapWords(fp.ev, room) {
		detail = append(detail, line{{text: w}})
	}
	if !fp.known {
		return detail
	}
	for _, part := range []struct{ label, text string }{{"why: ", fp.rule.Detail}, {"fix: ", fp.rule.Fix}} {
		for i, w := range wrapWords(own(part.text), room-cells(part.label)) {
			label := strings.Repeat(" ", cells(part.label))
			if i == 0 {
				label = part.label
			}
			detail = append(detail, line{{text: label + w, tone: dim}})
		}
	}
	return detail
}

// wrapWords breaks s into lines of at most width columns at spaces. A word
// longer than a line is cut, so no line ever runs past the width.
func wrapWords(s string, width int) []string {
	if s == "" || width <= 0 {
		return nil
	}
	var out []string
	cur := ""
	for w := range strings.FieldsSeq(s) {
		pieces := chop(w, width)
		for _, piece := range pieces[:len(pieces)-1] {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			out = append(out, piece)
		}
		w = pieces[len(pieces)-1]
		switch {
		case cur == "":
			cur = w
		case cells(cur)+1+cells(w) <= width:
			cur += " " + w
		default:
			out = append(out, cur)
			cur = w
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// chop cuts a word into pieces of at most width columns.
func chop(w string, width int) []string {
	var out []string
	piece := ""
	for _, r := range w {
		if piece != "" && cells(piece)+runeCells(r) > width {
			out = append(out, piece)
			piece = ""
		}
		piece += string(r)
	}
	return append(out, piece)
}

// tally is what one agent loads in a project.
type tally struct{ instructions, imports, hooks, skills, servers int }

func (t tally) items() []string {
	return nonEmpty(
		ifPos(t.instructions, plural(t.instructions, "instruction", "instructions")),
		ifPos(t.imports, plural(t.imports, "import", "imports")),
		ifPos(t.hooks, plural(t.hooks, "hook", "hooks")),
		ifPos(t.skills, plural(t.skills, "skill", "skills")),
		ifPos(t.servers, plural(t.servers, "MCP server", "MCP servers")),
	)
}

// loadTally counts what each agent loads in proj, as what's in effect, in
// the order the agents come.
func loadTally(proj model.Project) ([]model.Agent, map[model.Agent]*tally) {
	by := map[model.Agent]*tally{}
	var order []model.Agent
	get := func(a model.Agent) *tally {
		if by[a] == nil {
			by[a] = &tally{}
			order = append(order, a)
		}
		return by[a]
	}
	for _, in := range proj.Instructions {
		switch {
		case !in.Origin.InEffect:
		case in.Kind == model.InstructionImport:
			get(in.Origin.Agent).imports++
		default:
			get(in.Origin.Agent).instructions++
		}
	}
	countInEffect(proj.Hooks, func(h model.Hook) model.Origin { return h.Origin }, func(a model.Agent) { get(a).hooks++ })
	countInEffect(proj.Skills, func(s model.Skill) model.Origin { return s.Origin }, func(a model.Agent) { get(a).skills++ })
	countInEffect(proj.Servers, func(s model.Server) model.Origin { return s.Origin }, func(a model.Agent) { get(a).servers++ })
	return order, by
}

// countInEffect calls add with the agent of each item that's in effect.
func countInEffect[T any](items []T, origin func(T) model.Origin, add func(model.Agent)) {
	for _, it := range items {
		if o := origin(it); o.InEffect {
			add(o.Agent)
		}
	}
}

// loads says what each agent loads in a project, wrapping onto more lines
// on a narrow terminal.
func (p *Printer) loads(proj model.Project) node {
	order, by := loadTally(proj)
	var items []string
	for _, a := range order {
		if parts := by[a].items(); len(parts) > 0 {
			parts[0] = string(a) + " " + parts[0]
			items = append(items, parts...)
		}
	}
	if len(items) == 0 {
		return nil
	}
	return p.wrapList("loads here: ", items)
}

// wrapList lays out items after a label, joined by the list separator,
// starting a new line under the first item when one would run past the
// width.
func (p *Printer) wrapList(label string, items []string) node {
	indent := strings.Repeat(" ", cells(label))
	room := p.Style.width() - branchCells
	var n node
	cur := line{{text: own(label), tone: dim}}
	for i, it := range items {
		piece := own(it)
		if i > 0 {
			piece = own(p.sep()) + piece
		}
		if i > 0 && cur.cells()+cells(piece) > room {
			n = append(n, cur)
			cur = line{{text: indent}, {text: own(it)}}
			continue
		}
		cur = append(cur, seg{text: piece})
	}
	return append(n, cur)
}
