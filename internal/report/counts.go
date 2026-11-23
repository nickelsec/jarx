package report

import (
	"slices"
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
)

// counts is what the scanned block counts, each thing once even when
// several projects share it.
type counts struct {
	projects, notScanned          int
	notScannedWhy                 map[string]int
	instructions, imports         int
	credentials, unread           int
	skills, hooks, scripts        int
	rules, modes, configs         int
	unknowns                      int
	servers, serversOff, approval int
	tooLarge, unreadable, partial int
}

// counter fills counts, keeping each thing once by a key.
type counter struct {
	c    counts
	seen map[string]bool
}

func (k *counter) once(key ...string) bool {
	id := strings.Join(key, "\x00")
	if k.seen[id] {
		return false
	}
	k.seen[id] = true
	return true
}

func countAll(v ScanView) counts {
	k := &counter{c: counts{notScannedWhy: map[string]int{}}, seen: map[string]bool{}}
	for _, proj := range v.Projects {
		k.project(proj)
	}
	for _, in := range v.Instructions {
		k.instruction(in)
	}
	k.c.unknowns = len(v.Unknown)
	k.findings(v.Findings)
	return k.c
}

func (k *counter) project(proj model.Project) {
	k.c.projects++
	if proj.Status != model.ProjectOK {
		k.c.notScanned++
		k.c.notScannedWhy[string(proj.Status)]++
	}
	for _, in := range proj.Instructions {
		k.instruction(in)
	}
	for _, sk := range proj.Skills {
		if k.once("skill", sk.Path.Raw()) {
			k.c.skills++
		}
	}
	k.hooks(proj.Hooks)
	for _, perm := range proj.Permissions {
		k.permissions(perm)
	}
	k.servers(proj.Servers)
	for _, cfg := range proj.Configs {
		if k.once("config", cfg.Origin.File.Raw()) {
			k.c.configs++
		}
	}
}

func (k *counter) instruction(in model.Instruction) {
	if !k.once("instruction", in.Path.Raw(), string(in.Origin.Agent)) {
		return
	}
	if in.Kind == model.InstructionImport {
		k.c.imports++
	} else {
		k.c.instructions++
	}
	if in.Read == model.ReadCredential {
		k.c.credentials++
	} else if in.Read != model.ReadOK && in.Read != model.ReadMissing {
		k.c.unread++
	}
}

func (k *counter) hooks(hs []model.Hook) {
	for _, h := range hs {
		if k.once("hook", h.Origin.File.Raw(), h.Event.String(), h.Matcher.String(), h.Run.String()) {
			k.c.hooks++
		}
		if h.ScriptRead == model.ReadOK && k.once("script", h.Script.Raw()) {
			k.c.scripts++
		}
	}
}

func (k *counter) permissions(perm model.Permissions) {
	for _, r := range perm.Rules {
		if k.once("rule", r.Origin.File.Raw(), string(r.Action), r.Rule.String()) {
			k.c.rules++
		}
	}
	for _, d := range perm.AdditionalDirectories {
		if k.once("rule", d.Origin.File.Raw(), "additionalDirectories", d.Value.String()) {
			k.c.rules++
		}
	}
	for _, l := range perm.DefaultMode.Layers {
		if k.once("mode", l.Origin.File.Raw(), "defaultMode") {
			k.c.modes++
		}
	}
	for _, o := range perm.Options {
		for _, l := range o.Setting.Layers {
			if k.once("mode", l.Origin.File.Raw(), o.Key.String()) {
				k.c.modes++
			}
		}
	}
}

// findings counts what jarx skipped, from its own scan findings.
func (k *counter) findings(fs []finding.Finding) {
	for _, f := range fs {
		switch f.RuleID {
		case finding.SkippedTooLarge().ID:
			k.c.tooLarge++
		case finding.UnreadableRecord().ID:
			k.c.unreadable++
		case finding.WalkTruncated().ID:
			k.c.partial++
		}
	}
}

// scanRow is one line of the scanned block: what was counted, and a note
// about what wasn't.
type scanRow struct{ what, note []string }

func (c counts) rows(sep string) []scanRow {
	notScanned := make([]string, 0, len(c.notScannedWhy))
	for _, why := range sortedKeys(c.notScannedWhy) {
		notScanned = append(notScanned, strconv.Itoa(c.notScannedWhy[why])+" "+why)
	}
	rows := []scanRow{
		{[]string{plural(c.projects, "project", "projects")}, nonEmpty(join(notScanned, sep, ", not scanned"))},
		{[]string{plural(c.instructions, "instruction file", "instruction files"), plural(c.imports, "import", "imports")}, nonEmpty(
			ifPos(c.credentials, plural(c.credentials, "credential file not read", "credential files not read")),
			ifPos(c.unread, plural(c.unread, "file not read", "files not read")),
		)},
		{[]string{plural(c.skills, "skill", "skills"), plural(c.hooks, "hook", "hooks"), plural(c.scripts, "hook script", "hook scripts")}, nil},
		{[]string{plural(c.servers, "MCP server", "MCP servers")}, nonEmpty(
			ifPos(c.serversOff, plural(c.serversOff, "not started", "not started")),
			ifPos(c.approval, plural(c.approval, "approval unknown", "approval unknown")),
		)},
		{[]string{plural(c.rules, "permission rule", "permission rules"), plural(c.modes, "mode setting", "mode settings")}, nil},
		{[]string{plural(c.configs, "config file", "config files")},
			nonEmpty(ifPos(c.unknowns, plural(c.unknowns, "unknown setting", "unknown settings")))},
	}
	if skipped := nonEmpty(
		ifPos(c.tooLarge, plural(c.tooLarge, "file too large to read", "files too large to read")),
		ifPos(c.unreadable, plural(c.unreadable, "agent record unreadable", "agent records unreadable")),
		ifPos(c.partial, plural(c.partial, "project only partly listed", "projects only partly listed")),
	); len(skipped) > 0 {
		rows = append(rows, scanRow{[]string{"skipped"}, skipped})
	}
	return rows
}

// noteCol is the column the scanned block's notes start at.
const noteCol = 34

func (p *Printer) scanned(v ScanView) {
	p.emit(line{{text: "scanned", tone: bold}})
	rows := countAll(v).rows(p.sep())
	// Notes sit in a column after what was counted. When one doesn't fit
	// there, every note moves to its own line, so they stay lined up.
	inline := true
	for _, r := range rows {
		what, note := own(strings.Join(r.what, p.sep())), own(strings.Join(r.note, p.sep()))
		if note != "" && branchCells+max(noteCol, cells(what)+minGap)+cells(note) > p.Style.width() {
			inline = false
		}
	}
	nodes := make([]node, 0, len(rows))
	for _, r := range rows {
		what, note := own(strings.Join(r.what, p.sep())), own(strings.Join(r.note, p.sep()))
		l := line{{text: what}}
		switch {
		case note == "":
			nodes = append(nodes, node{l})
		case inline:
			pad := max(minGap, noteCol-cells(what))
			nodes = append(nodes, node{append(l, seg{text: strings.Repeat(" ", pad)}, seg{text: note, tone: dim})})
		default:
			nodes = append(nodes, node{l, line{{text: strings.Repeat(" ", minGap)}, {text: note, tone: dim}}})
		}
	}
	p.tree(nodes)
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func ifPos(n int, s string) string {
	if n > 0 {
		return s
	}
	return ""
}

func nonEmpty(xs ...string) []string {
	var out []string
	for _, x := range xs {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

func join(xs []string, sep, suffix string) string {
	if len(xs) == 0 {
		return ""
	}
	return strings.Join(xs, sep) + suffix
}

// servers counts MCP server definitions once per file and name, with the
// ones that won't start and the ones waiting on an approval jarx can't see.
func (k *counter) servers(ss []model.Server) {
	for _, s := range ss {
		if !k.once("server", s.Origin.File.Raw(), s.Name.String()) {
			continue
		}
		k.c.servers++
		switch s.Start {
		case model.StartNo:
			k.c.serversOff++
		case model.StartUnknown:
			k.c.approval++
		case model.StartYes, model.StartMaybe:
		}
	}
}
