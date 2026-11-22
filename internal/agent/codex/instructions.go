package codex

import (
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
)

// AGENTS.md discovery, from developers.openai.com/codex/guides/agents-md:
// the global file is $CODEX_HOME/AGENTS.override.md, else AGENTS.md (the
// first non-empty one). Then each dir from the project root down to the
// working dir adds at most one file: AGENTS.override.md, then AGENTS.md,
// then the project_doc_fallback_filenames, skipping empty files. Files are
// joined root first.
//
// The size cap, project_doc_max_bytes (32 KiB by default), is described two
// ways: the AGENTS.md guide says Codex stops adding files once their
// combined size reaches it, and the advanced config page says it's how much
// to read from each file. jarx marks a file off only when it's past the cap
// under the per-file reading, which cuts the least, so it never says the
// agent doesn't see something it may see. What the combined reading would
// cut goes in a note. jarx always keeps the whole file for the rules.

// defaultDocCap is project_doc_max_bytes when nothing sets it.
const defaultDocCap = 32 << 10

const (
	nameOverride = "AGENTS.override.md"
	nameAgents   = "AGENTS.md"
	keyDocCap    = "project_doc_max_bytes"
	keyFallbacks = "project_doc_fallback_filenames"
)

// RepoChangesInstructions is the finding for a project config that changes
// which instructions Codex loads: the size cap or the fallback filenames.
func RepoChangesInstructions() finding.Rule {
	return finding.Rule{
		ID:       "JARX-CODEX-006",
		Severity: finding.Medium,
		Title:    "a repository changes which instructions Codex loads",
		Fix:      "check the project's project_doc_max_bytes and project_doc_fallback_filenames",
	}
}

// The adapter reads instructions.
var _ agent.InstructionReader = Adapter{}

// Instructions lists the AGENTS.md chain Codex builds for each ok project.
// Parse problems in config files are reported by Settings, not again here.
func (Adapter) Instructions(c agent.Context, projects []model.Project) ([]model.Instruction, []finding.Finding) {
	s := &settings{c: c}
	s.load()
	var findings []finding.Finding
	for i := range projects {
		p := &projects[i]
		if p.Status != model.ProjectOK {
			continue
		}
		v := s.forProject(*p)
		r := &chainReader{v: v}
		p.Instructions = append(p.Instructions, r.build(p.Path.Raw())...)
		findings = append(findings, v.instructionFindings()...)
	}
	return nil, findings
}

// raw returns the value of key from the highest loaded layer that sets it.
func (v *view) raw(key string) (any, *layer) {
	for _, l := range v.loaded() {
		if val, ok := l.raw[key]; ok {
			return val, l
		}
	}
	return nil, nil
}

// docCap is the effective project_doc_max_bytes and the layer that set it.
func (v *view) docCap() (int, *layer) {
	val, l := v.raw(keyDocCap)
	if n, ok := val.(int64); ok && n >= 0 {
		return int(n), l
	}
	return defaultDocCap, nil
}

func (v *view) fallbacks() []string {
	val, _ := v.raw(keyFallbacks)
	list, _ := val.([]any)
	var out []string
	for _, x := range list {
		if s, ok := x.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// instructionFindings flags a loaded project layer that sets the cap or the
// fallback filenames.
func (v *view) instructionFindings() []finding.Finding {
	var out []finding.Finding
	for _, l := range v.loaded() {
		if l.origin.Scope != model.ScopeProject {
			continue
		}
		var what []string
		if n, ok := l.raw[keyDocCap].(int64); ok {
			what = append(what, "sets project_doc_max_bytes = "+strconv.FormatInt(n, 10)+" (the default is "+strconv.Itoa(defaultDocCap)+")")
		}
		if _, ok := l.raw[keyFallbacks]; ok {
			what = append(what, "sets project_doc_fallback_filenames, so other files load as instructions")
		}
		if len(what) > 0 {
			ev := v.s.text(l.origin.File.Text().String() + " " + strings.Join(what, " and "))
			out = append(out, RepoChangesInstructions().New(l.origin, ev))
		}
	}
	return out
}

// chainReader builds one project's AGENTS.md chain.
type chainReader struct {
	v     *view
	out   []model.Instruction
	sizes []int // raw byte size of each file in out, which the cap counts
}

// build lists the global file, then one file per dir from the project root
// down, then applies the cap.
func (r *chainReader) build(projectDir string) []model.Instruction {
	var winners []int
	if w := r.dir(codexHome(r.v.s.c.Env), model.ScopeUser, []string{nameOverride, nameAgents}); w >= 0 {
		winners = append(winners, w)
	}
	names := append([]string{nameOverride, nameAgents}, r.v.fallbacks()...)
	dirs := r.v.s.projectDirs(projectDir)
	slices.Reverse(dirs)
	for _, d := range dirs {
		if w := r.dir(d, model.ScopeProject, names); w >= 0 {
			winners = append(winners, w)
		}
	}
	r.applyCap(winners)
	return r.out
}

// dir adds every candidate file in one dir that exists. The first non-empty
// one is in effect; it returns its index, or -1.
func (r *chainReader) dir(dir string, scope model.Scope, names []string) int {
	won := -1
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, status := r.read(path)
		if status == model.ReadMissing {
			continue
		}
		in := model.Instruction{
			Kind: model.InstructionFile, Path: model.NewPath(r.v.s.c.Scrub, path), Load: model.LoadLaunch, Read: status,
			Origin: model.Origin{Agent: model.AgentCodex, File: model.NewPath(r.v.s.c.Scrub, path), Scope: scope, InEffect: true},
		}
		why := ""
		switch {
		case won >= 0:
			why = "Codex uses one file per dir, and " + filepath.Base(r.out[won].Path.Raw()) + " comes first here"
		case status == model.ReadOK && strings.TrimSpace(string(data)) == "":
			why = "it's empty, so Codex skips it"
		case status == model.ReadOK:
			won = len(r.out)
		}
		if status == model.ReadOK {
			in.Text = r.v.s.text(string(data))
		}
		if why != "" {
			in.Origin.InEffect, in.Origin.Why = false, r.v.s.text(why)
		}
		r.out = append(r.out, in)
		r.sizes = append(r.sizes, len(data))
	}
	return won
}

// read reads a file through fsys and says how that went.
func (r *chainReader) read(path string) ([]byte, model.ReadStatus) {
	data, err := r.v.s.c.Files.ReadFile(path)
	switch {
	case err == nil:
		return data, model.ReadOK
	case errors.Is(err, fs.ErrNotExist):
		return nil, model.ReadMissing
	case errors.Is(err, fsys.ErrCredential):
		return nil, model.ReadCredential
	case errors.Is(err, fsys.ErrNetworkPath):
		return nil, model.ReadNetwork
	case errors.Is(err, fsys.ErrNotRegular):
		return nil, model.ReadNotRegular
	case errors.Is(err, fsys.ErrTooLarge):
		return nil, model.ReadTooLarge
	default:
		return nil, model.ReadFailed
	}
}

// applyCap sets each winning file's limit under the per-file reading and
// notes what the combined reading would cut.
func (r *chainReader) applyCap(winners []int) {
	limit, from := r.v.docCap()
	source := "the default"
	if from != nil {
		source = string(from.origin.Scope) + " settings"
	}
	total := 0
	for _, w := range winners {
		in := &r.out[w]
		size := r.sizes[w] // raw bytes: masking a secret changes the text's length
		if limit == 0 {
			in.Origin.InEffect, in.Origin.Why = false, r.v.s.text("project_doc_max_bytes is 0 (from "+source+"), so Codex reads none of it")
			continue
		}
		var notes []string
		if size > limit {
			in.Limit = limit
			notes = append(notes, "Codex reads the first "+strconv.Itoa(limit)+" bytes (project_doc_max_bytes from "+source+")")
		}
		switch {
		case total >= limit:
			notes = append(notes, "under the combined reading in the AGENTS.md guide, earlier files already fill the cap, so Codex stops before this one")
		case total+size > limit:
			notes = append(notes, "under the combined reading in the AGENTS.md guide, Codex cuts it after byte "+strconv.Itoa(limit-total))
		}
		total += size
		if len(notes) > 0 {
			in.Note = r.v.s.text(strings.Join(notes, "; "))
		}
	}
}
