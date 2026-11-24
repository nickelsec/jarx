package codex

import (
	"io/fs"
	"path/filepath"
	"slices"

	"github.com/nickelsec/jarx/internal/model"
)

// Local memories, from learn.chatgpt.com/docs/customization/memories: Codex
// keeps them under $CODEX_HOME, in memories/ (v1) and memories_v2/ (v2),
// and the desktop app reads both during the migration. They're off by
// default; features.memories = true turns them on, and
// memories.use_memories = false stops existing ones being injected into new
// sessions. Codex puts them into context, so jarx treats them like any
// other instruction text: the poison and secret rules run on them, and a
// secret in one is one the agent sees.
//
// The docs call the files generated summaries and supporting evidence, and
// don't say which of them a session reads, so jarx counts every file and
// says so.

// memoryDirs are the two local memory stores.
//
//nolint:gochecknoglobals // fixed list, read only
var memoryDirs = []string{"memories", "memories_v2"}

// maxMemoryFiles caps how many files one store adds.
const maxMemoryFiles = 200

const memoryNote = "Codex doesn't document which memory files it reads, so jarx counts every file in the store"

// memories adds the memory files, in effect when memories are on.
func (r *chainReader) memories() {
	why := r.v.memoriesOff()
	for _, store := range memoryDirs {
		root := filepath.Join(codexHome(r.v.s.c.Env), store)
		var paths []string
		_ = r.v.s.c.Files.Walk(root, func(path string, d fs.DirEntry) error {
			if d.Type().IsRegular() && len(paths) < maxMemoryFiles {
				paths = append(paths, path)
			}
			return nil
		})
		slices.Sort(paths)
		for _, path := range paths {
			data, status := r.read(path)
			if status == model.ReadMissing {
				continue
			}
			in := model.Instruction{
				Kind: model.InstructionMemory, Path: model.NewPath(r.v.s.c.Scrub, path), Load: model.LoadOnDemand, Read: status,
				Note:   r.v.s.text(memoryNote),
				Origin: model.Origin{Agent: model.AgentCodex, File: model.NewPath(r.v.s.c.Scrub, path), Scope: model.ScopeUser, InEffect: why == ""},
			}
			if status == model.ReadOK {
				in.Text = r.v.s.text(string(data))
			}
			if why != "" {
				in.Origin.Why = r.v.s.text(why)
			}
			r.out = append(r.out, in)
			r.sizes = append(r.sizes, len(data))
		}
	}
}

// memoriesOff says why memories don't load, or "".
func (v *view) memoriesOff() string {
	if on, _ := v.nested("features", "memories").(bool); !on {
		return "memories are off: features.memories isn't true, and it's off by default"
	}
	if use, ok := v.nested("memories", "use_memories").(bool); ok && !use {
		return "memories.use_memories is false, so Codex doesn't inject them"
	}
	return ""
}

// nested is table.key from the highest loaded layer that sets it.
func (v *view) nested(table, key string) any {
	for _, l := range v.loaded() {
		if t, ok := l.raw[table].(map[string]any); ok {
			if val, ok := t[key]; ok {
				return val
			}
		}
	}
	return nil
}
