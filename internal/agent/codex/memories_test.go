package codex

import (
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
)

func memoryChain(t *testing.T, files map[string]string) ([]string, []model.Instruction) {
	t.Helper()
	c := fakeHome(t, files)
	is, _ := instructionsFor(t, c, "/p", model.TrustTrusted)
	var mem []model.Instruction
	for _, i := range is {
		if i.Kind == model.InstructionMemory {
			mem = append(mem, i)
		}
	}
	got := chain(c, mem)
	slices.Sort(got)
	return got, mem
}

func TestMemoriesLoadWhenTheFeatureIsOn(t *testing.T) {
	got, mem := memoryChain(t, map[string]string{
		".codex/config.toml":                     "[features]\nmemories = true\n",
		".codex/memories/memory_summary.md":      "the user prefers tabs",
		".codex/memories_v2/notes/2026-11-20.md": "deploys go through the gateway",
	})

	if want := []string{".codex/memories/memory_summary.md*", ".codex/memories_v2/notes/2026-11-20.md*"}; !slices.Equal(got, want) {
		t.Fatalf("memories = %q, want %q: both stores, since the desktop app reads both", got, want)
	}
	for _, m := range mem {
		if m.Load != model.LoadOnDemand || m.Text.IsZero() || !strings.Contains(m.Note.String(), "doesn't document which") {
			t.Errorf("memory %s: load %q, text %q, note %q; want on demand, read, and a note that jarx counts every file", m.Path.Raw(), m.Load, m.Text, m.Note)
		}
		if m.Origin.Scope != model.ScopeUser {
			t.Errorf("memory %s scope = %s, want user", m.Path.Raw(), m.Origin.Scope)
		}
	}
}

func TestMemoriesAreOffByDefault(t *testing.T) {
	got, mem := memoryChain(t, map[string]string{".codex/memories/memory_summary.md": "the user prefers tabs"})

	if want := []string{".codex/memories/memory_summary.md"}; !slices.Equal(got, want) {
		t.Fatalf("memories = %q, want %q, not in effect", got, want)
	}
	if why := mem[0].Origin.Why.String(); !strings.Contains(why, "features.memories") {
		t.Errorf("why = %q, want it to name features.memories, which is off by default", why)
	}
}

func TestUseMemoriesFalseStopsThemLoading(t *testing.T) {
	got, mem := memoryChain(t, map[string]string{
		".codex/config.toml":                "[features]\nmemories = true\n\n[memories]\nuse_memories = false\n",
		".codex/memories/memory_summary.md": "the user prefers tabs",
	})

	if want := []string{".codex/memories/memory_summary.md"}; !slices.Equal(got, want) {
		t.Fatalf("memories = %q, want %q, not in effect", got, want)
	}
	if why := mem[0].Origin.Why.String(); !strings.Contains(why, "memories.use_memories") {
		t.Errorf("why = %q, want it to name memories.use_memories", why)
	}
}

func TestNoMemoryStoreMeansNoMemories(t *testing.T) {
	if got, _ := memoryChain(t, map[string]string{".codex/config.toml": "[features]\nmemories = true\n"}); len(got) != 0 {
		t.Errorf("memories = %q, want none", got)
	}
}
