package snapshot

import (
	"cmp"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/redact"
)

// ChangeKind is how an item changed.
type ChangeKind string

// Change kinds.
const (
	Added   ChangeKind = "added"
	Removed ChangeKind = "removed"
	Changed ChangeKind = "changed"
)

// Change is one item that's new, gone or different. What says how a changed
// item differs.
type Change struct {
	Change ChangeKind
	Item   Item
	What   redact.Text
}

func id(it Item) string {
	return it.Project.String() + "\x00" + string(it.Kind) + "\x00" + it.Key.String()
}

// kindOrder lists the kinds in the order the diff shows them.
//
//nolint:gochecknoglobals // fixed list, read only
var kindOrder = []Kind{KindFinding, KindUnknown, KindProject, KindInstruction, KindSkill, KindHook, KindRule, KindOption, KindConfig}

// Diff says what changed from old to cur: by project, then by kind, then by
// key.
func Diff(s *redact.Scrubber, old, cur Snapshot) []Change {
	before := map[string]Item{}
	for _, it := range old.Items {
		before[id(it)] = it
	}
	now := map[string]bool{}
	var out []Change
	for _, it := range cur.Items {
		now[id(it)] = true
		was, ok := before[id(it)]
		switch {
		case !ok:
			out = append(out, Change{Change: Added, Item: it})
		default:
			if what := differences(was, it); what != "" {
				t, _ := s.Scrub(what)
				out = append(out, Change{Change: Changed, Item: it, What: t})
			}
		}
	}
	for _, it := range old.Items {
		if !now[id(it)] {
			out = append(out, Change{Change: Removed, Item: it})
		}
	}
	slices.SortStableFunc(out, func(a, b Change) int {
		return cmp.Or(
			cmp.Compare(a.Item.Project.String(), b.Item.Project.String()),
			cmp.Compare(slices.Index(kindOrder, a.Item.Kind), slices.Index(kindOrder, b.Item.Kind)),
			cmp.Compare(a.Item.Key.String(), b.Item.Key.String()),
		)
	})
	return out
}

// differences says how an item's state changed, or "".
func differences(was, now Item) string {
	var parts []string
	switch {
	case !was.InEffect && now.InEffect:
		parts = append(parts, "now in effect")
	case was.InEffect && !now.InEffect:
		p := "now not in effect"
		if !now.Why.IsZero() {
			p += ": " + now.Why.String()
		}
		parts = append(parts, p)
	case !now.InEffect && was.Why.String() != now.Why.String():
		parts = append(parts, "the reason it isn't in effect is now: "+now.Why.String())
	}
	if was.Hash != now.Hash {
		parts = append(parts, "content changed")
	}
	if was.Value.String() != now.Value.String() {
		parts = append(parts, "was "+orNone(was.Value)+", now "+orNone(now.Value))
	}
	return strings.Join(parts, "; ")
}

func orNone(t redact.Text) string {
	if t.IsZero() {
		return "none"
	}
	return t.String()
}
