package report

import (
	"strconv"
	"time"

	"github.com/nickelsec/jarx/internal/snapshot"
)

// changeMarks is how each kind of change starts its line.
//
//nolint:gochecknoglobals // fixed list, read only
var changeMarks = map[snapshot.ChangeKind]string{snapshot.Added: "+", snapshot.Removed: "-", snapshot.Changed: "~"}

// Changes prints what changed since the last snapshot, taken at since. A
// zero since means there's nothing to compare against, and note says why
// when it's more than this being the first scan. A failed save of this
// scan's snapshot is said last.
func (p *Printer) Changes(since time.Time, note string, changes []snapshot.Change, saveErr error) {
	switch {
	case since.IsZero() && note == "":
		p.Out.Printf("changes: no earlier snapshot\n")
	case since.IsZero():
		p.Out.Printf("changes: %s\n", p.text(note))
	case len(changes) == 0:
		p.Out.Printf("changes since %s: none\n", p.text(since.UTC().Format("2006-01-02 15:04:05")+" UTC"))
	default:
		p.Out.Printf("changes since %s (%s)\n", p.text(since.UTC().Format("2006-01-02 15:04:05")+" UTC"), p.text(strconv.Itoa(len(changes))))
		p.changeLines(changes)
	}
	if saveErr != nil {
		p.Out.Printf("  couldn't save this scan's snapshot: %s\n", p.text(saveErr.Error()))
	}
}

// changeLines lists the changes, scan-wide ones first, then each project's
// under its dir.
func (p *Printer) changeLines(changes []snapshot.Change) {
	project := ""
	for _, c := range changes {
		indent := "  "
		if dir := c.Item.Project.String(); dir != "" {
			if dir != project {
				p.Out.Printf("  in %s\n", c.Item.Project)
				project = dir
			}
			indent = "    "
		}
		what := ""
		if !c.What.IsZero() {
			what = ": " + c.What.String()
		}
		p.Out.Printf("%s%s %s  %s%s\n", p.text(indent), p.text(changeMarks[c.Change]), p.text(string(c.Item.Kind)), c.Item.Key, p.text(what))
	}
}
