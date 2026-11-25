package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"time"

	"github.com/nickelsec/jarx/internal/jarxdir"
)

// RunsFile is the scan log in jarx's state dir: one line of counts per
// scan, so the dashboard can show the history. It holds numbers and times
// only, never text from a scan.
const RunsFile = "runs.json"

// KeepRuns is how many runs the log keeps. Total counts every run.
const KeepRuns = 200

// Run is one scan's counts.
type Run struct {
	Taken       time.Time
	Findings    int  // findings the scan found
	NewFindings int  // findings that weren't in the scan before
	Added       int  // every item added since the scan before, findings too
	Removed     int  // every item removed
	Changed     int  // every item changed
	First       bool // nothing to compare against
}

// RunOf is a scan's counts: its findings, and what changed since the scan
// before. first says there was none.
func RunOf(taken time.Time, findings int, changes []Change, first bool) Run {
	r := Run{Taken: taken, Findings: findings, First: first}
	for _, c := range changes {
		switch c.Change {
		case Added:
			r.Added++
			if c.Item.Kind == KindFinding {
				r.NewFindings++
			}
		case Removed:
			r.Removed++
		case Changed:
			r.Changed++
		}
	}
	return r
}

// RunLog is the newest runs, newest first, and how many there were in all.
type RunLog struct {
	Total int
	Runs  []Run
}

type runsFile struct {
	Version int       `json:"version"`
	Total   int       `json:"total"`
	Runs    []runLine `json:"runs"` // oldest first
}

type runLine struct {
	Taken       string `json:"taken"`
	Findings    int    `json:"findings"`
	NewFindings int    `json:"newFindings,omitempty"`
	Added       int    `json:"added,omitempty"`
	Removed     int    `json:"removed,omitempty"`
	Changed     int    `json:"changed,omitempty"`
	First       bool   `json:"first,omitempty"`
}

// Runs reads the log. With none it's empty. One it can't use, broken or
// from a newer jarx, is empty with a note saying why, never an error.
func Runs(d *jarxdir.Dir) (RunLog, string) {
	f, note := readRuns(d)
	log := RunLog{Total: f.Total, Runs: make([]Run, 0, len(f.Runs))}
	for _, l := range slices.Backward(f.Runs) {
		taken, err := time.Parse(fileFormat, l.Taken)
		if err != nil {
			continue // a line with a bad time is skipped, the rest still show
		}
		r := Run{Taken: taken, Findings: l.Findings, NewFindings: l.NewFindings,
			Added: l.Added, Removed: l.Removed, Changed: l.Changed, First: l.First}
		log.Runs = append(log.Runs, r)
	}
	return log, note
}

func readRuns(d *jarxdir.Dir) (runsFile, string) {
	data, err := d.ReadFile(RunsFile)
	if errors.Is(err, fs.ErrNotExist) {
		return runsFile{}, ""
	}
	if err != nil {
		return runsFile{}, "couldn't read the scan history"
	}
	var f runsFile
	if json.Unmarshal(data, &f) != nil {
		return runsFile{}, "couldn't read the scan history: it isn't valid"
	}
	if f.Version > Version {
		return runsFile{}, "the scan history is from a newer jarx"
	}
	return f, ""
}

// AppendRun adds r to the log and keeps the newest KeepRuns. A log it
// can't read starts over.
func AppendRun(d *jarxdir.Dir, r Run) error {
	f, _ := readRuns(d)
	f.Version = Version
	f.Total++
	f.Runs = append(f.Runs, runLine{Taken: r.Taken.UTC().Format(fileFormat), Findings: r.Findings, NewFindings: r.NewFindings,
		Added: r.Added, Removed: r.Removed, Changed: r.Changed, First: r.First})
	if over := len(f.Runs) - KeepRuns; over > 0 {
		f.Runs = f.Runs[over:]
	}
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("encoding the scan history: %w", err)
	}
	if err := d.WriteFile(RunsFile, data); err != nil {
		return fmt.Errorf("saving the scan history: %w", err)
	}
	return nil
}
