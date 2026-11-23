package snapshot

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/nickelsec/jarx/internal/jarxdir"
	"github.com/nickelsec/jarx/internal/redact"
)

// Dir is where snapshots live, inside jarx's state dir.
const Dir = "snapshots"

// Keep is how many snapshots jarx keeps.
const Keep = 20

const (
	ext        = ".json"
	nameTime   = "20060102T150405.000000000Z" // sorts in time order
	suffixLen  = 3                            // random bytes, so two scans in one instant don't clash
	fileFormat = "2006-01-02T15:04:05.999999999Z07:00"
)

// file is a snapshot as it's stored. Every string in it came from a masked
// redact.Text or is jarx's own, and it goes back through the scrubber when
// it's read.
type file struct {
	Version int        `json:"version"`
	Taken   string     `json:"taken"`
	Items   []fileItem `json:"items"`
}

type fileItem struct {
	Project  string `json:"project,omitempty"`
	Kind     Kind   `json:"kind"`
	Key      string `json:"key"`
	InEffect bool   `json:"inEffect,omitempty"`
	Why      string `json:"why,omitempty"`
	Hash     string `json:"hash,omitempty"`
	Value    string `json:"value,omitempty"`
}

// Save writes snap and removes all but the newest Keep snapshots.
func Save(d *jarxdir.Dir, snap Snapshot) error {
	f := file{Version: Version, Taken: snap.Taken.UTC().Format(fileFormat), Items: make([]fileItem, 0, len(snap.Items))}
	for _, it := range snap.Items {
		f.Items = append(f.Items, fileItem{
			Project: it.Project.String(), Kind: it.Kind, Key: it.Key.String(), InEffect: it.InEffect,
			Why: it.Why.String(), Hash: it.Hash, Value: it.Value.String(),
		})
	}
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("encoding the snapshot: %w", err)
	}
	suffix := make([]byte, suffixLen)
	_, _ = rand.Read(suffix)
	name := Dir + "/" + snap.Taken.UTC().Format(nameTime) + "-" + hex.EncodeToString(suffix) + ext
	if err := d.WriteFile(name, data); err != nil {
		return fmt.Errorf("saving the snapshot: %w", err)
	}
	return prune(d)
}

// names lists the snapshot files, oldest first.
func names(d *jarxdir.Dir) ([]string, error) {
	entries, err := d.ReadDir(Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("listing snapshots: %w", err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ext) {
			out = append(out, e.Name())
		}
	}
	slices.Sort(out)
	return out, nil
}

func prune(d *jarxdir.Dir) error {
	all, err := names(d)
	if err != nil {
		return err
	}
	for len(all) > Keep {
		if err := d.Remove(Dir + "/" + all[0]); err != nil {
			return fmt.Errorf("removing an old snapshot: %w", err)
		}
		all = all[1:]
	}
	return nil
}

// Latest reads the newest snapshot. With none saved it returns a zero
// Snapshot. One it can't use, broken or from a newer jarx, is a zero
// Snapshot and a note saying why, never an error: the scan goes on without
// a diff. The error is only for a state dir it can't list.
func Latest(d *jarxdir.Dir, s *redact.Scrubber) (Snapshot, string, error) {
	all, err := names(d)
	if err != nil || len(all) == 0 {
		return Snapshot{}, "", err
	}
	data, err := d.ReadFile(Dir + "/" + all[len(all)-1])
	if err != nil {
		return Snapshot{}, "couldn't read the last snapshot", nil //nolint:nilerr // a bad snapshot is a note, not a failed scan
	}
	var f file
	if json.Unmarshal(data, &f) != nil {
		return Snapshot{}, "couldn't read the last snapshot: it isn't valid", nil //nolint:nilerr // a note, as above
	}
	if f.Version > Version {
		return Snapshot{}, "the last snapshot is from a newer jarx, so there's nothing to compare against", nil
	}
	taken, err := time.Parse(fileFormat, f.Taken)
	if err != nil {
		return Snapshot{}, "couldn't read the last snapshot: its time isn't valid", nil //nolint:nilerr // a note, as above
	}
	text := func(v string) redact.Text {
		t, _ := s.Scrub(v)
		return t
	}
	snap := Snapshot{Taken: taken, Items: make([]Item, 0, len(f.Items))}
	for _, it := range f.Items {
		snap.Items = append(snap.Items, Item{
			Project: text(it.Project), Kind: it.Kind, Key: text(it.Key), InEffect: it.InEffect,
			Why: text(it.Why), Hash: it.Hash, Value: text(it.Value),
		})
	}
	return snap, "", nil
}
