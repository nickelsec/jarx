package catalog

import (
	_ "embed"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/nickelsec/jarx/internal/model"
)

//go:embed advisories.tsv
var advisoriesTSV string

// advisoriesChecked is when advisories.tsv was last checked against the
// GitHub security advisories of anthropics/claude-code and openai/codex.
const advisoriesChecked = "2026-11-24"

// AdvisoriesStamp is the date the advisory data is as of.
func AdvisoriesStamp() string { return advisoriesChecked }

// Advisory is one row of advisories.tsv: a published security advisory
// for an agent's CLI package.
type Advisory struct {
	Agent     model.Agent
	ID        string // the GHSA id
	Package   string
	Fixed     string
	Severity  string // the advisory's own: critical, high, medium or low
	Published string
	Summary   string
	affected  []constraint // all of them hold for an affected version
}

type constraint struct {
	op      string
	version [3]int
}

func (c constraint) holds(v [3]int) bool {
	n := compare(v, c.version)
	switch c.op {
	case ">=":
		return n >= 0
	case ">":
		return n > 0
	case "<=":
		return n <= 0
	case "<":
		return n < 0
	}
	return n == 0
}

type advisoryTable struct {
	rows []Advisory
	err  error
}

//nolint:gochecknoglobals // parsed once from the embedded file
var loadAdvisories = sync.OnceValue(func() advisoryTable {
	rows, err := parseAdvisories(advisoriesTSV)
	return advisoryTable{rows: rows, err: err}
})

// Advisories is every advisory for an agent's CLI. A broken advisories.tsv
// panics: it's embedded, and its test catches that.
func Advisories(a model.Agent) []Advisory {
	t := loadAdvisories()
	if t.err != nil {
		panic(t.err)
	}
	var out []Advisory
	for _, r := range t.rows {
		if r.Agent == a {
			out = append(out, r)
		}
	}
	return out
}

// AffectedBy is the advisories whose affected range holds version, worst
// first, then newest. A version jarx can't read matches none.
func AffectedBy(a model.Agent, version string) []Advisory {
	v, ok := parseVersion(version)
	if !ok {
		return nil
	}
	var out []Advisory
	for _, adv := range Advisories(a) {
		if !slices.ContainsFunc(adv.affected, func(c constraint) bool { return !c.holds(v) }) {
			out = append(out, adv)
		}
	}
	slices.SortStableFunc(out, func(x, y Advisory) int {
		if d := severityRank(y.Severity) - severityRank(x.Severity); d != 0 {
			return d
		}
		return strings.Compare(y.Published, x.Published)
	})
	return out
}

func severityRank(s string) int {
	return slices.Index([]string{"low", "medium", "high", "critical"}, s)
}

// CompareVersions compares the first x.y.z in each, and says whether both
// had one.
func CompareVersions(a, b string) (int, bool) {
	x, ok1 := parseVersion(a)
	y, ok2 := parseVersion(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	return compare(x, y), true
}

func compare(a, b [3]int) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

const advisoryColumns = 8

func parseAdvisories(tsv string) ([]Advisory, error) {
	var out []Advisory
	for n, line := range strings.Split(tsv, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != advisoryColumns {
			return nil, fmt.Errorf("advisories.tsv line %d: %d columns, want %d", n+1, len(f), advisoryColumns)
		}
		adv := Advisory{
			Agent: model.Agent(f[0]), ID: f[1], Package: f[2], Fixed: f[4], Severity: f[5], Published: f[6], Summary: f[7],
		}
		if severityRank(adv.Severity) < 0 {
			return nil, fmt.Errorf("advisories.tsv line %d: severity %q", n+1, adv.Severity)
		}
		for c := range strings.FieldsSeq(f[3]) {
			op := c[:len(c)-len(strings.TrimLeft(c, "<>="))]
			v, ok := parseVersion(c[len(op):])
			if !ok || !slices.Contains([]string{">=", ">", "<=", "<", "="}, op) {
				return nil, fmt.Errorf("advisories.tsv line %d: range %q", n+1, c)
			}
			adv.affected = append(adv.affected, constraint{op: op, version: v})
		}
		if len(adv.affected) == 0 {
			return nil, fmt.Errorf("advisories.tsv line %d: no affected range", n+1)
		}
		out = append(out, adv)
	}
	return out, nil
}
