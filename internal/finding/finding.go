// Package finding holds findings, severities and the rule registry. Rules are
// plain values: each analyzer exposes its own, and scan builds one Registry
// from all of them, which rejects duplicate IDs. There's no global registry.
package finding

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"unicode/utf8"

	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// Severity of a finding. Higher is worse.
type Severity int

// Severities.
const (
	Info Severity = iota + 1
	Medium
	High
	Critical
)

// String returns the severity's name.
func (s Severity) String() string {
	switch s {
	case Info:
		return "info"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	default:
		return fmt.Sprintf("severity(%d)", int(s))
	}
}

func (s Severity) valid() bool { return s >= Info && s <= Critical }

// Rule is one detection rule. ID, Title, Detail and Fix are jarx's own
// constants.
type Rule struct {
	ID       string // like JARX-MCP-001
	Severity Severity
	Title    string // the short reason, at most MaxTitle chars
	Detail   string // the reason in full, when the title leaves some out
	Fix      string // the fix hint
}

// MaxTitle is how long a title can be: the scan prints it on one line with
// the severity and the rule ID.
const MaxTitle = 42

// Finding is one thing a rule found.
type Finding struct {
	RuleID   string
	Severity Severity
	Origin   model.Origin
	Evidence redact.Text
}

// New makes a finding for this rule. The severity always comes from the rule.
func (r Rule) New(o model.Origin, evidence redact.Text) Finding {
	return Finding{RuleID: r.ID, Severity: r.Severity, Origin: o, Evidence: evidence}
}

var ruleIDRe = regexp.MustCompile(`^JARX-[A-Z]+-\d{3}$`)

// Registry is a checked set of rules.
type Registry struct {
	byID map[string]Rule
}

// NewRegistry checks every rule (ID format, unique ID, a valid severity, a
// title and a fix) and returns the set.
func NewRegistry(rules ...Rule) (*Registry, error) {
	r := &Registry{byID: make(map[string]Rule, len(rules))}
	for _, rule := range rules {
		switch {
		case !ruleIDRe.MatchString(rule.ID):
			return nil, fmt.Errorf("rule %q: id must look like JARX-MCP-001", rule.ID)
		case r.byID[rule.ID].ID != "":
			return nil, fmt.Errorf("rule %s: duplicate id", rule.ID)
		case !rule.Severity.valid():
			return nil, fmt.Errorf("rule %s: bad severity %d", rule.ID, int(rule.Severity))
		case rule.Title == "" || rule.Fix == "":
			return nil, fmt.Errorf("rule %s: needs a title and a fix", rule.ID)
		case utf8.RuneCountInString(rule.Title) > MaxTitle:
			return nil, fmt.Errorf("rule %s: title is over %d chars; put the rest in Detail", rule.ID, MaxTitle)
		}
		r.byID[rule.ID] = rule
	}
	return r, nil
}

// Lookup returns the rule with id.
func (r *Registry) Lookup(id string) (Rule, bool) {
	rule, ok := r.byID[id]
	return rule, ok
}

// Sort orders findings worst first, then by rule ID, file and line.
func Sort(fs []Finding) {
	slices.SortStableFunc(fs, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(b.Severity, a.Severity),
			cmp.Compare(a.RuleID, b.RuleID),
			cmp.Compare(a.Origin.File.Raw(), b.Origin.File.Raw()),
			cmp.Compare(a.Origin.Line, b.Origin.Line),
		)
	})
}

// SkippedTooLarge is jarx's own rule for a file fsys refused to read, so a
// skipped file always shows up and is never dropped silently.
func SkippedTooLarge() Rule {
	return Rule{
		ID:       "JARX-SCAN-001",
		Severity: Info,
		Title:    "file skipped, too large to read",
		Fix:      "check the file by hand. Files over 10 MiB aren't read.",
	}
}

// UnreadableRecord is jarx's own rule for an agent record file it couldn't
// parse. The evidence names the file and position, never the content.
func UnreadableRecord() Rule {
	return Rule{
		ID:       "JARX-SCAN-002",
		Severity: Info,
		Title:    "couldn't read an agent's records",
		Fix:      "check that the file is valid.",
	}
}

// WalkTruncated is jarx's own rule for a project with more files than jarx
// lists, so a cut-off walk is never silent.
func WalkTruncated() Rule {
	return Rule{
		ID:       "JARX-SCAN-003",
		Severity: Info,
		Title:    "stopped listing a very large project",
		Detail:   "stopped listing files in a very large project",
		Fix:      "files past the limit weren't checked. Scan a subfolder with jarx scan <path> to cover them.",
	}
}

// Rules returns the rules the finding package itself owns.
func Rules() []Rule {
	return []Rule{SkippedTooLarge(), UnreadableRecord(), WalkTruncated()}
}

// FromSkips turns every file fsys refused into an info finding.
func FromSkips(s *redact.Scrubber, skips []fsys.Skip) []Finding {
	rule := SkippedTooLarge()
	out := make([]Finding, 0, len(skips))
	for _, skip := range skips {
		origin := model.Origin{Agent: model.AgentJarx, File: model.NewPath(s, skip.Path), InEffect: true}
		evidence, _ := s.Scrub(fmt.Sprintf("skipped, %s (%d bytes, cap %d bytes)", skip.Reason, skip.Size, fsys.MaxReadSize))
		out = append(out, rule.New(origin, evidence))
	}
	return out
}
