// Package versions checks each agent install found on disk: whether its
// version is in a known security advisory, and whether the install that
// wins on PATH is the one you think it is. It only reads the model; no
// agent is ever run to ask its version.
package versions

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

const vulnerableFix = "update the agent (claude update, or the package manager it came from); jarx's advisory data is only as new as its build"

// VulnerableHigh is an install whose worst advisory is high or critical.
func VulnerableHigh() finding.Rule {
	return finding.Rule{
		ID: "JARX-VERSION-001", Severity: finding.High, Title: "Agent version has a high advisory",
		Detail: "this install's version is in the affected range of a published security advisory rated high or critical",
		Fix:    vulnerableFix,
	}
}

// VulnerableMedium is an install whose worst advisory is medium.
func VulnerableMedium() finding.Rule {
	return finding.Rule{
		ID: "JARX-VERSION-002", Severity: finding.Medium, Title: "Agent version has a security advisory",
		Detail: "this install's version is in the affected range of a published security advisory rated medium",
		Fix:    vulnerableFix,
	}
}

// VulnerableLow is an install in low advisories only.
func VulnerableLow() finding.Rule {
	return finding.Rule{
		ID: "JARX-VERSION-003", Severity: finding.Info, Title: "Agent version has a low advisory",
		Detail: "this install's version is in the affected range of a published security advisory rated low",
		Fix:    vulnerableFix,
	}
}

// OlderOnPath is an older install that wins on PATH over a newer one.
func OlderOnPath() finding.Rule {
	return finding.Rule{
		ID: "JARX-VERSION-004", Severity: finding.Medium, Title: "An older install runs from PATH",
		Detail: "the agent is installed more than once, and the copy your shell runs is older than another, so an update may not have taken",
		Fix:    "remove the old install, or put the newer one first on PATH",
	}
}

// UnknownOnPath is a PATH winner at no install location the docs name.
func UnknownOnPath() finding.Rule {
	return finding.Rule{
		ID: "JARX-VERSION-005", Severity: finding.Info, Title: "The agent on PATH is at an unknown place",
		Detail: "the command your shell runs isn't at an install location the agent's docs name, so jarx can't tell its version or check it against advisories (it never runs the agent to ask)",
		Fix:    "check where it came from, and that it gets updated",
	}
}

// Rules returns the analyzer's rules.
func Rules() []finding.Rule {
	return []finding.Rule{VulnerableHigh(), VulnerableMedium(), VulnerableLow(), OlderOnPath(), UnknownOnPath()}
}

// Analyze checks every install against the embedded advisories and PATH.
func Analyze(s *redact.Scrubber, installs []model.Install) []finding.Finding {
	return analyze(s, installs, catalog.AffectedBy)
}

type lookup func(a model.Agent, version string) []catalog.Advisory

func analyze(s *redact.Scrubber, installs []model.Install, affectedBy lookup) []finding.Finding {
	var out []finding.Finding
	add := func(r finding.Rule, in model.Install, ev string) {
		t, _ := s.Scrub(ev)
		out = append(out, r.New(origin(in), t))
	}
	for _, in := range installs {
		if advs := affectedBy(in.Agent, in.Version.String()); len(advs) > 0 {
			add(ruleFor(advs), in, vulnerableEvidence(in, advs))
		}
		if !in.OnPath {
			continue
		}
		if in.Method == model.InstallUnknown {
			add(UnknownOnPath(), in, in.Path.Raw()+" comes first on PATH, at no install location the docs name")
		} else if newer, ok := newest(installs, in); ok {
			add(OlderOnPath(), in, fmt.Sprintf("PATH runs %s %s, while %s %s is installed at %s",
				in.Method, in.Version, newer.Method, newer.Version, newer.Path.Raw()))
		}
	}
	return out
}

func origin(in model.Install) model.Origin {
	return model.Origin{Agent: in.Agent, File: in.Path, Scope: model.ScopeUser, InEffect: true}
}

// ruleFor is the rule for the worst advisory. advs is worst first.
func ruleFor(advs []catalog.Advisory) finding.Rule {
	worst := advs[0].Severity
	for _, a := range advs[1:] {
		if rank(a.Severity) > rank(worst) {
			worst = a.Severity
		}
	}
	switch worst {
	case "critical", "high":
		return VulnerableHigh()
	case "medium":
		return VulnerableMedium()
	}
	return VulnerableLow()
}

func rank(sev string) int { return slices.Index([]string{"low", "medium", "high", "critical"}, sev) }

// shownAdvisories is how many advisory ids the evidence names.
const shownAdvisories = 3

// vulnerableEvidence names the version, how many advisories it's in, the
// worst few, and the version that fixes them all.
func vulnerableEvidence(in model.Install, advs []catalog.Advisory) string {
	ids := make([]string, 0, shownAdvisories)
	fix := ""
	for i, a := range advs {
		if i < shownAdvisories {
			ids = append(ids, a.ID+" ("+a.Severity+")")
		}
		if c, ok := catalog.CompareVersions(a.Fixed, fix); fix == "" || ok && c > 0 {
			fix = a.Fixed
		}
	}
	list := strings.Join(ids, ", ")
	if more := len(advs) - len(ids); more > 0 {
		list += fmt.Sprintf(" and %d more", more)
	}
	if len(advs) == 1 {
		return fmt.Sprintf("%s %s is in 1 advisory: %s; %s fixes it", in.Method, in.Version, list, fix)
	}
	return fmt.Sprintf("%s %s is in %d advisories: %s; %s fixes all of them", in.Method, in.Version, len(advs), list, fix)
}

// newest is a newer install of the same agent than in, if there is one.
func newest(installs []model.Install, in model.Install) (model.Install, bool) {
	var best model.Install
	found := false
	for _, other := range installs {
		if other.Agent != in.Agent || other.OnPath {
			continue
		}
		c, ok := catalog.CompareVersions(other.Version.String(), in.Version.String())
		if !ok || c <= 0 {
			continue
		}
		if b, ok := catalog.CompareVersions(other.Version.String(), best.Version.String()); !found || ok && b > 0 {
			best, found = other, true
		}
	}
	return best, found
}
