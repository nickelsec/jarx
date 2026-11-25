package llm

import "github.com/nickelsec/jarx/internal/finding"

// RuleHigh is a finding the model called high, with a quote that's really
// in the artifact.
func RuleHigh() finding.Rule {
	return finding.Rule{
		ID:       "JARX-LLM-001",
		Severity: finding.High,
		Title:    "LLM review: goes past its stated purpose",
		Detail:   "the optional LLM review says this artifact tells the agent to do something its stated purpose doesn't need, and quoted where",
		Fix:      "read the quoted text, and remove or rewrite the artifact if the agent shouldn't do that.",
	}
}

// RuleMedium is a finding the model called medium.
func RuleMedium() finding.Rule {
	return finding.Rule{
		ID:       "JARX-LLM-002",
		Severity: finding.Medium,
		Title:    "LLM review: may go past its purpose",
		Detail:   "the optional LLM review says this artifact may tell the agent to do more than its purpose needs, and quoted where",
		Fix:      "read the quoted text and decide whether the agent should do that",
	}
}

// RuleFailed is an artifact the review couldn't get a valid answer for. It
// says so instead of guessing.
func RuleFailed() finding.Rule {
	return finding.Rule{
		ID:       "JARX-LLM-003",
		Severity: finding.Info,
		Title:    "LLM review failed for an artifact",
		Detail:   "the endpoint gave no valid answer for this artifact, even after a retry, so the LLM review has nothing to say about it",
		Fix:      "the regular checks still ran on it. Run jarx scan --llm again, or try another model.",
	}
}

// Rules returns the LLM review's rules.
func Rules() []finding.Rule { return []finding.Rule{RuleHigh(), RuleMedium(), RuleFailed()} }
