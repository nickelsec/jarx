package agent

import (
	"slices"
	"testing"
)

const skillWithHooks = `---
name: secure-operations
description: Perform operations with security checks
allowed-tools: Bash(git add *) Bash(git commit *), Read
hooks:
  PreToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: '"${CLAUDE_PROJECT_DIR}"/scripts/security-check.sh'
tools:
  - Read
  - "Grep"
  - 'Bash(npm test *)'
model: sonnet
---
body
`

func TestFrontmatterBlockKeepsTheRawIndentedLines(t *testing.T) {
	block, ok := FrontmatterBlock(skillWithHooks, "hooks")

	want := "  PreToolUse:\n" +
		"    - matcher: \"Bash\"\n" +
		"      hooks:\n" +
		"        - type: command\n" +
		"          command: '\"${CLAUDE_PROJECT_DIR}\"/scripts/security-check.sh'\n"
	if !ok || block != want {
		t.Errorf("block = %q, %v; want %q", block, ok, want)
	}
}

func TestFrontmatterBlockForAnInlineValue(t *testing.T) {
	block, ok := FrontmatterBlock(skillWithHooks, "model")

	if !ok || block != "sonnet" {
		t.Errorf("block = %q, %v; want the inline value", block, ok)
	}
	if _, ok := FrontmatterBlock(skillWithHooks, "missing"); ok {
		t.Error("missing key found")
	}
	if _, ok := FrontmatterBlock("no frontmatter\nhooks: x\n", "hooks"); ok {
		t.Error("key outside frontmatter found")
	}
}

func TestToolListsFollowTheDocumentedForms(t *testing.T) {
	for name, tc := range map[string]struct {
		key  string
		want []string
	}{
		"spaces and commas with parens": {"allowed-tools", []string{"Bash(git add *)", "Bash(git commit *)", "Read"}},
		"yaml list with quotes":         {"tools", []string{"Read", "Grep", "Bash(npm test *)"}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := ToolList(skillWithHooks, tc.key); !slices.Equal(got, tc.want) {
				t.Errorf("ToolList(%s) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
	for raw, want := range map[string][]string{
		"[Read, Grep]":         {"Read", "Grep"},
		"Read, Grep, Bash(ls)": {"Read", "Grep", "Bash(ls)"},
		"Bash(echo a, b) Read": {"Bash(echo a, b)", "Read"},
		"":                     nil,
	} {
		if got := splitTools(raw); !slices.Equal(got, want) {
			t.Errorf("splitTools(%q) = %q, want %q", raw, got, want)
		}
	}
}
