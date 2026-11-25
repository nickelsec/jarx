package cli

import (
	"strings"
	"testing"
)

func TestScanShowsProgressOnAStderrTerminal(t *testing.T) {
	demo := demoCopy(t)

	got := opts{live: true}.run("scan", "--home", demo)

	if got.code != 0 {
		t.Fatalf("exit %d, stderr %q", got.code, got.stderr)
	}
	for _, step := range []string{"reading session history", "walking projects", "probing MCP servers", "checking findings"} {
		if !strings.Contains(got.stderr, " "+step) {
			t.Errorf("stderr doesn't show %q: %q", step, got.stderr)
		}
	}
	// It's one line drawn over itself, and it's blanked before the report.
	if strings.Contains(got.stderr, "\n") || !strings.HasSuffix(got.stderr, "\r") {
		t.Errorf("stderr = %q, want one line redrawn with \r and blanked at the end", got.stderr)
	}
	if !strings.HasPrefix(got.stdout, "fake home ") {
		t.Errorf("stdout starts %q, want the report as usual", strings.SplitN(got.stdout, "\n", 2)[0])
	}
	// Only jarx's own words: never a path.
	if strings.Contains(got.stderr, demo) || strings.Contains(got.stderr, "projects") && strings.Contains(got.stderr, "~") {
		t.Errorf("stderr holds a path: %q", got.stderr)
	}
}

func TestScanShowsNoProgressWithoutATerminal(t *testing.T) {
	demo := demoCopy(t)

	if got := run("scan", "--home", demo); got.stderr != "" {
		t.Errorf("stderr = %q, want nothing when it isn't a terminal", got.stderr)
	}
}

func TestScanLLMShowsTheReviewBar(t *testing.T) {
	f := &reviewer{}
	demo := llmDemo(t, f.serve(t))
	o := withKey()
	o.live = true

	got := o.ask("y\n", "scan", "--llm", "--home", demo)

	if got.code != 0 || !strings.Contains(got.stderr, "| reviewing  [") || !strings.Contains(got.stderr, " of ") {
		t.Errorf("exit %d, stderr %q; want the review bar", got.code, got.stderr)
	}
}
