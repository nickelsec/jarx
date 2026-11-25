package report

import (
	"strings"
	"testing"
)

func TestLLMPreviewIsABlock(t *testing.T) {
	p, s, out, _ := setup(t)

	p.LLMPreview(LLMPreviewView{
		Send: 12, Tokens: 9812, Cached: 73, Failed: 4, New: 8, Parallel: 4,
		Kinds: []Count{{N: 6, One: "tool", Many: "tools"}, {N: 1, One: "skill", Many: "skills"}, {N: 0, One: "hook", Many: "hooks"}},
		Host:  text(s, "llm.internal:8080"), Model: text(s, "m-1"), KeyEnv: text(s, "JARX_LLM_KEY"),
	})

	want := "llm review\n" +
		"+- 12 artifacts   6 tools - 1 skill\n" +
		"+- ~9,812 tokens  sent 4 at a time\n" +
		"+- last run       73 cached, not sent - 4 failed, sent again - 8 new\n" +
		"+- to             llm.internal:8080 - m-1 - key from JARX_LLM_KEY\n" +
		`\- secrets masked before sending - history never sent` + "\n"
	if out.String() != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
}

func TestLLMPreviewWithNoLastRunLeavesThatLineOut(t *testing.T) {
	p, s, out, _ := setup(t)

	p.LLMPreview(LLMPreviewView{Send: 1, Tokens: 900, New: 1, Parallel: 1, Kinds: []Count{{N: 1, One: "hook", Many: "hooks"}}, Host: text(s, "h"), Model: text(s, "m"), KeyEnv: text(s, "K")})

	want := "llm review\n" +
		"+- 1 artifact   1 hook\n" +
		"+- ~900 tokens  sent 1 at a time\n" +
		"+- to           h - m - key from K\n" +
		`\- secrets masked before sending - history never sent` + "\n"
	if out.String() != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
}

func TestLLMPreviewLeavesOutWhatIsZero(t *testing.T) {
	p, s, out, _ := setup(t)

	p.LLMPreview(LLMPreviewView{Send: 2, Tokens: 900, Failed: 2, Parallel: 4, Kinds: []Count{{N: 2, One: "hook", Many: "hooks"}}, Host: text(s, "h"), Model: text(s, "m"), KeyEnv: text(s, "K")})

	if want := "+- last run     2 failed, sent again\n"; !strings.Contains(out.String(), want) {
		t.Errorf("got\n%s\nwant a line\n%s", out, want)
	}
}

func TestLLMPreviewSaysWhatWasSkipped(t *testing.T) {
	p, s, out, _ := setup(t)

	p.LLMPreview(LLMPreviewView{Send: 1, Tokens: 900, New: 1, Skipped: 2, Parallel: 1, Kinds: []Count{{N: 1, One: "hook", Many: "hooks"}}, Host: text(s, "h"), Model: text(s, "m"), KeyEnv: text(s, "K")})

	want := "llm review\n" +
		"+- 1 artifact   1 hook\n" +
		"+- ~900 tokens  sent 1 at a time\n" +
		"+- skipped      2 not sent, you skipped them\n" +
		"+- to           h - m - key from K\n" +
		`\- secrets masked before sending - history never sent` + "\n"
	if out.String() != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
}
