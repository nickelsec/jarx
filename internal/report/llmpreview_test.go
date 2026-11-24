package report

import "testing"

func TestLLMPreviewIsABlock(t *testing.T) {
	p, s, out, _ := setup(t)

	p.LLMPreview(LLMPreviewView{
		Send: 14, Tokens: 9812, Cached: 3,
		Kinds: []Count{{N: 6, One: "tool", Many: "tools"}, {N: 1, One: "skill", Many: "skills"}, {N: 0, One: "hook", Many: "hooks"}},
		Host:  text(s, "llm.internal:8080"), Model: text(s, "m-1"), KeyEnv: text(s, "JARX_LLM_KEY"),
	})

	want := "llm review\n" +
		"+- 14 artifacts   6 tools - 1 skill\n" +
		"+- ~9,812 tokens  3 more cached, not sent again\n" +
		"+- to             llm.internal:8080 - m-1 - key from JARX_LLM_KEY\n" +
		`\- secrets masked before sending - history never sent` + "\n"
	if out.String() != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
}

func TestLLMPreviewWithNothingCachedLeavesTheNoteOut(t *testing.T) {
	p, s, out, _ := setup(t)

	p.LLMPreview(LLMPreviewView{Send: 1, Tokens: 900, Kinds: []Count{{N: 1, One: "hook", Many: "hooks"}}, Host: text(s, "h"), Model: text(s, "m"), KeyEnv: text(s, "K")})

	want := "llm review\n" +
		"+- 1 artifact   1 hook\n" +
		"+- ~900 tokens\n" +
		"+- to           h - m - key from K\n" +
		`\- secrets masked before sending - history never sent` + "\n"
	if out.String() != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
}
