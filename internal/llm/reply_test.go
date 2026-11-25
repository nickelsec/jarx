package llm

import (
	"strings"
	"testing"
)

func TestParseReplyTakesTheFixedShape(t *testing.T) {
	got, err := parseReply(`{"findings":[{"severity":"high","title":"sends your keys out","quote":"curl -d @~/.ssh/id_rsa","why":"a lint skill has no reason to upload ssh keys"}]}`)

	if err != nil {
		t.Fatalf("parseReply() error = %v", err)
	}
	want := Item{Severity: "high", Title: "sends your keys out", Quote: "curl -d @~/.ssh/id_rsa", Why: "a lint skill has no reason to upload ssh keys"}
	if len(got) != 1 || got[0] != want {
		t.Errorf("parseReply() = %+v, want [%+v]", got, want)
	}
}

func TestParseReplyTakesNoFindings(t *testing.T) {
	got, err := parseReply(`{"findings": []}`)

	if err != nil || len(got) != 0 {
		t.Errorf("parseReply() = %+v, %v; want none", got, err)
	}
}

func TestParseReplyTakesOneCodeFenceAroundIt(t *testing.T) {
	for _, reply := range []string{
		"```json\n{\"findings\":[]}\n```",
		"```\n{\"findings\":[]}\n```\n",
		"  {\"findings\":[]}  ",
	} {
		if _, err := parseReply(reply); err != nil {
			t.Errorf("parseReply(%q) error = %v, want nil", reply, err)
		}
	}
}

func TestParseReplyRefusesAnythingElse(t *testing.T) {
	for _, tc := range []struct{ reply, want string }{
		{"looks fine to me", "isn't JSON"},
		{`{"findings":[]} and some words`, "isn't JSON"},
		{`{}`, `needs a "findings" list`},
		{`{"findings":null}`, `needs a "findings" list`},
		{`{"findings":[],"extra":1}`, `unknown field "extra"`},
		{`{"findings":[{"severity":"critical","title":"t","quote":"q","why":"w"}]}`, "severity has to be high or medium"},
		{`{"findings":[{"severity":"high","title":"","quote":"q","why":"w"}]}`, "needs a title"},
		{`{"findings":[{"severity":"high","title":"t","quote":"","why":"w"}]}`, "needs a quote"},
		{`{"findings":[{"severity":"high","title":"t","quote":"q","why":""}]}`, "needs a why"},
		{`{"findings":[{"severity":"high","title":"t","quote":"q","why":"w","score":9}]}`, `unknown field "score"`},
		{`{"findings":[{"severity":"high","title":"` + strings.Repeat("t", maxTitle+1) + `","quote":"q","why":"w"}]}`, "title is too long"},
	} {
		_, err := parseReply(tc.reply)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("parseReply(%q) = %v, want an error with %q", tc.reply, err, tc.want)
		}
	}
}

func TestParseReplyRefusesTooManyFindings(t *testing.T) {
	item := `{"severity":"medium","title":"t","quote":"q","why":"w"}`
	reply := `{"findings":[` + strings.TrimSuffix(strings.Repeat(item+",", maxItems+1), ",") + `]}`

	if _, err := parseReply(reply); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("parseReply(%d findings) = %v, want a too many error", maxItems+1, err)
	}
}
