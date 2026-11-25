package report

import (
	"strconv"

	"github.com/nickelsec/jarx/internal/redact"
)

// SettingsView is what jarx setup shows: jarx's own settings.
type SettingsView struct {
	Home     redact.Text // paths inside it show from ~
	StateDir redact.Text
	StateNew bool // the state dir isn't created yet
	Repos    []RepoRow
	LLM      *LLMView // nil when the LLM review is off
}

// RepoRow is one saved extra repo.
type RepoRow struct {
	Path    redact.Text
	Missing bool
}

// LLMView is the LLM review's settings. It has the key's env var name and
// whether that var is set, never the key.
type LLMView struct {
	BaseURL  redact.Text
	Model    redact.Text
	KeyEnv   redact.Text
	KeySet   bool
	Parallel int // artifacts sent at once
}

// settingsLabel pads a row label so the values line up.
const settingsLabel = 9

// Settings prints jarx's own settings as a block.
func (p *Printer) Settings(v SettingsView) {
	p.emit(line{{text: "jarx settings", tone: bold}})
	home := v.Home.String()

	state := line{{text: escape(tildePath(v.StateDir.String(), home))}}
	if v.StateNew {
		state = append(state, seg{text: "  not created yet", tone: dim})
	}
	repos := node{p.settingsRow("repos", line{{text: "none"}})}
	if len(v.Repos) > 0 {
		detail := make([]line, 0, len(v.Repos))
		for _, r := range v.Repos {
			l := line{{text: escape(tildePath(r.Path.String(), home))}}
			if r.Missing {
				l = append(l, seg{text: "  missing", tone: dim})
			}
			detail = append(detail, l)
		}
		repos = p.branch(p.settingsRow("repos", line{{text: strconv.Itoa(len(v.Repos))}}), detail)
	}
	llm := line{{text: "off"}, {text: "  (jarx setup llm)", tone: dim}}
	if v.LLM != nil {
		llm = line{
			{text: escape(v.LLM.BaseURL.String())},
			{text: own(p.sep())},
			{text: escape(v.LLM.Model.String())},
			{text: own(p.sep() + "key from ")},
			{text: escape(v.LLM.KeyEnv.String())},
			shortKeyState(v.LLM.KeySet),
		}
	}
	p.tree([]node{
		{p.settingsRow("state dir", state)},
		repos,
		{p.settingsRow("llm", llm)},
	})
}

func (p *Printer) settingsRow(label string, value line) line {
	return append(line{{text: own(pad(label, settingsLabel) + "  ")}}, value...)
}

// LLMSummary prints the LLM review's settings as a block, before they're
// saved.
func (p *Printer) LLMSummary(v LLMView) {
	p.emit(line{{text: "llm review", tone: bold}})
	p.tree([]node{
		{line{{text: "endpoint  "}, {text: escape(v.BaseURL.String())}}},
		{line{{text: "model     "}, {text: escape(v.Model.String())}}},
		{line{{text: "key       from "}, {text: escape(v.KeyEnv.String())}, keyState(v.KeySet)}},
		{line{{text: own("parallel  " + strconv.Itoa(v.Parallel) + " at a time")}}},
	})
}

func keyState(set bool) seg {
	if set {
		return seg{text: "  set in this terminal", tone: dim}
	}
	return seg{text: "  not set in this terminal", tone: yellow}
}

// shortKeyState fits the settings row, which also has the URL and model.
func shortKeyState(set bool) seg {
	if set {
		return seg{text: "  set", tone: dim}
	}
	return seg{text: "  not set", tone: yellow}
}

// tildePath shows path from ~ when it's inside home.
func tildePath(path, home string) string {
	if home == "" {
		return path
	}
	if rest, ok := cutPathPrefix(path, home); ok {
		return "~" + string(path[len(home)]) + rest
	}
	return path
}

func pad(s string, n int) string {
	for cells(s) < n {
		s += " "
	}
	return s
}
