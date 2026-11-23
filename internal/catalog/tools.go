package catalog

import (
	_ "embed"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/nickelsec/jarx/internal/model"
)

//go:embed tools.tsv
var toolsTSV string

// Stamp is when an agent's part of tools.tsv was checked against the docs,
// and the agent version that was current then.
type Stamp struct {
	Version string // the newest release on the day the docs were checked
	Checked string
	Source  string // where Version came from
}

// toolStamps are the stamps for tools.tsv, by agent.
//
//nolint:gochecknoglobals // fixed table, read only
var toolStamps = map[model.Agent]Stamp{
	model.AgentClaude: {Version: "2.1.330", Checked: "2026-11-24", Source: "code.claude.com/docs/en/changelog"},
	model.AgentCodex:  {Version: "0.171.0", Checked: "2026-11-24", Source: "developers.openai.com/codex/changelog"},
}

// Channel is how a tool reaches things: which credential reach it can give.
type Channel string

// Channels.
const (
	ChannelFileRead  Channel = "file-read"
	ChannelFileWrite Channel = "file-write"
	ChannelShell     Channel = "shell"
	ChannelNetwork   Channel = "network"
	ChannelMCP       Channel = "mcp"
	ChannelAgent     Channel = "agent"
	ChannelOther     Channel = "other"
)

// Prompts is whether a tool asks before it runs, by default.
type Prompts string

// Prompt values.
const (
	PromptsYes     Prompts = "yes"
	PromptsNo      Prompts = "no"
	PromptsSome    Prompts = "some"    // only in some cases, which the docs name
	PromptsPolicy  Prompts = "policy"  // Codex: approval_policy and the sandbox decide
	PromptsUnknown Prompts = "unknown" // the docs don't say
)

// BuiltinTool is one row of tools.tsv.
type BuiltinTool struct {
	Agent   model.Agent
	Name    string
	Channel Channel
	Prompts Prompts
	// Rule is the Claude permission rule whose specifier covers this tool,
	// like Read for Grep. A tool the docs' rule table doesn't list takes
	// only its bare name.
	Rule    string
	Removed bool
	Alias   string // the tool this name stands for, for an old name
	Source  string
	What    string
}

type toolTable struct {
	byAgent map[model.Agent][]BuiltinTool
	err     error
}

//nolint:gochecknoglobals // parsed once from the embedded file
var loadTools = sync.OnceValue(func() toolTable {
	byAgent, err := parseTools(toolsTSV)
	return toolTable{byAgent: byAgent, err: err}
})

// Tools is an agent's built-in tools, old names and removed tools included.
// A broken tools.tsv panics: it's embedded, and its test catches that.
func Tools(a model.Agent) []BuiltinTool {
	t := loadTools()
	if t.err != nil {
		panic(t.err)
	}
	return t.byAgent[a]
}

// Tool finds a built-in tool by name, case-sensitive. An old name gives the
// tool it stands for.
func Tool(a model.Agent, name string) (BuiltinTool, bool) {
	for _, t := range Tools(a) {
		if t.Name != name {
			continue
		}
		if t.Alias != "" {
			return Tool(a, t.Alias)
		}
		return t, true
	}
	return BuiltinTool{}, false
}

// ToolNames is every name a rule may use for an agent's built-in tools.
func ToolNames(a model.Agent) []string {
	ts := Tools(a)
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return out
}

// ToolsStamp is the stamp of an agent's part of the catalog.
func ToolsStamp(a model.Agent) Stamp { return toolStamps[a] }

// Coverage is whether the catalog covers an installed version.
type Coverage string

// Coverage values.
const (
	Covered        Coverage = "covered"
	Newer          Coverage = "newer"   // the agent is newer, so it may have tools the catalog lacks
	UnknownVersion Coverage = "unknown" // no version, or one jarx can't read
)

var versionRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// Covers compares an installed version with the catalog's stamp. The first
// x.y.z in version counts, so "codex-cli 0.171.0" works.
func Covers(a model.Agent, version string) Coverage {
	st, ok := toolStamps[a]
	if !ok {
		return UnknownVersion
	}
	have, ok1 := parseVersion(version)
	built, ok2 := parseVersion(st.Version)
	if !ok1 || !ok2 {
		return UnknownVersion
	}
	for i := range have {
		if have[i] != built[i] {
			if have[i] > built[i] {
				return Newer
			}
			return Covered
		}
	}
	return Covered
}

func parseVersion(v string) ([3]int, bool) {
	m := versionRe.FindStringSubmatch(v)
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := range out {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

const toolColumns = 8

func parseTools(tsv string) (map[model.Agent][]BuiltinTool, error) {
	out := map[model.Agent][]BuiltinTool{}
	for n, line := range strings.Split(tsv, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != toolColumns {
			return nil, fmt.Errorf("tools.tsv line %d: %d columns, want %d", n+1, len(f), toolColumns)
		}
		t := BuiltinTool{
			Agent: model.Agent(f[0]), Name: f[1], Channel: Channel(f[2]), Prompts: Prompts(f[3]),
			Rule: f[4], Source: f[6], What: f[7],
		}
		switch status := f[5]; {
		case status == "removed":
			t.Removed = true
		case strings.HasPrefix(status, "alias:"):
			t.Alias = strings.TrimPrefix(status, "alias:")
		case status != "":
			return nil, fmt.Errorf("tools.tsv line %d: status %q", n+1, status)
		}
		out[t.Agent] = append(out[t.Agent], t)
	}
	return out, nil
}
