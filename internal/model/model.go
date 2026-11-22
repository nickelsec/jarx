// Package model is the agent-neutral inventory that adapters write into and
// analyzers read from. Every value keeps where it came from (Origin).
//
// The model never holds a raw string: text is redact.Text and paths are
// Path. A test walks every type reachable from Inventory and fails on any
// raw string, wherever it hides.
//
// The model grows per phase. This is the core every later type builds on.
package model

import (
	"github.com/nickelsec/jarx/internal/redact"
)

// Agent is who a value belongs to.
type Agent string

// Agents.
const (
	AgentClaude Agent = "claude"
	AgentCodex  Agent = "codex"
	AgentJarx   Agent = "jarx" // jarx's own records, like repos added with setup
)

// Scope is the config layer a value came from. The names cover both agents'
// precedence lists in the PRD.
type Scope string

// Scopes.
const (
	ScopeManaged      Scope = "managed"
	ScopeCLI          Scope = "cli"
	ScopeLocal        Scope = "local"
	ScopeProject      Scope = "project"
	ScopeUser         Scope = "user"
	ScopeProfile      Scope = "profile"
	ScopeRequirements Scope = "requirements"
	ScopeSystem       Scope = "system"
	ScopePlugin       Scope = "plugin"
	ScopeCloud        Scope = "cloud"
	ScopeJarx         Scope = "jarx"
)

// Origin is where one value came from and whether it's in effect.
type Origin struct {
	Agent    Agent
	File     Path
	Scope    Scope
	Line     int         // 0 when unknown
	InEffect bool        // false when overridden, ignored or waiting on trust
	Why      redact.Text // why it's not in effect, like "project allow waits for trust"
	Observed bool        // read from an observed, not documented, format
}

// Layer is one scope's value for a setting.
type Layer[T any] struct {
	Value  T
	Origin Origin
}

// Setting is a value that can be set in more than one scope. Layers are in
// precedence order, highest first. The adapter decides which layers are in
// effect (Origin.InEffect, with Origin.Why when not), since each agent merges
// differently. The model only holds the result.
type Setting[T any] struct {
	Layers []Layer[T]
}

// Effective returns the first layer in effect: the winning value for a
// setting where the highest scope overrides the rest.
func (s Setting[T]) Effective() (Layer[T], bool) {
	for _, l := range s.Layers {
		if l.Origin.InEffect {
			return l, true
		}
	}
	return Layer[T]{}, false
}

// InEffect returns every layer in effect, in order: what applies for a
// setting where scopes combine, like permission rule lists.
func (s Setting[T]) InEffect() []Layer[T] {
	var out []Layer[T]
	for _, l := range s.Layers {
		if l.Origin.InEffect {
			out = append(out, l)
		}
	}
	return out
}

// ProjectStatus says whether jarx could look at a project dir.
type ProjectStatus string

// Project statuses.
const (
	ProjectOK          ProjectStatus = "ok"
	ProjectStale       ProjectStatus = "stale"             // recorded, but missing or not a dir
	ProjectOutsideHome ProjectStatus = "outside fake home" // under --home, points outside it; never read
	ProjectInvalid     ProjectStatus = "not an absolute path"
	ProjectUnreadable  ProjectStatus = "can't check"
)

// TrustLevel is an agent's trust decision for a project.
type TrustLevel string

// Trust levels.
const (
	TrustTrusted   TrustLevel = "trusted"
	TrustUntrusted TrustLevel = "untrusted"
	TrustUnknown   TrustLevel = "unknown" // set, but to a value jarx doesn't know
)

// Trust is one agent's recorded trust decision.
type Trust struct {
	Level  TrustLevel
	Origin Origin
}

// WalkMethod is how a project's files were listed.
type WalkMethod string

// Walk methods.
const (
	WalkGit      WalkMethod = "git"  // hardened git ls-files: tracked plus untracked, not ignored
	WalkFallback WalkMethod = "walk" // jarx's own walk, when git isn't there or refuses
)

// Project is a project dir an agent knows about.
type Project struct {
	Path    Path
	Origins []Origin // every record that mentions it
	Status  ProjectStatus
	Trust   []Trust
	Files   []Path     // what the agent can see in it, after the skip list
	Walk    WalkMethod // "" when the project wasn't walked
	// Permissions holds each agent's permission settings as they apply in
	// this project, one entry per agent that has any.
	Permissions []Permissions
	// Instructions is every text an agent reads as instructions in this
	// project: instruction files, rules, imports, memory and output styles,
	// in effect or not. Origin.Agent says whose.
	Instructions []Instruction
	// Hooks are the hook handlers that apply here, from settings and
	// plugins. Hooks declared in skill or subagent frontmatter are kept as
	// text on the Skill instead.
	Hooks []Hook
	// Skills are the skills, commands and subagents the agent can use here.
	Skills []Skill
	// Plugins are the plugins the agent's settings mention for this
	// project, enabled or not.
	Plugins []Plugin
	// Configs are the settings and config files the agents read for this
	// project, each scrubbed whole, so the secrets scan sees them.
	Configs []Config
}

// Config is one settings or config file, scrubbed. Origin says whose and
// from which scope.
type Config struct {
	Origin Origin
	Text   redact.Text
}

// Hook is one hook handler. jarx only reads it: it never runs the command,
// sends the request or calls the tool.
type Hook struct {
	Event   redact.Text
	Matcher redact.Text
	Type    redact.Text // command, http, mcp_tool, prompt, agent, or whatever the file says
	// Run is what the handler runs, as written: the command and its args, the
	// URL, the server and tool, or the prompt. Variables are never filled in.
	Run redact.Text
	// Script is a script file the command runs, when jarx could tell which.
	// jarx reads it as text, so the rules can check it.
	Script     Path
	ScriptRead ReadStatus
	ScriptText redact.Text
	// Note says something about whether it runs that jarx can't settle, like
	// a per-hook trust the agent keeps where jarx can't see.
	Note   redact.Text
	Origin Origin
}

// SkillKind is what kind of skill-like thing a Skill is.
type SkillKind string

// Skill kinds.
const (
	SkillSkill    SkillKind = "skill"
	SkillCommand  SkillKind = "command"
	SkillSubagent SkillKind = "subagent"
)

// Skill is a skill, a command or a subagent: a file the agent can load as
// instructions when it's invoked, often with tools and hooks of its own.
type Skill struct {
	Kind SkillKind
	Name redact.Text
	Path Path
	Load LoadWhen
	Read ReadStatus
	Text redact.Text // the whole file, scrubbed; empty unless Read is ReadOK
	// Tools is a skill's or command's allowed-tools, which it pre-approves,
	// or a subagent's tools list.
	Tools []redact.Text
	// Hooks is the raw hooks block from the frontmatter, scrubbed, when the
	// file declares any.
	Hooks redact.Text
	// ShellCommands counts the shell commands the body runs before the agent
	// sees it (Claude's !`cmd` and ```! blocks).
	ShellCommands int
	// Mode is a subagent's permissionMode, when it sets one.
	Mode   redact.Text
	Plugin redact.Text // the plugin it comes from, if any
	Origin Origin
}

// Plugin is a plugin an agent's settings mention.
type Plugin struct {
	ID      redact.Text
	Enabled Setting[bool]
	// Path is where its files are, when jarx found them.
	Path    Path
	Version redact.Text
	Origin  Origin
}

// InstructionKind is what kind of instruction text a file is.
type InstructionKind string

// Instruction kinds.
const (
	InstructionFile        InstructionKind = "instructions" // CLAUDE.md, AGENTS.md and the like
	InstructionLocal       InstructionKind = "local instructions"
	InstructionRule        InstructionKind = "rule"
	InstructionImport      InstructionKind = "import"
	InstructionSetting     InstructionKind = "instructions in settings" // like Claude's managed claudeMd key
	InstructionMemory      InstructionKind = "memory"
	InstructionAgentMemory InstructionKind = "agent memory"
	InstructionOutputStyle InstructionKind = "output style"
)

// LoadWhen is when the agent puts an instruction into its context.
type LoadWhen string

// Load times.
const (
	LoadLaunch   LoadWhen = "at launch"
	LoadOnDemand LoadWhen = "on demand"
	LoadMatching LoadWhen = "when matching files are read"
	LoadSelected LoadWhen = "when selected"
	LoadSubagent LoadWhen = "when its subagent runs"
	LoadInvoked  LoadWhen = "when invoked"
)

// ReadStatus says whether jarx read an instruction's text, and if not, why.
type ReadStatus string

// Read statuses.
const (
	ReadOK          ReadStatus = "read"
	ReadMissing     ReadStatus = "missing"
	ReadCredential  ReadStatus = "credential file, not read" //nolint:gosec // G101: a status label, not a credential
	ReadNetwork     ReadStatus = "network path, not read"
	ReadOutsideHome ReadStatus = "outside fake home, not read"
	ReadNotRegular  ReadStatus = "not a regular file, not read"
	ReadTooLarge    ReadStatus = "too large, not read"
	ReadFailed      ReadStatus = "couldn't read"
	ReadNotFollowed ReadStatus = "not followed"
)

// Instruction is one text an agent reads as instructions.
type Instruction struct {
	Kind InstructionKind
	Path Path
	Load LoadWhen
	Read ReadStatus
	// Text is the content, scrubbed. It's empty unless Read is ReadOK.
	Text redact.Text
	// ImportedBy is the file whose @import pulled this one in, and Depth how
	// many hops that took. Both are zero for files the agent finds itself.
	ImportedBy Path
	Depth      int
	// Limit is how many bytes the agent reads from the file, when it reads
	// less than all of it (0 means all). Text always holds the whole file,
	// so the rules see what's past the limit too.
	Limit int
	// Note says something about loading that jarx can't settle, like a cap
	// the docs describe two ways.
	Note   redact.Text
	Origin Origin
}

// RuleAction is what a permission rule does.
type RuleAction string

// Rule actions.
const (
	RuleAllow RuleAction = "allow"
	RuleAsk   RuleAction = "ask"
	RuleDeny  RuleAction = "deny"
	RuleRead  RuleAction = "read"  // a filesystem grant to read, like Codex's permission profiles
	RuleWrite RuleAction = "write" // a filesystem grant to read and write
)

// PermissionRule is one rule from one file, like Bash(git *) or
// Read(./.env). Whether it's in effect, and why not, is on its Origin.
type PermissionRule struct {
	Action RuleAction
	Rule   redact.Text
	Origin Origin
}

// Permissions is one agent's permission settings for a project. Layers and
// rules keep every file they came from, in effect or not.
type Permissions struct {
	Agent                 Agent
	DefaultMode           Setting[redact.Text]
	Rules                 []PermissionRule
	AdditionalDirectories []Layer[redact.Text]
	// Options are named settings that shape permissions, each with every
	// layer that sets it, like Codex's approval_policy or sandbox_mode.
	Options []Option
}

// Option is one named setting and its layers.
type Option struct {
	Key     redact.Text
	Setting Setting[redact.Text]
}

// Unknown is a config key the adapter doesn't recognize.
type Unknown struct {
	Key    redact.Text
	Origin Origin
}

// Inventory is everything one scan found.
type Inventory struct {
	Projects []Project
	Unknown  []Unknown
	// Instructions holds instruction texts jarx can't tie to one project,
	// like auto memory folders whose project naming isn't documented.
	Instructions []Instruction
}
