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
}

// RuleAction is what a permission rule does.
type RuleAction string

// Rule actions.
const (
	RuleAllow RuleAction = "allow"
	RuleAsk   RuleAction = "ask"
	RuleDeny  RuleAction = "deny"
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
}
