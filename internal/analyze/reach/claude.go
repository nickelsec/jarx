package reach

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/analyze/perms"
	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/credmeta"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

// Claude's modes, as the permission-modes docs name them.
const (
	modeBypass  = "bypassPermissions"
	modeAuto    = "auto"
	modeDontAsk = "dontAsk"
)

// claude is what decides a verdict in one project, read once from its
// settings.
type claude struct {
	s    *redact.Scrubber
	env  platform.Env
	p    model.Project
	perm model.Permissions

	mode, modeWhy string
	blockReads    string // where blockReadsOutsideWorkingDirectories is on, or ""
	sandboxOff    string // why the sandbox doesn't guard shell reads, or ""
	noRetry       string // where allowUnsandboxedCommands is false, or ""
	askRetry      string // an ask rule on the unsandboxed retry, or ""
	readAllow     string // an allow rule that approves a read command's retry, or ""
	excluded      []string
	scrub         bool // CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1 in Claude's env
}

func newClaude(s *redact.Scrubber, env platform.Env, p model.Project, perm model.Permissions) *claude {
	c := &claude{s: s, env: env, p: p, perm: perm, mode: perm.StartMode.String(), modeWhy: perm.StartWhy.String()}
	if v, f := c.option("permissions.blockReadsOutsideWorkingDirectories"); v == valueTrue {
		c.blockReads = f
	}
	c.sandboxOff = c.whySandboxOff()
	if v, f := c.option("sandbox.allowUnsandboxedCommands"); v == valueFalse {
		c.noRetry = f
	}
	c.readRules()
	// Only a value in the env itself counts: jarx doesn't read values from
	// a settings env block, and assuming the scrub is on would be the
	// hopeful mistake.
	if v, ok := env.Lookup("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"); ok && v == "1" {
		c.scrub = true
	}
	return c
}

// How a settings switch reads when it's on or off.
const (
	valueTrue  = "true"
	valueFalse = "false"
)

// readRules picks out the rules that change a verdict beyond file rules:
// an ask on the unsandboxed retry, an allow that approves a read's retry,
// and the excluded commands.
func (c *claude) readRules() {
	for _, r := range c.rules() {
		tool, pattern := splitRule(r.Rule.String())
		switch {
		case r.Action == model.RuleAsk && tool == "Bash" && strings.ReplaceAll(pattern, " ", "") == "dangerouslyDisableSandbox:true":
			c.askRetry = in(r)
		case r.Action == model.RuleAllow && readCommand(tool, pattern) && c.readAllow == "":
			c.readAllow = in(r)
		case r.Action == model.RuleExclude:
			c.excluded = append(c.excluded, r.Target.String())
		}
	}
}

func (c *claude) text(v string) redact.Text {
	t, _ := c.s.Scrub(v)
	return t
}

func (c *claude) texts(vs ...string) []redact.Text {
	out := make([]redact.Text, 0, len(vs))
	for _, v := range vs {
		if v != "" {
			out = append(out, c.text(v))
		}
	}
	return out
}

// in names a rule and its file, for a why.
func in(r model.PermissionRule) string {
	return r.Rule.String() + " in " + r.Origin.File.Text().String()
}

// rules are the rules in effect.
func (c *claude) rules() []model.PermissionRule {
	var out []model.PermissionRule
	for _, r := range c.perm.Rules {
		if r.Origin.InEffect {
			out = append(out, r)
		}
	}
	return out
}

// option is an option's value in effect and its file.
func (c *claude) option(key string) (string, string) {
	for _, o := range c.perm.Options {
		if o.Key.String() != key {
			continue
		}
		if eff, ok := o.Setting.Effective(); ok {
			return eff.Value.String(), eff.Origin.File.Text().String()
		}
	}
	return "", ""
}

func (c *claude) whySandboxOff() string {
	if c.env.GOOS == goosWindows {
		return "Claude's sandbox doesn't run on native Windows"
	}
	if v, _ := c.option("sandbox.enabled"); v != valueTrue {
		return "the sandbox is off"
	}
	if v, f := c.option("sandbox.filesystem.disabled"); v == valueTrue {
		return "sandbox.filesystem.disabled is true in " + f + ", so the sandbox doesn't limit reads"
	}
	return ""
}

func splitRule(rule string) (string, string) {
	tool, rest, ok := strings.Cut(rule, "(")
	if !ok || !strings.HasSuffix(rest, ")") {
		return strings.TrimSpace(rule), ""
	}
	return strings.TrimSpace(tool), strings.TrimSuffix(rest, ")")
}

// readCommands can print a file they're pointed at, so an allow for one
// approves reading a credential with it, retries included.
//
//nolint:gochecknoglobals // fixed list, read only
var readCommands = []string{
	"cat", "head", "tail", "less", "more", "grep", "rg", "egrep", "fgrep", "awk", "sed", "cut", "sort", "uniq",
	"base64", "xxd", "od", "hexdump", "strings", "cp", "tar", "zip", "curl", "Get-Content", "type", "gc",
}

// readCommand says whether an allow for a shell tool covers a command that
// reads files: the whole tool, a read command, or a program that runs any
// code (the command table's "any" class).
func readCommand(tool, pattern string) bool {
	if tool != "Bash" && tool != "PowerShell" {
		return false
	}
	if pattern == "" || pattern == "*" {
		return true
	}
	program := strings.Fields(pattern)[0]
	if slices.Contains(readCommands, program) {
		return true
	}
	cmds, err := catalog.Commands()
	if err != nil {
		return false
	}
	return slices.ContainsFunc(cmds, func(cmd catalog.Command) bool {
		return cmd.Program == program && cmd.Sub == "" && cmd.Class == catalog.RunsAnything
	})
}

// paths are the paths a rule has to cover for a credential: the file, or
// for a whole dir the dir and a file in it.
func paths(cr model.Credential) []string {
	if cr.Dir {
		return []string{cr.Path.Raw(), filepath.Join(cr.Path.Raw(), "credentials")}
	}
	return []string{cr.Path.Raw()}
}

func covers(m func(string) bool, cr model.Credential) bool {
	return slices.ContainsFunc(paths(cr), m)
}

// fileRule is the first in-effect rule with the action, for one of the
// tools, whose pattern covers the credential.
func (c *claude) fileRule(cr model.Credential, action model.RuleAction, tools ...string) (model.PermissionRule, bool) {
	for _, r := range c.rules() {
		tool, pattern := splitRule(r.Rule.String())
		if r.Action != action || !slices.Contains(tools, tool) || strings.HasPrefix(r.Rule.String(), "sandbox.") {
			continue
		}
		if covers(perms.ClaudePath(c.env, c.p.Path.Raw(), r.Origin, pattern), cr) {
			return r, true
		}
	}
	return model.PermissionRule{}, false
}

// insideWorkingDirs says whether the credential is in the project or an
// additional dir, where Read doesn't ask.
func (c *claude) insideWorkingDirs(cr model.Credential) bool {
	if covers(perms.SandboxPath(c.env, c.p.Path.Raw(), model.Origin{Scope: model.ScopeProject}, c.p.Path.Raw()), cr) {
		return true
	}
	for _, d := range c.perm.AdditionalDirectories {
		if d.Origin.InEffect && covers(perms.SandboxPath(c.env, c.p.Path.Raw(), d.Origin, d.Value.String()), cr) {
			return true
		}
	}
	return false
}

// verdicts are every channel's verdict for one credential.
func (c *claude) verdicts(cr model.Credential) []model.Reach {
	pc := process{s: c.s, p: c.p, agent: model.AgentClaude, strips: c.scrubs}
	if cr.Kind == credmeta.KindEnvVar {
		return append([]model.Reach{c.envShell(cr)}, pc.channels(cr, true)...)
	}
	return append([]model.Reach{c.fileTools(cr), c.shell(cr)}, pc.channels(cr, false)...)
}

// reachOf starts a Claude verdict.
func (c *claude) reachOf(cr model.Credential, ch model.ReachChannel) model.Reach {
	return reachOf(model.AgentClaude, cr, ch)
}

// withMode is a verdict that needs your approval, after the mode: bypass
// skips the prompt, auto hands it to a classifier (which isn't you), and
// dontAsk denies it.
func (c *claude) withMode(r model.Reach, why ...string) model.Reach {
	r.Why = c.texts(why...)
	switch c.mode {
	case modeBypass:
		r.Verdict = model.ReachSilent
		r.Why = append(r.Why, c.text("the session starts in bypassPermissions, which skips the prompt: "+c.modeWhy))
	case modeAuto:
		r.Verdict = model.ReachSilent
		r.Why = append(r.Why, c.text("the session starts in auto, where a classifier approves instead of you: "+c.modeWhy))
	case modeDontAsk:
		r.Verdict = model.ReachBlocked
		r.Why = append(r.Why, c.text("the session starts in dontAsk, which denies what no rule allows: "+c.modeWhy))
	default:
		r.Verdict = model.ReachApproval
	}
	return r
}

// fileTools is Read, Grep, Glob and LSP: Read deny, ask and allow rules
// (an Edit allow grants reads too), then the working dirs and the mode.
func (c *claude) fileTools(cr model.Credential) model.Reach {
	r := c.reachOf(cr, model.ChannelFileTools)
	if d, ok := c.fileRule(cr, model.RuleDeny, "Read"); ok {
		r.Verdict, r.Why = model.ReachBlocked, c.texts("denied by "+in(d))
		return r
	}
	if a, ok := c.fileRule(cr, model.RuleAsk, "Read"); ok {
		r.Verdict, r.Why = model.ReachApproval, c.texts("ask "+in(a)+"; an explicit ask prompts in every mode")
		return r
	}
	if a, ok := c.fileRule(cr, model.RuleAllow, "Read", "Edit"); ok {
		r.Verdict, r.Why = model.ReachSilent, c.texts("allowed by "+in(a))
		return r
	}
	if c.insideWorkingDirs(cr) {
		r.Verdict, r.Why = model.ReachSilent, c.texts("it's inside the working dirs, where Read doesn't ask")
		return r
	}
	if c.blockReads != "" {
		r.Verdict, r.Why = model.ReachBlocked, c.texts("blockReadsOutsideWorkingDirectories is on in "+c.blockReads+": the file tools refuse reads outside the working dirs")
		return r
	}
	return c.withMode(r, "it's outside the working dirs, where Read asks")
}

// shell is Bash and PowerShell. Without the sandbox, the read-only set
// (cat, grep and the rest) runs without asking, and a Read deny only
// catches commands that name the file. With it, the sandbox's read policy
// decides, then the unsandboxed retry.
func (c *claude) shell(cr model.Credential) model.Reach {
	r := c.reachOf(cr, model.ChannelShell)
	outside := !c.insideWorkingDirs(cr)
	if c.sandboxOff != "" {
		return c.unsandboxedShell(r, cr, outside)
	}
	blockedBy, reopened := c.sandboxBlocks(cr, outside)
	if blockedBy == "" {
		if m, ok := c.sandboxEntry(cr, model.RuleMask, "sandbox.credentials.files "); ok {
			r.Verdict, r.Why = model.ReachBlocked, c.texts("masked by "+m+": sandboxed commands get a stand-in, though the docs say a mask that matches nothing leaves the real file readable")
			return r
		}
		why := "the sandbox's default read policy covers most of the machine, and sandboxed commands run without asking"
		if reopened != "" {
			why = reopened + ", and sandboxed commands run without asking"
		}
		r.Verdict, r.Why = model.ReachSilent, c.texts(why)
		return r
	}
	return c.retry(r, blockedBy, outside)
}

func (c *claude) unsandboxedShell(r model.Reach, cr model.Credential, outside bool) model.Reach {
	if c.blockReads != "" && outside {
		return c.everyMode(r, c.sandboxOff, "blockReadsOutsideWorkingDirectories is on in "+c.blockReads+", so reading it prompts in every mode")
	}
	for _, action := range []model.RuleAction{model.RuleDeny, model.RuleAsk} {
		if d, ok := c.fileRule(cr, action, "Read"); ok {
			r.Verdict = model.ReachBypassable
			r.Why = c.texts(string(action)+" "+in(d)+" catches cat and redirects, but not grep -r or a script that opens the file itself", c.sandboxOff+", so nothing backs it up")
			return r
		}
	}
	r.Verdict, r.Why = model.ReachSilent, c.texts("cat and grep are in the read-only set, which runs without asking in every mode", c.sandboxOff)
	return r
}

// everyMode is "needs approval" that no mode skips, though dontAsk still
// denies it.
func (c *claude) everyMode(r model.Reach, why ...string) model.Reach {
	r.Verdict, r.Why = model.ReachApproval, c.texts(why...)
	if c.mode == modeDontAsk {
		r.Verdict = model.ReachBlocked
		r.Why = append(r.Why, c.text("the session starts in dontAsk, which denies it: "+c.modeWhy))
	}
	return r
}

// sandboxBlocks says what keeps sandboxed commands from reading the
// credential, or "": a credentials.files deny, a denyRead no narrower
// allowRead reopens, or blockReads outside the working dirs. When a
// narrower allowRead reopens a denyRead, reopened says so.
func (c *claude) sandboxBlocks(cr model.Credential, outside bool) (string, string) {
	if d, ok := c.sandboxEntry(cr, model.RuleDeny, "sandbox.credentials.files "); ok {
		return "denied to sandboxed commands by " + d, ""
	}
	deny, denyLen := c.longest(cr, model.RuleDeny, "sandbox.filesystem.denyRead ")
	allow, allowLen := c.longest(cr, model.RuleRead, "sandbox.filesystem.allowRead ")
	if deny != "" && allowLen <= denyLen {
		return "denied to sandboxed commands by " + deny, ""
	}
	if c.blockReads != "" && outside {
		return "blockReadsOutsideWorkingDirectories is on in " + c.blockReads + ", which also keeps sandboxed commands out of your home", ""
	}
	if deny != "" {
		return "", "the narrower " + allow + " reopens what " + deny + " closes"
	}
	return "", ""
}

// longest is the in-effect sandbox rule with the prefix that covers the
// credential with the longest path, and that length: the most specific
// one wins between denyRead and allowRead.
func (c *claude) longest(cr model.Credential, action model.RuleAction, prefix string) (string, int) {
	best, n := "", -1
	for _, r := range c.rules() {
		if r.Action != action || !strings.HasPrefix(r.Rule.String(), prefix) {
			continue
		}
		if t := r.Target.String(); covers(perms.SandboxPath(c.env, c.p.Path.Raw(), r.Origin, t), cr) && len(t) > n {
			best, n = in(r), len(t)
		}
	}
	return best, n
}

func (c *claude) sandboxEntry(cr model.Credential, action model.RuleAction, prefix string) (string, bool) {
	for _, r := range c.rules() {
		if r.Action == action && strings.HasPrefix(r.Rule.String(), prefix) &&
			covers(perms.SandboxPath(c.env, c.p.Path.Raw(), r.Origin, r.Target.String()), cr) {
			return in(r), true
		}
	}
	return "", false
}

// retry is what happens once the sandbox stops a read: Claude may retry
// the command outside the sandbox, which goes through the normal
// permission flow (sandboxing docs, "The unsandboxed retry escape hatch").
func (c *claude) retry(r model.Reach, blockedBy string, outside bool) model.Reach {
	note := ""
	if len(c.excluded) > 0 {
		note = "excludedCommands run outside the sandbox: " + strings.Join(c.excluded, ", ")
	}
	switch {
	case c.noRetry != "":
		r.Verdict, r.Why = model.ReachBlocked, c.texts(blockedBy, "allowUnsandboxedCommands is false in "+c.noRetry+", so there's no unsandboxed retry", note)
		return r
	case c.blockReads != "" && outside:
		return c.everyMode(r, blockedBy, "the unsandboxed retry prompts in every mode while blockReadsOutsideWorkingDirectories is on", note)
	case c.askRetry != "":
		return c.everyMode(r, blockedBy, "ask "+c.askRetry+" prompts on every unsandboxed retry, in every mode", note)
	case c.mode == modeDontAsk:
		r.Verdict, r.Why = model.ReachBlocked, c.texts(blockedBy, "dontAsk denies the unsandboxed retry: "+c.modeWhy, note)
		return r
	case c.mode == modeBypass:
		r.Verdict, r.Why = model.ReachSilent, c.texts(blockedBy, "bypassPermissions runs the unsandboxed retry without asking: "+c.modeWhy, note)
		return r
	case c.readAllow != "":
		r.Verdict, r.Why = model.ReachSilent, c.texts(blockedBy, "allow "+c.readAllow+" approves the unsandboxed retry of a read", note)
		return r
	case c.mode == modeAuto:
		r.Verdict, r.Why = model.ReachSilent, c.texts(blockedBy, "in auto a classifier approves the unsandboxed retry instead of you: "+c.modeWhy, note)
		return r
	}
	r.Verdict, r.Why = model.ReachApproval, c.texts(blockedBy, "the unsandboxed retry asks you", note)
	return r
}

// githubToken is a name the subprocess scrub leaves in place.
func githubToken(name string) bool {
	n := strings.ToUpper(name)
	return strings.Contains(n, "GITHUB") || strings.HasPrefix(n, "GH_")
}

// scrubs says whether the subprocess env scrub removes the var.
func (c *claude) scrubs(name string) bool { return c.scrub && !githubToken(name) }

// envShell is an env var through Bash, which inherits Claude's env whatever
// the file rules say.
func (c *claude) envShell(cr model.Credential) model.Reach {
	r := c.reachOf(cr, model.ChannelShell)
	name := cr.Name.String()
	if c.scrubs(name) {
		r.Verdict, r.Why = model.ReachBlocked, c.texts("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1 strips it from Bash, hooks and stdio MCP servers")
		return r
	}
	scrubNote := ""
	if c.scrub {
		scrubNote = "the subprocess env scrub leaves GitHub tokens in place"
	}
	if c.sandboxOff == "" || strings.HasPrefix(c.sandboxOff, "sandbox.filesystem") {
		// Env scrubbing is independent of the filesystem layer.
		if m, ok := c.envEntry(name, model.RuleMask); ok {
			r.Verdict, r.Why = model.ReachBlocked, c.texts("masked by "+m+": sandboxed commands get a stand-in", scrubNote)
			return r
		}
		if d, ok := c.envEntry(name, model.RuleDeny); ok {
			return c.retry(r, "denied to sandboxed commands by "+d, false)
		}
	}
	via := cr.Via.String()
	r.Verdict, r.Why = model.ReachSilent, c.texts("Bash inherits Claude's env, from "+via, scrubNote)
	return r
}

func (c *claude) envEntry(name string, action model.RuleAction) (string, bool) {
	for _, r := range c.rules() {
		if r.Action == action && strings.HasPrefix(r.Rule.String(), "sandbox.credentials.envVars ") && r.Target.String() == name {
			return in(r), true
		}
	}
	return "", false
}
