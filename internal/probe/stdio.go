package probe

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/mcp"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/proc"
)

// probeStdio starts a stdio server the way its agent would and lists it.
// Under --home the only thing it starts is the demo server.
func probeStdio(ctx context.Context, c agent.Context, s model.Server, spec model.LaunchSpec, p model.Project, opts Options) result {
	dir := workDir(spec, p)
	command, args, env, missing := stdioLaunch(c, s.Origin.Agent, spec)
	if len(missing) > 0 {
		return missingCredential(missing)
	}
	if c.Env.Fake() {
		if spec.Command != DemoCommand {
			return result{status: model.StatusNotStarted, why: "under --home jarx never starts a program from the fake PATH"}
		}
		return runDemo(ctx, c, spec, dir, opts)
	}
	if strings.ContainsAny(command, `/\`) && !filepath.IsAbs(command) {
		command = filepath.Join(dir, command)
	}
	path, err := proc.Find(c.Files, c.Env, command)
	if err != nil {
		return result{status: model.StatusFailed, why: "the command " + command + " isn't on PATH"}
	}
	return runStdio(ctx, proc.Spec{Path: path, Args: args, Dir: dir, Env: proc.Env(c.Env, env)}, opts)
}

// workDir is where the server starts: Codex's cwd when it's set (from the
// project when it's relative), otherwise the project dir.
func workDir(spec model.LaunchSpec, p model.Project) string {
	switch {
	case spec.Cwd == "":
		return p.Path.Raw()
	case filepath.IsAbs(spec.Cwd):
		return spec.Cwd
	}
	return filepath.Join(p.Path.Raw(), spec.Cwd)
}

// stdioLaunch is the command, args and declared env after the agent's own
// expansion, and the variables a reference needed but didn't find.
func stdioLaunch(c agent.Context, a model.Agent, spec model.LaunchSpec) (string, []string, [][2]string, []string) {
	if a != model.AgentClaude {
		// Codex doesn't expand ${VAR} in config. env_vars forwards variables
		// from here; one read on a remote executor isn't for a local probe.
		env := append([][2]string{}, spec.Env...)
		for _, f := range spec.ForwardEnv {
			if v, ok := c.Env.Lookup(f.Name); ok && !f.Remote {
				env = append(env, [2]string{f.Name, v})
			}
		}
		return spec.Command, spec.Args, env, nil
	}
	var missing []string
	expand := func(s string) string {
		out, m := expandClaude(s, c.Env.Lookup, spec, false)
		missing = append(missing, m...)
		return out
	}
	command := expand(spec.Command)
	args := make([]string, 0, len(spec.Args))
	for _, a := range spec.Args {
		args = append(args, expand(a))
	}
	env := make([][2]string, 0, len(spec.Env))
	for _, kv := range spec.Env {
		env = append(env, [2]string{kv[0], expand(kv[1])})
	}
	return command, args, env, missing
}

func missingCredential(names []string) result {
	return result{status: model.StatusMissingCredential,
		why: "the config references " + strings.Join(names, ", ") + ", which isn't set, so the agent would start it broken too"}
}

// runDemo runs the demo home's fake server: the jarx binary in DemoMode,
// serving a script read from inside the fake home.
func runDemo(ctx context.Context, c agent.Context, spec model.LaunchSpec, dir string, opts Options) result {
	if len(spec.Args) != 1 || opts.Self == "" {
		return result{status: model.StatusFailed, why: "the demo server needs one script and the jarx binary"}
	}
	script := spec.Args[0]
	if filepath.IsAbs(script) {
		script = c.Env.MapPath(script)
	} else {
		script = filepath.Join(dir, script)
	}
	data, err := c.Files.ReadFile(script)
	if err != nil {
		return result{status: model.StatusFailed, why: "couldn't read the demo script inside the fake home"}
	}
	env := proc.Env(c.Env, [][2]string{{DemoMarker, "1"}})
	return runStdio(ctx, proc.Spec{Path: opts.Self, Args: []string{DemoMode, string(data)}, Dir: dir, Env: env}, opts)
}

// runStdio starts the server, lists it and kills its whole tree.
func runStdio(ctx context.Context, spec proc.Spec, opts Options) result {
	p, err := opts.Start(spec)
	switch {
	case errors.Is(err, proc.ErrBatchArgs):
		return result{status: model.StatusFailed, why: "its command is a .bat or .cmd file and an argument has a cmd.exe metacharacter, so jarx won't run it"}
	case err != nil:
		return result{status: model.StatusFailed, why: "couldn't start it"}
	}
	l, err := mcp.ListStdio(ctx, p.Stdin, p.Stdout, mcp.Options{ClientVersion: opts.ClientVersion})
	exited := false
	select {
	case <-p.Done():
		exited = true
	default:
	}
	_ = p.Kill()
	r := result{listing: l, stderr: p.Stderr()}
	switch {
	case err == nil:
		r.status = model.StatusListed
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		r.status, r.why = model.StatusTimedOut, "no full answer within "+opts.Timeout.String()
	case exited:
		r.status, r.why = model.StatusFailed, "it exited with code "+strconv.Itoa(p.ExitCode())+" before answering"
	default:
		r.status, r.why = model.StatusFailed, "it didn't speak MCP: "+mcpReason(err)
	}
	return r
}

// mcpReason says what went wrong without quoting the server.
func mcpReason(err error) string {
	switch {
	case errors.Is(err, mcp.ErrUnsupported):
		return "no protocol version in common"
	case errors.Is(err, mcp.ErrTooLarge):
		return "a message was over the size cap"
	case errors.Is(err, mcp.ErrOtherOrigin):
		return "its SSE endpoint is on another origin"
	}
	if rerr, ok := errors.AsType[*mcp.RPCError](err); ok {
		return "it answered with error " + strconv.Itoa(rerr.Code)
	}
	return "the conversation broke off"
}
