// Package probe starts or contacts the MCP servers the agents would start,
// lists what they offer through the list-only mcp client, and gives each
// server one status. It only probes servers the adapters marked as starting.
// Stdio servers run through proc, so their whole process tree dies after;
// remote ones are reached only through netguard. Everything a server sends
// is scrubbed before it goes on the model.
//
// Under --home, probe never contacts a remote server and never starts a
// program from the fake PATH. The one thing it starts there is the demo
// home's fake server: a stdio server whose command is DemoCommand, run as
// the jarx binary itself in DemoMode. On the real machine DemoCommand is an
// ordinary command name.
package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/mcp"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/netguard"
	"github.com/nickelsec/jarx/internal/proc"
)

// The demo home's fake server.
const (
	// DemoCommand is the command a demo server config names. Only under
	// --home does it mean the fake server.
	DemoCommand = "jarx-fakemcp"
	// DemoMode is the hidden first argument that makes jarx serve a script.
	DemoMode = "__fakemcp"
	// DemoMarker is set in the demo server's env; jarx's hidden mode refuses
	// to serve without it.
	DemoMarker = "JARX_DEMO_FAKEMCP"
)

// Defaults from the PRD.
const (
	defaultTimeout  = 15 * time.Second
	defaultParallel = 4
)

// Options tune a probe run.
type Options struct {
	Disabled bool          // --no-probe
	Timeout  time.Duration // per server; 0 means 15s
	Parallel int           // servers at once; 0 means 4
	Client   *netguard.Client
	// Start starts a stdio server; nil means proc.Start. Tests wrap it.
	Start func(proc.Spec) (*proc.Process, error)
	// Self is the jarx binary, which runs the demo server under --home.
	Self          string
	ClientVersion string
	// OnProgress, when set, hears how many definitions are done and running
	// out of the total, from 0 at the start to all done. It's called from
	// the probing goroutines, one call at a time.
	OnProgress func(done, running, total int)
}

// Run probes every server that starts in projects and stores the result on
// each server. A definition that applies in several projects, like a user
// server, is probed once and the result goes on all of them.
func Run(ctx context.Context, c agent.Context, projects []model.Project, opts Options) {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.Parallel <= 0 {
		opts.Parallel = defaultParallel
	}
	if opts.Start == nil {
		opts.Start = proc.Start
	}
	jobs, order := collect(c, projects, opts)
	tell := tally(opts.OnProgress, len(order))
	tell(0, 0)
	sem := make(chan struct{}, opts.Parallel)
	var wg sync.WaitGroup
	for _, key := range order {
		j := jobs[key]
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			tell(0, 1)
			r := probeOne(ctx, c, j.server, j.project, opts)
			for _, s := range j.targets {
				r.apply(c, s)
			}
			tell(1, -1)
		})
	}
	wg.Wait()
}

// tally keeps the done and running counts and passes each change to f, one
// call at a time. With no f it does nothing.
func tally(f func(done, running, total int), total int) func(done, running int) {
	if f == nil {
		return func(int, int) {}
	}
	var mu sync.Mutex
	done, running := 0, 0
	return func(d, r int) {
		mu.Lock()
		defer mu.Unlock()
		done, running = done+d, running+r
		f(done, running, total)
	}
}

// job is one server definition to probe and every copy of it.
type job struct {
	server  model.Server
	project model.Project
	targets []*model.Server
}

// collect gives a status to every server that won't be probed, and groups
// the rest by definition.
func collect(c agent.Context, projects []model.Project, opts Options) (map[string]*job, []string) {
	jobs := map[string]*job{}
	var order []string
	for i := range projects {
		p := &projects[i]
		for j := range p.Servers {
			s := &p.Servers[j]
			switch {
			case s.Start != model.StartYes && s.Start != model.StartMaybe:
				setStatus(c, s, model.StatusNotStarted, "the agent wouldn't start it: "+s.Origin.Why.String())
				continue
			case opts.Disabled:
				setStatus(c, s, model.StatusNotStarted, "not probed: --no-probe")
				continue
			}
			key := jobKey(*s, *p)
			if jobs[key] == nil {
				jobs[key] = &job{server: *s, project: *p}
				order = append(order, key)
			}
			jobs[key].targets = append(jobs[key].targets, s)
		}
	}
	return jobs, order
}

// jobKey is a definition's identity: whose it is, where it's from, its name
// and its raw launch data. A stdio server runs in its project's dir, so the
// project is part of the key for those.
func jobKey(s model.Server, p model.Project) string {
	spec, _ := s.Launch.Spec()
	h := sha256.New()
	for _, part := range []string{
		string(s.Origin.Agent), s.Origin.File.Raw(), string(s.Origin.Scope), s.Name.String(), string(s.Transport),
		spec.Command, strings.Join(spec.Args, "\x00"), spec.URL, spec.Cwd, flatten(spec.Env), flatten(spec.Headers),
		flatten(spec.HeaderVars), spec.BearerVar, spec.PluginRoot,
	} {
		_, _ = h.Write([]byte(part + "\x01"))
	}
	if s.Transport == model.TransportStdio || strings.Contains(spec.URL, "${CLAUDE_PROJECT_DIR}") {
		_, _ = h.Write([]byte(p.Path.Raw()))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func flatten(ps [][2]string) string {
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		parts = append(parts, p[0]+"="+p[1])
	}
	return strings.Join(parts, "\x00")
}

func setStatus(c agent.Context, s *model.Server, st model.ServerStatus, why string) {
	s.Status = st
	s.StatusWhy, _ = c.Scrub.Scrub(why)
}

// result is what probing one server found, raw until apply scrubs it.
type result struct {
	status  model.ServerStatus
	why     string
	listing mcp.Listing
	stderr  []byte
}

func (r result) apply(c agent.Context, s *model.Server) {
	setStatus(c, s, r.status, r.why)
	if r.status == model.StatusListed {
		s.Offers = offers(c, r.listing)
		s.Instructions, _ = c.Scrub.Scrub(r.listing.Instructions)
		for _, n := range r.listing.Notes {
			t, _ := c.Scrub.Scrub(n)
			s.ProbeNotes = append(s.ProbeNotes, t)
		}
		if n := r.listing.Noise; n != (mcp.Noise{}) {
			t, _ := c.Scrub.Scrub(noiseNote(n))
			s.ProbeNotes = append(s.ProbeNotes, t)
		}
	}
	if len(r.stderr) > 0 {
		s.Stderr, _ = c.Scrub.Scrub(string(r.stderr))
	}
}

// probeOne decides how to probe one server and does it.
func probeOne(ctx context.Context, c agent.Context, s model.Server, p model.Project, opts Options) result {
	spec, ok := s.Launch.Spec()
	if !ok {
		return result{status: model.StatusNotStarted, why: "jarx has no launch data for it"}
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	if s.Transport == model.TransportStdio {
		return probeStdio(ctx, c, s, spec, p, opts)
	}
	return probeRemote(ctx, c, s, spec, opts)
}
