package ui

import (
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/report"
)

// inventoryBody is the Inventory page: the agents, the totals the scan's
// terminal report counts, every project, and every MCP server.
type inventoryBody struct {
	Agents   []agentCard
	Totals   []total
	Projects []invProject
	Servers  []invServer
}

type agentCard struct {
	Name, ConfigDir, Version, Method string
	Found, OnPath                    bool
}

// total is one box in the totals grid, with a note on what it doesn't
// cover.
type total struct {
	Label, Note string
	N           int
}

type invProject struct {
	Name, Full, Href, Status, Walk          string
	Trust                                   []trustPill
	Instructions, Skills, Servers, Findings int
}

type invServer struct {
	Name, Agent, Where, WhereFull, File, Runs, Start, StartKey, Probe string
	Tools                                                             int
}

func inventoryOf(d Data) inventoryBody {
	home := d.Scan.Home.Text().String()
	b := inventoryBody{Totals: totalsOf(report.Totals(d.Scan))}
	for _, a := range d.Scan.Agents {
		c := agentCard{Name: a.Name, ConfigDir: tilde(a.ConfigDir.Text().String(), home), Found: a.Found}
		if len(a.Installs) > 0 {
			in := a.Installs[0]
			c.Version, c.Method, c.OnPath = in.Version.String(), string(in.Method), in.OnPath
		}
		b.Agents = append(b.Agents, c)
	}
	for i, p := range d.Scan.Projects {
		b.Projects = append(b.Projects, invProjectOf(d, i, p, home))
	}
	b.Servers = serversOf(d, home)
	return b
}

func totalsOf(t report.Total) []total {
	off := ""
	if t.ServersOff > 0 {
		off = strconv.Itoa(t.ServersOff) + " not started"
	}
	notScanned := ""
	if t.NotScanned > 0 {
		notScanned = strconv.Itoa(t.NotScanned) + " not scanned"
	}
	return []total{
		{Label: "Projects", N: t.Projects, Note: notScanned},
		{Label: "Instruction files", N: t.Instructions},
		{Label: "Skills", N: t.Skills},
		{Label: "Hooks", N: t.Hooks},
		{Label: "MCP servers", N: t.Servers, Note: off},
		{Label: "Permission rules", N: t.Rules},
		{Label: "Credential locations", N: t.CredentialLocations},
		{Label: "Config files", N: t.Configs},
		{Label: "Sessions", N: t.Sessions},
		{Label: "History files", N: t.HistoryFiles},
	}
}

func invProjectOf(d Data, i int, p model.Project, home string) invProject {
	full := tilde(p.Path.Text().String(), home)
	r := invProject{Name: base(full), Full: full, Href: "/projects/" + strconv.Itoa(i),
		Instructions: len(p.Instructions), Skills: len(p.Skills), Servers: len(p.Servers),
		Findings: len(rows(d, filters{project: []string{strconv.Itoa(i)}}, nil))}
	if p.Status != model.ProjectOK {
		r.Status = string(p.Status)
	}
	r.Trust = trustOf(p)
	switch p.Walk {
	case model.WalkGit:
		r.Walk = "from git"
	case model.WalkFallback:
		r.Walk = "found on disk"
	}
	return r
}

// serversOf is every MCP server, once per file and name the way the
// scan's count keeps them, in the order the projects list them.
func serversOf(d Data, home string) []invServer {
	seen := map[string]bool{}
	var out []invServer
	for _, p := range d.Scan.Projects {
		for _, s := range p.Servers {
			key := s.Origin.File.Raw() + "\x00" + s.Name.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, serverRow(d, s, home))
		}
	}
	return out
}

func serverRow(d Data, s model.Server, home string) invServer {
	pi := projectIndex(d.Scan.Projects, finding.Finding{Origin: s.Origin})
	where, whereFull := userConfig, userConfigNote
	if pi >= 0 {
		whereFull = tilde(d.Scan.Projects[pi].Path.Text().String(), home)
		where = base(whereFull)
	}
	r := invServer{Name: s.Name.String(), Agent: string(s.Origin.Agent), Where: where, WhereFull: whereFull,
		File: relTo(s.Origin.File.Text().String(), projDir(d, pi), home), Runs: serverRuns(s, home),
		Start: string(s.Start), StartKey: strings.ReplaceAll(string(s.Start), " ", "-"), Probe: probeOf(s)}
	for _, o := range s.Offers {
		if o.Kind == model.OfferTool {
			r.Tools++
		}
	}
	return r
}

// serverRuns is what a server runs: its command and arguments, or the host of
// its URL. Only the host, since a URL's path and query can hold a token.
func serverRuns(s model.Server, home string) string {
	if s.Transport == model.TransportStdio || s.URL.String() == "" {
		parts := make([]string, 0, 1+len(s.Args))
		parts = append(parts, shortenAll(s.Command.String(), home))
		for _, a := range s.Args {
			parts = append(parts, shortenAll(a.String(), home))
		}
		return cut(strings.Join(slices.DeleteFunc(parts, func(p string) bool { return p == "" }), " "))
	}
	if u, err := url.Parse(s.URL.String()); err == nil && u.Host != "" {
		return u.Host
	}
	return string(s.Transport)
}

// probeOf is what jarx's probe found, or that it didn't run.
func probeOf(s model.Server) string {
	if s.Status == model.StatusUnprobed {
		return "not probed"
	}
	return string(s.Status)
}
