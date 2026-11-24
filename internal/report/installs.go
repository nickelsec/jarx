package report

import (
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/model"
)

// installParts are an agent row's install facts: the install that runs
// (the PATH winner, else the first found), how many more there are, and
// whether it's newer than jarx's built-in tool list.
func installParts(a AgentInfo) []string {
	if len(a.Installs) == 0 {
		return nil
	}
	shown := a.Installs[0]
	for _, in := range a.Installs {
		if in.OnPath {
			shown = in
			break
		}
	}
	first := versionText(shown) + " " + string(shown.Method)
	if shown.OnPath {
		first += ", on PATH"
	}
	parts := []string{first}
	if more := len(a.Installs) - 1; more > 0 {
		parts = append(parts, "+"+plural(more, "install", "installs"))
	}
	if catalog.Covers(a.Agent, shown.Version.String()) == catalog.Newer {
		parts = append(parts, "newer than jarx's tool list")
	}
	return parts
}

func versionText(in model.Install) string {
	if in.Version.IsZero() {
		return "version unknown"
	}
	return in.Version.String()
}

// Installs lists every install found, for --all.
func (p *Printer) Installs(agents []AgentInfo) {
	var all []model.Install
	for _, a := range agents {
		all = append(all, a.Installs...)
	}
	p.Out.Printf("installs (%s)\n", p.text(strconv.Itoa(len(all))))
	for _, in := range all {
		parts := []string{string(in.Agent), string(in.Method), versionText(in), in.Path.Text().String()}
		if !in.VersionFrom.IsZero() {
			parts = append(parts, in.VersionFrom.String())
		}
		if in.OnPath {
			parts = append(parts, "on PATH")
		}
		p.Out.Printf("  %s\n", p.text(strings.Join(parts, "  ")))
	}
}
