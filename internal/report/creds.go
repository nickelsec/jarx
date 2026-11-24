package report

import (
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/model"
)

// Credentials lists the machine's credential locations with the safe
// metadata jarx read from each.
func (p *Printer) Credentials(cs []model.Credential) {
	p.Out.Printf("credentials (%s)\n", p.text(strconv.Itoa(len(cs))))
	for _, cr := range cs {
		p.credential("  ", cr)
	}
}

// credential is one credential line: its kind and path, the env var that
// placed it when one did, then its facts, or why there are none.
func (p *Printer) credential(indent string, cr model.Credential) {
	where := cr.Path.Text().String()
	if cr.Path.IsZero() {
		where = cr.Name.String() // an env var has a name, not a path
	}
	parts := []string{string(cr.Kind), where}
	if v := cr.Via.String(); v != "" && v != valueDefault {
		parts = append(parts, "via "+v)
	}
	facts := make([]string, 0, len(cr.Facts))
	for _, f := range cr.Facts {
		fact := f.Key.String()
		if v := f.Value.String(); v != "" {
			fact += ": " + v
		}
		facts = append(facts, fact)
	}
	switch {
	case len(facts) > 0:
		parts = append(parts, strings.Join(facts, "; "))
	case cr.Read != model.ReadOK:
		parts = append(parts, string(cr.Read))
	}
	p.Out.Printf("%s%s\n", p.text(indent), p.text(strings.Join(parts, "  ")))
}

// reach lists a project's verdicts by agent and credential: each channel's
// verdict and the reasons behind it.
func (p *Printer) reach(proj model.Project) {
	var agent model.Agent
	last := ""
	for _, r := range proj.Reach {
		if r.Agent != agent {
			agent, last = r.Agent, ""
			p.Out.Printf("    %s reach\n", p.text(string(r.Agent)))
		}
		where := r.Path.Text().String()
		if r.Path.IsZero() {
			where = r.Name.String()
		}
		if head := string(r.Kind) + "  " + where; head != last {
			last = head
			p.Out.Printf("      %s\n", p.text(head))
		}
		why := make([]string, 0, len(r.Why))
		for _, y := range r.Why {
			why = append(why, y.String())
		}
		ch := string(r.Channel)
		if !r.Via.IsZero() {
			ch += " (" + r.Via.String() + ")"
		}
		p.Out.Printf("        %s\n", p.text(ch+"  "+string(r.Verdict)+": "+strings.Join(why, "; ")))
	}
}

// valueDefault is how jarx says a setting is the agent's default.
const valueDefault = "default"

// credentialStates are the credential view's states, worst first.
//
//nolint:gochecknoglobals // fixed list, read only
var credentialStates = []model.CredentialState{model.StateSees, model.StateCanRead, model.StateCanUse, model.StateUnreachable}

// credentialLine is a project's credential view in one line: how many
// credentials are in each state, for each agent, worst first.
func (p *Printer) credentialLine(proj model.Project) node {
	var items []string
	for _, a := range []model.Agent{model.AgentClaude, model.AgentCodex} {
		counts := map[model.CredentialState]int{}
		for _, e := range proj.Exposure {
			if e.Agent == a {
				for _, st := range e.States {
					counts[st]++
				}
			}
		}
		var parts []string
		for _, st := range credentialStates {
			if n := counts[st]; n > 0 {
				parts = append(parts, strconv.Itoa(n)+" "+string(st))
			}
		}
		if len(parts) > 0 {
			parts[0] = string(a) + " " + parts[0]
			items = append(items, parts...)
		}
	}
	if len(items) == 0 {
		return nil
	}
	return p.wrapList("credentials: ", items)
}

// credentialView lists a project's credential view by agent: each
// credential, its states worst first, and what holds or shows it.
func (p *Printer) credentialView(proj model.Project) {
	var agent model.Agent
	for _, e := range proj.Exposure {
		if e.Agent != agent {
			agent = e.Agent
			p.Out.Printf("    %s credential view\n", p.text(string(e.Agent)))
		}
		where := e.Path.Text().String()
		switch {
		case e.Path.IsZero():
			where = e.Name.String()
		case !e.Name.IsZero():
			where = e.Name.String() + " in " + where
		}
		states := make([]string, 0, len(e.States))
		for _, st := range e.States {
			states = append(states, string(st))
		}
		line := string(e.Kind) + "  " + where + "  " + strings.Join(states, ", ")
		if len(e.Via) > 0 {
			via := make([]string, 0, len(e.Via))
			for _, v := range e.Via {
				via = append(via, v.String())
			}
			line += ": " + strings.Join(via, "; ")
		}
		p.Out.Printf("      %s\n", p.text(line))
	}
}
