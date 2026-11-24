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
	if v := cr.Via.String(); v != "" && v != "default" {
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
