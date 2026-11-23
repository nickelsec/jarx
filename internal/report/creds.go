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
	parts := []string{string(cr.Kind), cr.Path.Text().String()}
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
