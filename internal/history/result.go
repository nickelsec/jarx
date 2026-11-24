package history

import (
	"fmt"
	"slices"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// TranscriptLeak is a secret that ended up in session history.
func TranscriptLeak() finding.Rule {
	return finding.Rule{
		ID: "JARX-HISTORY-001", Severity: finding.Medium, Title: "A secret is in session history",
		Detail: "a secret was pasted, printed or read during a session, so it sits in plain text in the agent's history on disk and was sent to the model",
		Fix:    "rotate the secret, then delete the session (claude purge, or remove the file)",
	}
}

// TooLarge is a history file over the size jarx reads.
func TooLarge() finding.Rule {
	return finding.Rule{
		ID: "JARX-HISTORY-002", Severity: finding.Info, Title: "A history file is too large to read",
		Detail: "jarx skips history files over 200 MB, so this one wasn't checked for leaks or modes",
		Fix:    "nothing to do; delete old sessions if you want it checked",
	}
}

// Rules returns history's rules.
func Rules() []finding.Rule { return []finding.Rule{TranscriptLeak(), TooLarge()} }

func (r *reader) origin(path string, line int) model.Origin {
	return model.Origin{Agent: model.AgentClaude, File: model.NewPath(r.c.Scrub, path), Scope: model.ScopeUser, Line: line, InEffect: true, Observed: true}
}

func (r *reader) text(s string) redact.Text {
	t, _ := r.c.Scrub.Scrub(s)
	return t
}

// result merges every file's sessions by id and turns leaks into findings.
// Files are read in name order, so a session's own transcript comes before
// its set-aside copies.
func (r *reader) result(a model.Agent) Result {
	slices.Sort(r.files)
	r.sessions(a)
	holders := map[string]map[string]bool{} // fingerprint -> files
	for _, path := range r.files {
		for _, l := range r.cur.Files[path].Leaks {
			if holders[l.Fingerprint] == nil {
				holders[l.Fingerprint] = map[string]bool{}
			}
			holders[l.Fingerprint][path] = true
		}
	}
	for _, path := range r.files {
		for _, l := range r.cur.Files[path].Leaks {
			ev := fmt.Sprintf("line %d: %s REDACTED:%s:%s", l.Line, l.Kind, l.Kind, l.Fingerprint)
			if others := len(holders[l.Fingerprint]) - 1; l.Fingerprint != "" && others > 0 {
				ev += fmt.Sprintf(", also in %d other history %s", others, plural(others, "file", "files"))
			}
			r.res.Findings = append(r.res.Findings, TranscriptLeak().New(r.origin(path, l.Line), r.text(ev)))
		}
	}
	return r.res
}

// sessions merges every file's sessions by id, in file order.
func (r *reader) sessions(a model.Agent) {
	byID := map[string]*model.Session{}
	var order []string
	for _, path := range r.files {
		st := r.cur.Files[path]
		ids := make([]string, 0, len(st.Sessions))
		for id := range st.Sessions {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			s, ok := byID[id]
			if !ok {
				s = &model.Session{Agent: a, ID: r.text(id), File: model.NewPath(r.c.Scrub, path)}
				byID[id] = s
				order = append(order, id)
			}
			merge(r, s, st.Sessions[id])
		}
	}
	for _, id := range order {
		r.res.Sessions = append(r.res.Sessions, *byID[id])
	}
}

func merge(r *reader, s *model.Session, st *sessionState) {
	if s.CWD.IsZero() && st.CWD != "" {
		s.CWD = model.NewPath(r.c.Scrub, r.c.Env.MapPath(st.CWD))
	}
	for _, m := range st.Modes {
		if !slices.ContainsFunc(s.Modes, func(t redact.Text) bool { return t.String() == m }) {
			s.Modes = append(s.Modes, r.text(m))
		}
	}
	if st.Last.After(s.Last) {
		s.Last = st.Last
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
