package catalog

import "testing"

func TestTheCommandTableLoads(t *testing.T) {
	cs, err := Commands()
	if err != nil {
		t.Fatalf("Commands() error = %v", err)
	}
	if CommandsAsOf == "" {
		t.Error("CommandsAsOf is empty")
	}
	find := func(prog, sub string) (Command, bool) {
		for _, c := range cs {
			if c.Program == prog && c.Sub == sub {
				return c, true
			}
		}
		return Command{}, false
	}
	for _, want := range []struct {
		prog, sub string
		class     CommandClass
	}{
		{"python", "", RunsAnything},
		{"npm", "", RunsAnything},
		{"npm", "run", RunsRepoCode},
		{"npm", "exec", RunsAnything},
		{"python", "-m pytest", RunsRepoCode},
		{"git", "", HasEscape},
	} {
		c, ok := find(want.prog, want.sub)
		if !ok || c.Class != want.class || c.Why == "" {
			t.Errorf("%s %q = %+v, %v; want class %s with a why", want.prog, want.sub, c, ok, want.class)
		}
	}
}

func TestBadCommandRowsAreErrors(t *testing.T) {
	for name, tsv := range map[string]string{
		"bad class":    "python\t\tsometimes\twhy\n",
		"missing cols": "python\t\tany\n",
		"no why":       "python\t\tany\t\n",
		"duplicate":    "python\t\tany\twhy\npython\t\tany\twhy again\n",
		"upper case":   "Python\t\tany\twhy\n",
	} {
		if _, err := parseCommands(tsv); err == nil {
			t.Errorf("%s: parseCommands() error = nil", name)
		}
	}
}
