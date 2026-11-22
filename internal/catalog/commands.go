package catalog

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
)

// CommandsAsOf is when commands.tsv was last checked.
const CommandsAsOf = "2026-11-23"

//go:embed commands.tsv
var commandsTSV string

// CommandClass is how much an allow for a command hands over.
type CommandClass string

// Command classes.
const (
	RunsAnything CommandClass = "any"    // runs any code it's given
	RunsRepoCode CommandClass = "repo"   // runs code the repo defines
	HasEscape    CommandClass = "escape" // a common tool with a way to run any command
)

// Command is one row of commands.tsv. Sub is empty for the program with any
// args, or the words that follow the program, like "run" or "-m pytest".
type Command struct {
	Program, Sub string
	Class        CommandClass
	Why          string
}

// Commands returns the command table.
func Commands() ([]Command, error) { return parseCommands(commandsTSV) }

const commandColumns = 4

var programRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

func checkCommand(c Command, seen map[string]bool) error {
	switch {
	case !programRe.MatchString(c.Program):
		return fmt.Errorf("bad program %q", c.Program)
	case c.Class != RunsAnything && c.Class != RunsRepoCode && c.Class != HasEscape:
		return fmt.Errorf("bad class %q", c.Class)
	case c.Why == "":
		return fmt.Errorf("%s %q has no why", c.Program, c.Sub)
	case seen[c.Program+"\x00"+c.Sub]:
		return fmt.Errorf("%s %q is listed twice", c.Program, c.Sub)
	}
	return nil
}

func parseCommands(tsv string) ([]Command, error) {
	var out []Command
	seen := map[string]bool{}
	for n, line := range strings.Split(tsv, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != commandColumns {
			return nil, fmt.Errorf("commands.tsv line %d: want program, subcommand, class and why, got %d columns", n+1, len(cols))
		}
		c := Command{Program: cols[0], Sub: cols[1], Class: CommandClass(cols[2]), Why: cols[3]}
		if err := checkCommand(c, seen); err != nil {
			return nil, fmt.Errorf("commands.tsv line %d: %w", n+1, err)
		}
		seen[c.Program+"\x00"+c.Sub] = true
		out = append(out, c)
	}
	return out, nil
}
