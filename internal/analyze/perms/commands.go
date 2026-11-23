package perms

import (
	"regexp"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/catalog"
)

// classify says what an allow for a command pattern hands over, and why,
// from the command table. A class of "" means nothing more than it looks.
//
// The pattern is a Bash or PowerShell rule's target, like "npm run *".
// Claude reads a trailing ":*" like " *". A program with open args right
// after it is the program's base row; a program followed by a subcommand
// the table lists is that row, open or exact. Task runners count however
// they're called, since every target they run is the repo's.
func classify(cmds []catalog.Command, pattern string) (catalog.CommandClass, string) {
	words, open := splitPattern(pattern)
	if len(words) == 0 || strings.Contains(words[0], "*") {
		return "", ""
	}
	prog, inRepo := program(words[0])
	if inRepo {
		return catalog.RunsRepoCode, "runs " + words[0] + ", a file in the repo"
	}
	args := words[1:]
	if c, ok := longestSub(cmds, prog, args); ok {
		return c.Class, c.Why
	}
	base, ok := baseRow(cmds, prog)
	if !ok {
		return "", ""
	}
	return byBase(base, prog, args, open)
}

// splitPattern splits a command pattern into its fixed words, and says
// whether it ends open (with *).
func splitPattern(pattern string) ([]string, bool) {
	p := strings.TrimSpace(pattern)
	if rest, ok := strings.CutSuffix(p, ":*"); ok {
		p = rest + " *"
	}
	words := strings.Fields(p)
	open := len(words) > 0 && words[len(words)-1] == "*"
	if open {
		words = words[:len(words)-1]
	}
	return words, open
}

// byBase classifies a pattern by its program's base row.
func byBase(base catalog.Command, prog string, args []string, open bool) (catalog.CommandClass, string) {
	switch base.Class {
	case catalog.RunsRepoCode:
		return base.Class, base.Why
	case catalog.HasEscape:
		if open && len(args) == 0 {
			return base.Class, base.Why
		}
	case catalog.RunsAnything:
		if open && allFlags(args) {
			return base.Class, base.Why
		}
		if len(args) > 0 && looksLikeFile(args[0]) {
			return catalog.RunsRepoCode, "runs " + args[0] + ", a file in the repo, with " + prog
		}
	}
	return "", ""
}

func longestSub(cmds []catalog.Command, prog string, args []string) (catalog.Command, bool) {
	var best catalog.Command
	found := false
	for _, c := range cmds {
		sub := strings.Fields(c.Sub)
		if c.Program != prog || len(sub) == 0 || len(sub) > len(args) || !slices.Equal(args[:len(sub)], sub) {
			continue
		}
		if !found || len(sub) > len(strings.Fields(best.Sub)) {
			best, found = c, true
		}
	}
	return best, found
}

func baseRow(cmds []catalog.Command, prog string) (catalog.Command, bool) {
	for _, c := range cmds {
		if c.Program == prog && c.Sub == "" {
			return c, true
		}
	}
	return catalog.Command{}, false
}

var driveRe = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

// program is the program a command's first word names, lowercased, without
// its dir, .exe or version suffix (python3.12 is python). A relative path,
// like ./scripts/test.sh, is a file in the repo.
func program(word string) (string, bool) {
	w := strings.Trim(word, `"'`)
	if strings.ContainsAny(w, `/\`) {
		abs := strings.HasPrefix(w, "/") || strings.HasPrefix(w, "~") || strings.HasPrefix(w, `\\`) || driveRe.MatchString(w)
		if !abs {
			return "", true
		}
		w = w[strings.LastIndexAny(w, `/\`)+1:]
	}
	w = strings.TrimSuffix(strings.ToLower(w), ".exe")
	if t := strings.TrimRight(w, "0123456789."); t != "" {
		w = t
	}
	return w, false
}

func allFlags(args []string) bool {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return false
		}
	}
	return true
}

// looksLikeFile is an interpreter's script argument: a path, or a file with
// a script extension.
func looksLikeFile(arg string) bool {
	if strings.HasPrefix(arg, "-") {
		return false
	}
	if strings.ContainsAny(arg, `/\`) {
		return true
	}
	for _, ext := range []string{".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php", ".sh", ".ps1", ".lua"} {
		if strings.HasSuffix(strings.ToLower(arg), ext) {
			return true
		}
	}
	return false
}
