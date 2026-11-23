package poison

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func itoa(n int) string { return strconv.Itoa(n) }

// networkRe is a network tool in command position, or a URL.
var networkRe = regexp.MustCompile(`(?im)(?:^\s*|[;&|(]\s*|\$\(\s*|\bsudo\s+)(?:curl|wget|nc|ncat|telnet|scp|rsync|ftp|iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer)\b|\bhttps?://`)

// startupTargetRe is a file or place that runs at shell start or login.
var startupTargetRe = regexp.MustCompile(`(?i)\.(?:bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv|zlogin|kshrc|cshrc|tcshrc)\b|config[/\\]fish[/\\]config\.fish|\$profile\b|powershell_profile\.ps1|launchagents|launchdaemons|\.config[/\\]autostart|systemd[/\\]user|/etc/cron|/etc/rc\.local|currentversion\\run|start menu\\programs\\startup`)

// startupWriteRes write to a startup target on the same line. A target
// mentioned in a read, like grep ~/.bashrc 2>/dev/null, doesn't count.
//
//nolint:gochecknoglobals // fixed list, read only
var startupWriteRes = withTarget(
	`>>?\s*["']?[^\s"']*$T`,
	`(?i)\btee\s+(?:-a\s+)?["']?[^\s"']*$T`,
	`(?i)\b(?:cp|mv|ln|install)\b[^\n;&|]*$T`,
	`(?i)\b(?:add-content|set-content|out-file)\b[^\n]*$T`,
	`(?i)\bsed\s+-i\b[^\n;&|]*$T`,
	`(?i)\breg(?:\.exe)?\s+add\b[^\n]*$T`,
	`(?i)\b(?:new|set)-itemproperty\b[^\n]*$T`,
)

// withTarget compiles each pattern with $T standing for a startup target.
func withTarget(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile(strings.ReplaceAll(p, "$T", "(?:"+startupTargetRe.String()+")")))
	}
	return out
}

// crontabWriteRe installs a crontab: crontab with a file or -, not -l.
var crontabWriteRe = regexp.MustCompile(`(?i)\bcrontab\s+(?:-\s|-$|[^-\s])`)

// tempRe is a temp dir at the start of a path.
var tempRe = regexp.MustCompile(`(?i)^(?:/tmp/|/var/tmp/|/dev/shm/|/private/tmp/|/private/var/folders/|\$tmpdir\b|\$\{tmpdir\}|%temp%|%tmp%|\$env:te?mp\b|[a-z]:\\users\\[^\\]+\\appdata\\local\\temp\\|%localappdata%\\temp\\)`)

// interpreters run the next word as a program.
//
//nolint:gochecknoglobals // fixed list, read only
var interpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "python": true, "python3": true,
	"node": true, "perl": true, "ruby": true, "pwsh": true, "powershell": true, "sudo": true, "exec": true,
}

func hookRules(src source) []hit {
	t := src.text
	var out []hit
	if strings.EqualFold(src.hookType, "http") {
		out = append(out, hit{hookNetwork(), 1, "an http hook sends each event to " + excerpt(t)})
	} else if loc := networkRe.FindStringIndex(t); loc != nil {
		out = append(out, hit{hookNetwork(), lineAt(t, loc[0]), "\"" + excerpt(lineOf(t, loc[0])) + "\""})
	}
	for _, m := range downloadRunMatches(t) {
		out = append(out, hit{hookDownloadRun(), lineAt(t, m.at), "\"" + excerpt(m.text) + "\""})
	}
	off := 0
	for _, line := range strings.SplitAfter(t, "\n") {
		if startupWrite(line) {
			out = append(out, hit{hookStartup(), lineAt(t, off), "\"" + excerpt(line) + "\""})
		}
		off += len(line)
	}
	if src.script {
		if p := src.origin.File.Raw(); outsideTemp(p, src.project) {
			out = append(out, hit{hookTemp(), 0, "its script is in a temp dir"})
		}
	} else if prog := program(t); outsideTemp(prog, src.project) {
		out = append(out, hit{hookTemp(), 1, "runs " + prog})
	}
	return out
}

// outsideTemp reports a path in a temp dir that isn't inside the project.
// A repo cloned into a temp dir has its own scripts there, and that's the
// project's file, not a hook reaching out to a temp dir.
func outsideTemp(path, project string) bool {
	if path == "" || !tempRe.MatchString(path) {
		return false
	}
	if project == "" {
		return true
	}
	rel, err := filepath.Rel(project, path)
	return err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func startupWrite(line string) bool {
	for _, re := range startupWriteRes {
		if re.MatchString(line) {
			return true
		}
	}
	return crontabWriteRe.MatchString(line) && !strings.Contains(line, "crontab -l")
}

// program is the program a command runs: its first word, past env
// assignments and interpreters like sh or python.
func program(cmd string) string {
	for w := range strings.FieldsSeq(cmd) {
		w = strings.Trim(w, `"'`)
		switch {
		case strings.Contains(w, "=") && !strings.ContainsAny(w, `/\`):
			continue // FOO=bar
		case strings.HasPrefix(w, "-"):
			continue // a flag of an interpreter
		case interpreters[strings.ToLower(w)]:
			continue
		}
		return w
	}
	return ""
}

func lineOf(t string, at int) string {
	start := strings.LastIndex(t[:at], "\n") + 1
	end := strings.Index(t[at:], "\n")
	if end < 0 {
		return t[start:]
	}
	return t[start : at+end]
}
