package poison

import (
	"regexp"
	"strings"
)

// match is one regexp match: where it starts and what it says.
type match struct {
	at   int
	text string
}

func allMatches(res []*regexp.Regexp, t string) []match {
	var out []match
	for _, re := range res {
		for _, m := range re.FindAllStringIndex(t, -1) {
			out = append(out, match{m[0], t[m[0]:m[1]]})
		}
	}
	return out
}

// aimedRes is text that works against you: overriding the agent's other
// instructions, keeping things from you, or doing things on the quiet.
// Ordinary instructions like "always run the tests" don't match.
//
//nolint:gochecknoglobals // fixed list, read only
var aimedRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override)\s+(?:(?:all|any|the|of|your|my|these|those)\s+){0,3}(?:previous|prior|earlier|above|preceding|other|your|all)\s+(?:instructions?|rules|guidelines|directions|prompts?|guidance)\b`),
	regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget)\s+(?:everything|anything)\s+(?:above|before|you\s+were\s+told)\b`),
	regexp.MustCompile(`(?i)\b(?:do\s+not|don't|dont|never)\s+(?:tell|inform|mention|reveal|disclose|report)\b[^.\n]{0,40}?\b(?:user|human|anyone|developer)s?\b`),
	regexp.MustCompile(`(?i)\b(?:secretly|covertly|silently|quietly)\s+(?:send|upload|post|copy|forward|run|execute|install|delete|exfiltrate|add)\b`),
	regexp.MustCompile(`(?i)\bbefore\s+(?:using|calling|running)\s+(?:any|every)\s+other\s+tools?\b`),
	regexp.MustCompile(`(?i)\b(?:new|updated|real)\s+system\s+(?:prompt|instructions?|message)\b`),
}

// withoutRe is "without telling the user". It's only aimed against you when
// the sentence isn't itself saying not to, like "don't deploy without
// telling the user".
var withoutRe = regexp.MustCompile(`(?i)\bwithout\s+(?:telling|informing|notifying|alerting|asking)\b[^.\n]{0,30}?\b(?:user|human|anyone|you)\b`)

var negationRe = regexp.MustCompile(`(?i)\b(?:don't|dont|do\s+not|never|not)\b`)

func aimedMatches(t string) []match {
	out := allMatches(aimedRes, t)
	for _, m := range withoutRe.FindAllStringIndex(t, -1) {
		sentence := t[sentenceStart(t, m[0]):m[0]]
		if !negationRe.MatchString(sentence) {
			out = append(out, match{m[0], t[m[0]:m[1]]})
		}
	}
	return out
}

func sentenceStart(t string, at int) int {
	return strings.LastIndexAny(t[:at], ".!?\n") + 1
}

func aimedAt(visible string) []hit {
	ms := aimedMatches(visible)
	out := make([]hit, 0, len(ms))
	for _, m := range ms {
		out = append(out, hit{aimed(), lineAt(visible, m.at), "\"" + excerpt(m.text) + "\""})
	}
	return out
}

// sensitiveRes are credential and key files an agent has no everyday
// reason to read. Both slash styles count, for Windows paths.
//
//nolint:gochecknoglobals // fixed list, read only
var sensitiveRes = []*regexp.Regexp{
	regexp.MustCompile(`~[/\\]\.ssh\b`),
	regexp.MustCompile(`\.ssh[/\\](?:id_[A-Za-z0-9_]+|authorized_keys)\b`),
	regexp.MustCompile(`\bid_(?:rsa|dsa|ecdsa|ed25519)\b`),
	regexp.MustCompile(`\.aws[/\\]credentials\b`),
	regexp.MustCompile(`\.(?:netrc|git-credentials|npmrc|pypirc)\b`),
	regexp.MustCompile(`\.docker[/\\]config\.json\b`),
	regexp.MustCompile(`\.kube[/\\]config\b`),
	regexp.MustCompile(`\.config[/\\]gh[/\\]hosts\.yml\b`),
	regexp.MustCompile(`\.codex[/\\]auth\.json\b`),
	regexp.MustCompile(`\.claude[/\\]\.credentials\.json\b`),
	regexp.MustCompile(`\.gnupg\b`),
	// .env and .env.local, but not .envrc or process.env.
	regexp.MustCompile(`(?:^|[\s"'` + "`" + `(/\\=@])\.env(?:\.[A-Za-z0-9_-]+)?\b`),
}

func sensitiveMatches(t string) []match {
	out := allMatches(sensitiveRes, t)
	for i := range out {
		out[i].text = strings.TrimLeft(out[i].text, " \t\r\n\"'`(/\\=@")
		if strings.HasPrefix(out[i].text, "env") {
			out[i].text = "." + out[i].text
		}
	}
	return out
}

func sensitive(visible string) []hit {
	ms := sensitiveMatches(visible)
	out := make([]hit, 0, len(ms))
	for _, m := range ms {
		out = append(out, hit{sensitivePath(), lineAt(visible, m.at), "points at " + m.text})
	}
	return out
}

// downloadRunRes is fetching code and handing it straight to a shell or an
// interpreter, in sh and PowerShell forms.
//
//nolint:gochecknoglobals // fixed list, read only
var downloadRunRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|python3?|perl|ruby|node|iex|invoke-expression)\b`),
	regexp.MustCompile(`(?i)\b(?:ba|z)?sh\s+(?:-c\s+)?["']?\$\(\s*(?:curl|wget)\b`),
	regexp.MustCompile(`(?i)\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b`),
	regexp.MustCompile(`(?i)\biex\s*\(\s*(?:irm|iwr|invoke-restmethod|invoke-webrequest|\(?\s*new-object\s+net\.webclient)`),
}

// sendRes is a tool that sends data, used on the same line as a credential
// or key file (checked by exfilShapes).
var sendRe = regexp.MustCompile(`(?i)(?:^|[\s;&|(])(?:curl|wget|nc|ncat|scp|rsync|ftp|iwr|irm|invoke-webrequest|invoke-restmethod)\b`)

//nolint:gochecknoglobals // fixed list, read only
var encodeSendRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:base64|encode|encoded|hex)\b[^.\n]{0,80}?\b(?:send|post|upload|exfiltrate|curl)\b`),
	regexp.MustCompile(`(?i)\b(?:send|post|upload)\b[^.\n]{0,80}?\b(?:base64|encoded)\b`),
}

// blobRe is a long base64 run, which can carry a hidden payload. Masked
// secrets are already gone, so a key doesn't count.
var blobRe = regexp.MustCompile(`[A-Za-z0-9+/]{200,}={0,2}`)

func downloadRunMatches(t string) []match { return allMatches(downloadRunRes, t) }

// exfilShapes is the exfil rule. In a hook, download-and-run is the hook
// rule instead, so it isn't reported twice.
func exfilShapes(t string, hook bool) []hit {
	var out []hit
	add := func(at int, what string) { out = append(out, hit{exfil(), lineAt(t, at), what}) }
	if !hook {
		for _, m := range downloadRunMatches(t) {
			add(m.at, "downloads and runs: \""+excerpt(m.text)+"\"")
		}
	}
	for _, m := range allMatches(encodeSendRes, t) {
		add(m.at, "encodes and sends: \""+excerpt(m.text)+"\"")
	}
	for _, m := range blobRe.FindAllStringIndex(t, -1) {
		add(m[0], "a base64 blob of "+itoa(m[1]-m[0])+" chars")
	}
	off := 0
	for _, line := range strings.SplitAfter(t, "\n") {
		if sendRe.MatchString(line) {
			if ps := sensitiveMatches(line); len(ps) > 0 {
				add(off, "sends "+ps[0].text+": \""+excerpt(line)+"\"")
			}
		}
		off += len(line)
	}
	return out
}

// hiddenExfil is exfil in text a person can't see, which is the high
// hidden rule.
func hiddenExfil(hidden string, line int, where string) []hit {
	ms := append(downloadRunMatches(hidden), allMatches(encodeSendRes, hidden)...)
	out := make([]hit, 0, len(ms))
	for _, m := range ms {
		out = append(out, hit{hiddenAimed(), line, where + ": \"" + excerpt(m.text) + "\""})
	}
	return out
}
