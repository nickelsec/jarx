package model

import (
	"regexp"
	"slices"
	"strings"
)

// changeWords are tool name words that say the tool changes something.
//
//nolint:gochecknoglobals // fixed list, read only
var changeWords = []string{
	"delete", "remove", "rm", "drop", "destroy", "erase", "wipe", "purge", "truncate", "overwrite",
	"write", "update", "create", "save", "set", "put", "post", "send", "upload", "push", "publish",
	"deploy", "move", "rename", "modify", "edit", "exec", "execute", "run", "kill", "revoke", "transfer", "pay",
}

var camelBreak = regexp.MustCompile(`([a-z0-9])([A-Z])`)

// ChangeWord is the first word of the offer's name that says it changes
// something, like delete or send, or "". The name splits at _, -, ., spaces
// and camelCase, and only whole words count.
func (o Offer) ChangeWord() string {
	name := strings.ToLower(camelBreak.ReplaceAllString(o.Name.String(), "${1}_${2}"))
	for _, w := range strings.FieldsFunc(name, func(r rune) bool { return r == '_' || r == '-' || r == '.' || r == ' ' }) {
		if slices.Contains(changeWords, w) {
			return w
		}
	}
	return ""
}
