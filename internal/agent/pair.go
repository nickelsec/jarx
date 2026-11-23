package agent

import (
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// Pair scrubs an env var or header from a server definition. The value is
// scrubbed with its name in front, so the name rule sees API_TOKEN=... and
// not just a bare value. When that finds a secret the value alone doesn't,
// the whole value is masked as that kind. A ${VAR} reference is never a
// secret, so it stays readable.
func Pair(s *redact.Scrubber, name, value string) model.Pair {
	v, alone := s.Scrub(value)
	if _, named := s.Scrub(name + "=" + value); len(named) > len(alone) {
		v, _ = s.Secret(named[len(named)-1].Kind, value)
	}
	k, _ := s.Scrub(name)
	return model.Pair{Key: k, Value: v}
}
