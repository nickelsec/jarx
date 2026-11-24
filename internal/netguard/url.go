package netguard

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Errors from CheckURL, besides ErrInsecure and ErrBlocked.
var (
	ErrBadURL        = errors.New("not a full URL")
	ErrURLSecretSpot = errors.New("a user, password, query or fragment in the URL")
)

// CheckURL checks a URL jarx is about to save or call, by its text, with
// the same rules a request gets: https, or plain http to loopback only, and
// no metadata names or addresses. It also refuses a user, a password, a
// query or a fragment, since that's where keys hide in URLs. Plain http to
// a name other than localhost is refused, since the name could resolve
// anywhere; the dial-time check still runs on every request. Errors never
// quote the URL, which could hold a secret.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !fullURL(u) {
		return fmt.Errorf("%w: want one like https://host/v1", ErrBadURL)
	}
	if secretSpot(u, raw) {
		return ErrURLSecretSpot
	}
	loopback, err := checkHost(u.Hostname())
	if err != nil {
		return err
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if loopback {
			return nil
		}
		return fmt.Errorf("%w: plain http only goes to loopback (127.0.0.1, ::1, localhost)", ErrInsecure)
	default:
		return fmt.Errorf("%w: only https, or plain http to loopback", ErrInsecure)
	}
}

func fullURL(u *url.URL) bool { return u.IsAbs() && u.Opaque == "" && u.Hostname() != "" }

// secretSpot is a user, a password, a query or a fragment, even an empty one.
func secretSpot(u *url.URL, raw string) bool {
	return u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#")
}

// checkHost refuses metadata names and blocked addresses, and says whether
// the host is loopback: a loopback IP, or localhost.
func checkHost(host string) (bool, error) {
	if blockedName(host) {
		return false, fmt.Errorf("%w: a cloud metadata name", ErrBlocked)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if checkAddr(ip) != nil {
			return false, fmt.Errorf("%w: a link-local, metadata or unspecified address", ErrBlocked)
		}
		return ip.WithZone("").Unmap().IsLoopback(), nil
	}
	return strings.EqualFold(strings.TrimSuffix(host, "."), "localhost"), nil
}
