package credmeta

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"io"
	"slices"
	"strings"
)

// sshHead is how much of a key file the ssh parser reads: enough for the
// armor, PEM headers and the start of an OpenSSH key's body.
const sshHead = 4 << 10

// opensshHead is how much of an OpenSSH key body gets decoded: the magic,
// cipher, kdf and the public key, which come before the private section.
// The decoded bytes are zeroed when the parser is done.
const opensshHead = 1 << 10

// lenSize is the size of an SSH wire string's length.
const lenSize = 4

// What a key's facts say.
const (
	unknown = "unknown"
	yes     = "yes"
	no      = "no"
)

// parseSSH gives a private key's type and whether it has a passphrase. A
// file that isn't a private key (config, known_hosts, a .pub) gives nothing.
func parseSSH(_ string, r io.Reader) ([]Fact, error) {
	s := bufio.NewScanner(io.LimitReader(r, sshHead))
	if !s.Scan() {
		return nil, nil
	}
	first := strings.TrimSpace(s.Text())
	var keyType, pass string
	switch {
	case first == "-----BEGIN OPENSSH PRIVATE KEY-----":
		keyType, pass = opensshMeta(s)
	case strings.HasPrefix(first, "-----BEGIN ") && strings.HasSuffix(first, " PRIVATE KEY-----"):
		keyType, pass = pemMeta(first, s)
	case strings.HasPrefix(first, "PuTTY-User-Key-File-"):
		keyType, pass = puttyMeta(first, s)
	default:
		return nil, nil
	}
	return []Fact{{"type", keyType}, {"passphrase", pass}}, nil
}

// opensshMeta reads the cipher name, which is "none" for a key with no
// passphrase (PROTOCOL.key), and the key type from the public key.
func opensshMeta(s *bufio.Scanner) (string, string) {
	raw := opensshBody(s)
	defer clear(raw)
	rest, ok := strings.CutPrefix(string(raw), "openssh-key-v1\x00")
	if !ok {
		return unknown, unknown
	}
	p := []byte(rest)
	cipher, ok1 := wireString(&p)
	_, ok2 := wireString(&p) // kdf name
	_, ok3 := wireString(&p) // kdf options
	if !ok1 || !ok2 || !ok3 || len(p) < lenSize {
		return unknown, unknown
	}
	pass := yes
	if string(cipher) == "none" {
		pass = no
	}
	p = p[lenSize:] // the number of keys
	pub, ok := wireString(&p)
	if !ok {
		return unknown, pass
	}
	keyType, ok := wireString(&pub)
	if !ok {
		return unknown, pass
	}
	return sshKeyType(string(keyType)), pass
}

// opensshBody decodes the first opensshHead bytes of an OpenSSH key body.
func opensshBody(s *bufio.Scanner) []byte {
	limit := base64.StdEncoding.EncodedLen(opensshHead)
	var b64 strings.Builder
	for b64.Len() < limit && s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "-----END") {
			break
		}
		b64.WriteString(line)
	}
	enc := b64.String()
	enc = enc[:min(len(enc), limit)]
	enc = enc[:len(enc)/lenSize*lenSize] // whole base64 groups only
	raw, _ := base64.StdEncoding.DecodeString(enc)
	return raw
}

// wireString reads an SSH wire string off the front of p.
func wireString(p *[]byte) ([]byte, bool) {
	if len(*p) < lenSize {
		return nil, false
	}
	n := int64(binary.BigEndian.Uint32(*p))
	if n > int64(len(*p)-lenSize) {
		return nil, false
	}
	out := (*p)[lenSize : lenSize+n]
	*p = (*p)[lenSize+n:]
	return out, true
}

// pemMeta reads a PEM key's label and, for the legacy formats, its
// Proc-Type header.
func pemMeta(first string, s *bufio.Scanner) (string, string) {
	switch label := strings.TrimSuffix(strings.TrimPrefix(first, "-----BEGIN "), " PRIVATE KEY-----"); label {
	case "ENCRYPTED":
		return unknown, yes // PKCS#8 with a passphrase
	case "":
		return unknown, no // PKCS#8 without one
	case "RSA":
		return "rsa", pemEncrypted(s)
	case "EC":
		return "ecdsa", pemEncrypted(s)
	case "DSA":
		return "dsa", pemEncrypted(s)
	default:
		return unknown, pemEncrypted(s)
	}
}

// pemEncrypted reads a legacy PEM key's headers for Proc-Type ENCRYPTED.
func pemEncrypted(s *bufio.Scanner) string {
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || !strings.Contains(line, ":") {
			break // the headers end at the body
		}
		if strings.HasPrefix(line, "Proc-Type:") && strings.Contains(line, "ENCRYPTED") {
			return yes
		}
	}
	return no
}

// puttyMeta reads a PuTTY key's type from its first line and its
// Encryption header.
func puttyMeta(first string, s *bufio.Scanner) (string, string) {
	_, keyType, _ := strings.Cut(first, ":")
	pass := unknown
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), "Encryption:"); ok {
			pass = yes
			if strings.TrimSpace(v) == "none" {
				pass = no
			}
			break
		}
	}
	return sshKeyType(strings.TrimSpace(keyType)), pass
}

// sshKeyType turns an SSH key type name into a short label.
func sshKeyType(t string) string {
	switch {
	case t == "ssh-ed25519":
		return "ed25519"
	case t == "ssh-rsa":
		return "rsa"
	case t == "ssh-dss":
		return "dsa"
	case strings.HasPrefix(t, "ecdsa-sha2-"):
		return "ecdsa"
	case strings.HasPrefix(t, "sk-ssh-ed25519"):
		return "ed25519-sk"
	case strings.HasPrefix(t, "sk-ecdsa-"):
		return "ecdsa-sk"
	}
	return unknown
}

// sshNotKeys are the files OpenSSH keeps in ~/.ssh that aren't private
// keys (ssh_config, sshd and ssh-keygen man pages).
//
//nolint:gochecknoglobals // fixed list, read only
var sshNotKeys = []string{"config", "known_hosts", "known_hosts.old", "authorized_keys", "authorized_keys2", "environment", "rc"}

// NotAKey says whether a file in ~/.ssh is one OpenSSH documents as
// something other than a private key: its config, host lists, authorized
// keys, and public keys (.pub).
func NotAKey(name string) bool {
	return strings.HasSuffix(name, ".pub") || slices.Contains(sshNotKeys, name)
}
