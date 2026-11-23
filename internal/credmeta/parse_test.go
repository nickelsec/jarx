package credmeta

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// canary marks every secret slot in the fixtures. No fact may hold it.
const canary = "CANARY"

func facts(t *testing.T, kind, rel string, body []byte) []string {
	t.Helper()
	fs, err := Parse(kind, rel, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Parse(%s, %s): %v", kind, rel, err)
	}
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Key+"="+f.Value)
	}
	return out
}

func noCanary(t *testing.T, got []string) {
	t.Helper()
	for _, f := range got {
		if strings.Contains(strings.ToUpper(f), canary) {
			t.Errorf("fact %q holds a secret from the file", f)
		}
	}
}

func TestParsersKeepOnlyTheAllowedFields(t *testing.T) {
	for fixture, tc := range map[string]struct {
		kind, rel string
		want      []string
	}{
		"aws/credentials": {"aws", "credentials", []string{"profile default=static keys", "profile dev=static keys"}},
		"aws/config": {"aws", "config", []string{
			"profile default=", "profile dev=sso", "profile ci=role", "profile proc=credential process",
			"profile both=static keys, role", "sso session my-sso=",
		}},
		"gh/hosts.yml": {"gh", "hosts.yml", []string{"host github.com=user octocat, token in the file", "host ghe.example.com=user dev-one, no token in the file"}},
		"docker/config.json": {"docker", "config.json", []string{
			"registry https://index.docker.io/v1/=inline auth", "registry ghcr.io=", "registry registry.example.com=inline auth",
			"creds store=desktop", "cred helper gcr.io=gcloud",
		}},
		"kube/config": {"kube", "config", []string{
			"cluster prod=", "context prod-admin=", "context dev=", "current context=prod-admin",
			"user admin=token", "user dev=client key", "user gke=exec", "user legacy=password",
		}},
		"netrc/netrc":     {"netrc", ".netrc", []string{"machine=api.example.com", "machine=git.example.com", "machine=default", "machine=ftp.example.com", "machine=odd.example.com"}},
		"git/credentials": {"git_credentials", ".git-credentials", []string{"url=https://github.com", "url=https://gitlab.example.com:8443"}},
		"npm/npmrc":       {"npmrc", ".npmrc", []string{"registry registry.npmjs.org/=_authToken", "registry npm.example.com/repo/=_auth", "default registry=_authToken"}},
		"pypi/pypirc":     {"pypirc", ".pypirc", []string{"index server pypi=", "index server private=pypi.example.com"}},
		"env/.env":        {"env_file", ".env", []string{"key=API_KEY", "key=DB_URL", "key=EMPTY", "key=SPACED_KEY"}},
	} {
		t.Run(fixture, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", "parse", filepath.FromSlash(fixture)))
			if err != nil {
				t.Fatal(err)
			}
			got := facts(t, tc.kind, tc.rel, body)
			if !slices.Equal(got, tc.want) {
				t.Errorf("facts =\n  %q\nwant\n  %q", got, tc.want)
			}
			noCanary(t, got)
		})
	}
}

func TestEveryFixtureHidesACanary(t *testing.T) {
	err := filepath.WalkDir(filepath.Join("testdata", "parse"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := os.ReadFile(path) //nolint:gosec // G304: our own fixture dir
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		if !strings.Contains(string(body), canary) {
			t.Errorf("%s has no canary, so it can't catch a leak", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestKindsThatAreOnlyCheckedForExistence(t *testing.T) {
	for _, kind := range []string{"gcloud", "azure", "gnupg", "claude_login", "codex_login", "private_key"} {
		if Reads(kind, "anything") {
			t.Errorf("Reads(%s) = true, want existence only", kind)
		}
	}
	for kind, rel := range map[string]string{"aws": "credentials", "ssh": "id_ed25519", "env_file": ".env"} {
		if !Reads(kind, rel) {
			t.Errorf("Reads(%s, %s) = false, want its metadata read", kind, rel)
		}
	}
}

func TestParseRefusesAKindItDoesntRead(t *testing.T) {
	if fs, err := Parse("azure", "msal_token_cache.json", strings.NewReader(`{"secret": "JARX-CANARY"}`)); err == nil || len(fs) != 0 {
		t.Errorf("Parse(azure) = %v, %v; want an error and nothing", fs, err)
	}
}

// sshString is an SSH wire string: a big-endian length, then the bytes.
func sshString(b []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) //nolint:gosec // G115: test keys are small
}

func armor(label string, raw []byte, headers string) []byte {
	b := base64.StdEncoding.EncodeToString(raw)
	var lines []string
	for len(b) > 70 {
		lines, b = append(lines, b[:70]), b[70:]
	}
	lines = append(lines, b)
	return []byte("-----BEGIN " + label + "-----\n" + headers + strings.Join(lines, "\n") + "\n-----END " + label + "-----\n")
}

// opensshKey is a made-up key in OpenSSH's own format (PROTOCOL.key), with
// a canary in the private section, which is plain text when cipher is none.
// Tests build keys here instead of committing key files, so nothing in the
// repo looks like a private key.
func opensshKey(keyType, cipher string, pub []byte) []byte {
	kdf, kdfOpts := "none", []byte{}
	if cipher != "none" {
		kdf, kdfOpts = "bcrypt", append(sshString(make([]byte, 16)), 0, 0, 0, 16)
	}
	priv := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 0x1234), 0x1234)
	priv = append(priv, sshString([]byte(keyType))...)
	priv = append(priv, sshString([]byte("JARX-CANARY-PRIVATE-"+strings.Repeat("A", 40)))...)
	raw := append([]byte("openssh-key-v1\x00"), sshString([]byte(cipher))...)
	raw = append(raw, sshString([]byte(kdf))...)
	raw = append(raw, sshString(kdfOpts)...)
	raw = binary.BigEndian.AppendUint32(raw, 1)
	raw = append(raw, sshString(append(sshString([]byte(keyType)), pub...))...)
	raw = append(raw, sshString(priv)...)
	return armor("OPENSSH PRIVATE KEY", raw, "")
}

func TestSSHKeysGiveTheirTypeAndWhetherTheyHaveAPassphrase(t *testing.T) {
	rsaPub := append(sshString([]byte{1, 0, 1}), sshString(bytes.Repeat([]byte{0x22}, 513))...)
	ecPub := append(sshString([]byte("nistp256")), sshString(bytes.Repeat([]byte{0x33}, 65))...)
	pemHeaders := "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\n"
	for name, tc := range map[string]struct {
		body []byte
		want []string
	}{
		"openssh ed25519, none":  {opensshKey("ssh-ed25519", "none", sshString(bytes.Repeat([]byte{0x11}, 32))), []string{"type=ed25519", "passphrase=no"}},
		"openssh rsa, encrypted": {opensshKey("ssh-rsa", "aes256-ctr", rsaPub), []string{"type=rsa", "passphrase=yes"}},
		"openssh ecdsa":          {opensshKey("ecdsa-sha2-nistp256", "none", ecPub), []string{"type=ecdsa", "passphrase=no"}},
		"pem rsa, encrypted":     {armor("RSA PRIVATE KEY", []byte("JARX-CANARY-PEM"), pemHeaders), []string{"type=rsa", "passphrase=yes"}},
		"pem ec":                 {armor("EC PRIVATE KEY", []byte("JARX-CANARY-EC"), ""), []string{"type=ecdsa", "passphrase=no"}},
		"pkcs8":                  {armor("PRIVATE KEY", []byte("JARX-CANARY-PKCS8"), ""), []string{"type=unknown", "passphrase=no"}},
		"pkcs8, encrypted":       {armor("ENCRYPTED PRIVATE KEY", []byte("JARX-CANARY-PKCS8E"), ""), []string{"type=unknown", "passphrase=yes"}},
		"putty v3": {[]byte("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: fake\nPrivate-Lines: 1\nJARX-CANARY-PUTTY\n"),
			[]string{"type=ed25519", "passphrase=no"}},
		"putty v2, encrypted": {[]byte("PuTTY-User-Key-File-2: ssh-rsa\nEncryption: aes256-cbc\nPrivate-Lines: 1\nJARX-CANARY-PUTTY2\n"),
			[]string{"type=rsa", "passphrase=yes"}},
		"ssh config":        {[]byte("Host demo\n  IdentityFile ~/.ssh/id_ed25519\n"), nil},
		"public key":        {[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBER fake@demo\n"), nil},
		"truncated openssh": {[]byte("-----BEGIN " + "OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n"), []string{"type=unknown", "passphrase=unknown"}},
	} {
		t.Run(name, func(t *testing.T) {
			got := facts(t, "ssh", "id_key", tc.body)
			if !slices.Equal(got, tc.want) {
				t.Errorf("facts = %q, want %q", got, tc.want)
			}
			noCanary(t, got)
		})
	}
}
