package discover

import (
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/credmeta"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// Limits on walking a credential dir: they're small, and a huge one is
// still counted, just not past these.
const (
	credDirDepth = 4
	credDirFiles = 500
)

// credentials finds the machine's credentials at every place credmeta
// knows, with their safe metadata. A dir like gcloud's is one entry with
// its file count; ~/.ssh is one entry per private key.
func credentials(c agent.Context) []model.Credential {
	var out []model.Credential
	seen := map[string]bool{}
	for _, pl := range credmeta.Places(c.Env) {
		if seen[pl.Path] {
			continue
		}
		seen[pl.Path] = true
		out = append(out, atPlace(c, pl)...)
	}
	return append(out, envVars(c)...)
}

// envVars are the env vars whose names say they hold a secret. Only the
// names are looked at: jarx never reads an env var's value.
func envVars(c agent.Context) []model.Credential {
	var out []model.Credential
	for _, name := range c.Env.Names() {
		if catalog.SecretName(name) {
			out = append(out, model.Credential{
				Kind: credmeta.KindEnvVar, Name: text(c, name), Via: text(c, "environment"), Read: model.ReadExistsOnly,
			})
		}
	}
	return out
}

// atPlace is what's at one place: nothing when it doesn't exist.
func atPlace(c agent.Context, pl credmeta.Place) []model.Credential {
	info, err := c.Files.Stat(pl.Path)
	switch {
	case err != nil:
	case !pl.Dir && info.Mode().IsRegular():
		return []model.Credential{credential(c, pl.Kind, pl.Path, pl.Via)}
	case pl.Dir && info.IsDir() && pl.Kind == credmeta.KindSSH:
		return sshKeys(c, pl)
	case pl.Dir && info.IsDir():
		return []model.Credential{dirCredential(c, pl)}
	}
	return nil
}

// dirCredential is one entry for a credential dir jarx only counts the
// files in, like gcloud's.
func dirCredential(c agent.Context, pl credmeta.Place) model.Credential {
	return model.Credential{
		Kind: model.CredentialKind(pl.Kind), Path: model.NewPath(c.Scrub, pl.Path), Dir: true, Via: text(c, pl.Via), Read: model.ReadExistsOnly,
		Facts: []model.Pair{{Key: text(c, "files"), Value: text(c, strconv.Itoa(len(filesIn(c, pl.Path))))}},
	}
}

// sshKeys is one credential per private key in ~/.ssh, skipping the files
// OpenSSH documents as something else.
func sshKeys(c agent.Context, pl credmeta.Place) []model.Credential {
	var out []model.Credential
	for _, path := range filesIn(c, pl.Path) {
		if credmeta.NotAKey(filepath.Base(path)) {
			continue
		}
		if cr := credential(c, pl.Kind, path, pl.Via); len(cr.Facts) > 0 || cr.Read != model.ReadOK {
			out = append(out, cr)
		}
	}
	return out
}

// projectCredentials are the credential files among a project's files.
func projectCredentials(c agent.Context, p model.Project) []model.Credential {
	var out []model.Credential
	for _, f := range p.Files {
		path := f.Raw()
		if !filepath.IsAbs(path) {
			path = filepath.Join(p.Path.Raw(), filepath.FromSlash(path)) // files are listed relative to the project
		}
		if at, ok := credmeta.Locate(c.Env, path); ok {
			out = append(out, credential(c, at.Kind, path, ""))
		}
	}
	return out
}

// credential reads one credential file's safe metadata through fsys, the
// one way to read a credential. A failure gives no detail: an error from a
// parser could quote the file.
func credential(c agent.Context, kind, path, via string) model.Credential {
	cr := model.Credential{Kind: model.CredentialKind(kind), Path: model.NewPath(c.Scrub, path), Read: model.ReadOK}
	if via != "" {
		cr.Via = text(c, via)
	}
	facts, err := c.Files.CredentialFacts(path)
	switch {
	case errors.Is(err, credmeta.ErrNotRead):
		cr.Read = model.ReadExistsOnly
	case err != nil:
		cr.Read = model.ReadFailed
	}
	for _, f := range facts {
		cr.Facts = append(cr.Facts, model.Pair{Key: text(c, f.Key), Value: text(c, f.Value)})
	}
	return cr
}

func text(c agent.Context, s string) redact.Text {
	t, _ := c.Scrub.Scrub(s)
	return t
}

// filesIn lists the files under dir, sorted, down to credDirDepth and up
// to credDirFiles.
func filesIn(c agent.Context, dir string) []string {
	var out []string
	var walk func(string, int)
	walk = func(d string, depth int) {
		entries, err := c.Files.ReadDir(d)
		if err != nil {
			return
		}
		for _, e := range entries {
			if len(out) >= credDirFiles {
				return
			}
			p := filepath.Join(d, e.Name())
			switch {
			case e.IsDir() && depth < credDirDepth:
				walk(p, depth+1)
			case e.Type()&fs.ModeType == 0:
				out = append(out, p)
			}
		}
	}
	walk(dir, 1)
	slices.Sort(out)
	return out
}
