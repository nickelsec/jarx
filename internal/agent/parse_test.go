package agent

import (
	"slices"
	"strings"
	"testing"
)

func TestImportsFollowTheDocumentedSyntax(t *testing.T) {
	text := strings.Join([]string{
		"See @README for the overview and @package.json for scripts.", // 1
		"- git workflow @docs/git-instructions.md",                    // 2
		"- @~/.claude/my-project-instructions.md",                     // 3
		"- API conventions @Design\\ Docs/api-conventions.md",         // 4: escaped space
		"Design @Design Docs/x.md stops at the space",                 // 5
		"quoted @\"docs/q.md\" is not an import",                      // 6
		"mail me at someone@example.com, not an import",               // 7
		"literal `@README` in a code span",                            // 8
		"```",                                                         // 9
		"@inside/a/fence.md",                                          // 10
		"```",                                                         // 11
		"~~~md",                                                       // 12
		"@inside/tilde/fence.md",                                      // 13
		"~~~",                                                         // 14
		"@/etc/absolute.md and @../up.md",                             // 15
		"lone @ sign",                                                 // 16
		"``double `@ticks` span`` then @after.md",                     // 17
	}, "\n")

	imports := Imports(text)
	got := make([]string, 0, len(imports))
	for _, im := range imports {
		got = append(got, im.Path+":"+itoa(im.Line))
	}

	want := []string{
		"README:1", "package.json:1",
		"docs/git-instructions.md:2",
		"~/.claude/my-project-instructions.md:3",
		"Design Docs/api-conventions.md:4",
		"Design:5",
		"/etc/absolute.md:15", "../up.md:15",
		"after.md:17",
	}
	if !slices.Equal(got, want) {
		t.Errorf("imports =\n%q\nwant\n%q", got, want)
	}
}

func TestImportsAreCapped(t *testing.T) {
	text := strings.Repeat("@a.md ", MaxImportsPerFile+50)

	if got := len(Imports(text)); got != MaxImportsPerFile {
		t.Errorf("imports = %d, want the cap %d", got, MaxImportsPerFile)
	}
}

func TestFrontmatterSplitsTheHeader(t *testing.T) {
	for name, tc := range map[string]struct {
		text  string
		keys  map[string]string
		body  string
		hasFM bool
	}{
		"plain": {"# Title\nbody\n", nil, "# Title\nbody\n", false},
		"header": {
			"---\nname: Diagrams first\npaths:\n  - \"src/**/*.ts\"\n---\n# Rules\n",
			map[string]string{"name": "Diagrams first", "paths": ""}, "# Rules\n", true,
		},
		"crlf and bom": {
			string(rune(0xFEFF)) + "---\r\nname: x\r\n---\r\nbody", map[string]string{"name": "x"}, "body", true,
		},
		"quoted value":   {"---\nname: \"Quoted\"\n---\n", map[string]string{"name": "Quoted"}, "", true},
		"never closed":   {"---\nname: x\nbody\n", nil, "---\nname: x\nbody\n", false},
		"not at the top": {"text\n---\nname: x\n---\n", nil, "text\n---\nname: x\n---\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			fm, body, ok := Frontmatter(tc.text)

			if ok != tc.hasFM || body != tc.body {
				t.Errorf("Frontmatter() body = %q, ok = %v; want %q, %v", body, ok, tc.body, tc.hasFM)
			}
			for k, v := range tc.keys {
				if got, has := fm[k]; !has || got != v {
					t.Errorf("key %s = %q (%v), want %q", k, got, has, v)
				}
			}
			if len(fm) != len(tc.keys) {
				t.Errorf("keys = %v, want %v", fm, tc.keys)
			}
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
