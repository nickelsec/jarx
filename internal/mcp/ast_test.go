package mcp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The client's promise is that it only discovers and lists. This test reads
// the package's own source and fails if any MCP method other than those
// shows up as a string, so a later change can't add a call by accident.

// listOnly is every method string the package may contain.
//
//nolint:gochecknoglobals // fixed list, read only
var listOnly = []string{
	"server/discover", "initialize", "notifications/initialized",
	"tools/list", "prompts/list", "resources/list",
}

// methodLike is a string shaped like an MCP method: words joined by
// slashes, like tools/call or notifications/roots/list_changed.
var methodLike = regexp.MustCompile(`^[a-z][a-zA-Z_]*(/[a-zA-Z_]+)+$`)

// mediaTypes are the slash strings that aren't methods.
//
//nolint:gochecknoglobals // fixed list, read only
var mediaTypes = []string{"application/json", "text/event-stream"}

func TestThePackageHoldsNoMethodButListing(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		if !strings.HasSuffix(f, "_test.go") {
			checkSource(t, f)
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no source files checked")
	}
}

// checkSource fails on any method string in one file but discovery and
// the lists.
func checkSource(t *testing.T, f string) {
	t.Helper()
	src, err := os.ReadFile(f) //nolint:gosec // G304: a file of this package, from Glob
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, f, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if _, ok := n.(*ast.ImportSpec); ok {
			return false // import paths like net/http look like methods but aren't
		}
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if s, err := strconv.Unquote(lit.Value); err == nil && forbidden(s) {
			t.Errorf("%s: method %q isn't discovery or a list", fset.Position(lit.Pos()), s)
		}
		return true
	})
}

// forbidden says whether s is a method string outside discovery and lists.
func forbidden(s string) bool {
	return (methodLike.MatchString(s) || s == "initialize") && !slices.Contains(listOnly, s) && !slices.Contains(mediaTypes, s)
}

func TestTheASTCheckCatchesACall(t *testing.T) {
	for _, s := range []string{"tools/call", "resources/read", "prompts/get", "sampling/createMessage"} {
		if !methodLike.MatchString(s) || slices.Contains(listOnly, s) {
			t.Errorf("%q would get past the source check", s)
		}
	}
}
