package model

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nickelsec/jarx/internal/redact"
)

// The model must never hold a raw string. Text is redact.Text, paths are
// Path. rawStrings walks a type and returns every place a raw string could
// hide in it.

// leafTypes are allowed as they are, without looking inside. Each keeps its
// raw value unexported: Text and Path only ever show the masked form, and
// Launch shows nothing (its own test proves it never prints or encodes).

func leafTypes() []reflect.Type {
	return []reflect.Type{reflect.TypeFor[redact.Text](), reflect.TypeFor[Path](), reflect.TypeFor[Launch]()}
}

// enumTypes are named string types whose values are our own constants.
func enumTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeFor[Agent](), reflect.TypeFor[Scope](),
		reflect.TypeFor[ProjectStatus](), reflect.TypeFor[TrustLevel](), reflect.TypeFor[WalkMethod](),
		reflect.TypeFor[RuleAction](), reflect.TypeFor[InstructionKind](), reflect.TypeFor[LoadWhen](),
		reflect.TypeFor[ReadStatus](), reflect.TypeFor[SkillKind](),
		reflect.TypeFor[Transport](), reflect.TypeFor[StartState](), reflect.TypeFor[ServerStatus](), reflect.TypeFor[OfferKind](), reflect.TypeFor[ToolAccess](),
		reflect.TypeFor[CredentialKind](),
	}
}

const modelPkg = "github.com/nickelsec/jarx/internal/model"

// walker collects every raw string hiding spot in a type.
type walker struct {
	found []string
	seen  map[reflect.Type]bool
}

func rawStrings(t reflect.Type) []string {
	w := &walker{seen: map[reflect.Type]bool{}}
	w.walk(t, t.String())
	return w.found
}

func (w *walker) flag(at, why string) { w.found = append(w.found, at+" "+why) }

// walk lists every reflect kind on purpose, so a kind can't slip through a
// default case unnoticed.
//
//nolint:cyclop // one case per reflect kind
func (w *walker) walk(t reflect.Type, at string) {
	if slices.Contains(leafTypes(), t) || slices.Contains(enumTypes(), t) {
		return
	}
	switch t.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return // bools and numbers can't hold text
	case reflect.String:
		w.flag(at, "is a string ("+t.String()+")")
	case reflect.Slice, reflect.Array:
		if k := t.Elem().Kind(); k == reflect.Uint8 || k == reflect.Int32 {
			w.flag(at, "holds bytes or runes ("+t.String()+")")
			return
		}
		w.walk(t.Elem(), at+"[]")
	case reflect.Map:
		w.walk(t.Key(), at+"[key]")
		w.walk(t.Elem(), at+"[value]")
	case reflect.Pointer:
		w.walk(t.Elem(), at)
	case reflect.Struct:
		w.walkStruct(t, at)
	case reflect.Interface, reflect.Func, reflect.Chan, reflect.UnsafePointer,
		reflect.Complex64, reflect.Complex128, reflect.Invalid:
		w.flag(at, "is a "+t.Kind().String()+" ("+t.String()+"), which can hold anything")
	}
}

func (w *walker) walkStruct(t reflect.Type, at string) {
	if w.seen[t] {
		return
	}
	w.seen[t] = true
	if t.PkgPath() != modelPkg && t.Name() != "" {
		w.flag(at, "is "+t.String()+", a type from another package that isn't allowlisted")
		return
	}
	for f := range t.Fields() {
		w.walk(f.Type, at+"."+f.Name)
	}
}

func TestInventoryHoldsNoRawStrings(t *testing.T) {
	if found := rawStrings(reflect.TypeFor[Inventory]()); len(found) > 0 {
		t.Errorf("the model holds raw strings:\n  %s", strings.Join(found, "\n  "))
	}
}

// The fixtures below each hide a string a different way. The walker has to
// flag every one, or the test above proves nothing.

type (
	myString       string
	embeddedString struct{ S string }
	recursive      struct {
		Next *recursive
		S    string
	}
)

type (
	hidePlain      struct{ S string }
	hideUnexported struct{ s string } //nolint:unused // the walker has to find this field
	hideNamed      struct{ N myString }
	hidePointer    struct{ P *string }
	hideSlice      struct{ L []string }
	hideArray      struct{ A [2]string }
	hideMapKey     struct{ M map[string]int }
	hideMapValue   struct{ M map[int]string }
	hideBytes      struct{ B []byte }
	hideRunes      struct{ R []rune }
	hideInterface  struct{ I any }
	hideError      struct{ E error }
	hideFunc       struct{ F func() string }
	hideChan       struct{ C chan int }
	hideEmbedded   struct{ embeddedString }
	hideDeep       struct {
		X struct{ Y []map[int]*struct{ Z string } }
	}
	hideGeneric   struct{ S Setting[string] }
	hideForeign   struct{ T time.Time }
	hideRecursive struct{ R recursive }
)

func TestRawStringsFindsEveryHidingSpot(t *testing.T) {
	for name, typ := range map[string]reflect.Type{
		"plain field":      reflect.TypeFor[hidePlain](),
		"unexported field": reflect.TypeFor[hideUnexported](),
		"named string":     reflect.TypeFor[hideNamed](),
		"pointer":          reflect.TypeFor[hidePointer](),
		"slice":            reflect.TypeFor[hideSlice](),
		"array":            reflect.TypeFor[hideArray](),
		"map key":          reflect.TypeFor[hideMapKey](),
		"map value":        reflect.TypeFor[hideMapValue](),
		"bytes":            reflect.TypeFor[hideBytes](),
		"runes":            reflect.TypeFor[hideRunes](),
		"interface":        reflect.TypeFor[hideInterface](),
		"error":            reflect.TypeFor[hideError](),
		"func":             reflect.TypeFor[hideFunc](),
		"chan":             reflect.TypeFor[hideChan](),
		"embedded struct":  reflect.TypeFor[hideEmbedded](),
		"deep nesting":     reflect.TypeFor[hideDeep](),
		"generic":          reflect.TypeFor[hideGeneric](),
		"foreign struct":   reflect.TypeFor[hideForeign](),
		"recursive type":   reflect.TypeFor[hideRecursive](),
	} {
		if found := rawStrings(typ); len(found) == 0 {
			t.Errorf("%s: rawStrings(%s) found nothing, want it flagged", name, typ)
		}
	}
}

type clean struct {
	T  redact.Text
	P  Path
	A  Agent
	S  Scope
	B  bool
	N  int
	L  []redact.Text
	M  map[Scope]Path
	O  *Origin
	G  Setting[redact.Text]
	GB Setting[bool]
	R  *clean
}

func TestRawStringsAllowsTheModelsOwnTypes(t *testing.T) {
	if found := rawStrings(reflect.TypeFor[clean]()); len(found) > 0 {
		t.Errorf("clean fixture flagged:\n  %s", strings.Join(found, "\n  "))
	}
}
