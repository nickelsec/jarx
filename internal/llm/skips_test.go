package llm

import (
	"slices"
	"testing"

	"github.com/nickelsec/jarx/internal/jarxdir"
)

func TestNothingIsSkippedAtFirst(t *testing.T) {
	sk := LoadSkips(fakeEnv(t))

	if sk.Has(KeyOf(skillArtifact(t, lintSkill))) || sk.Len() != 0 {
		t.Error("a fresh skip list skips something")
	}
}

func TestASkipIsKeptAndUndoneByTheArtifactsContent(t *testing.T) {
	env := fakeEnv(t)
	art := skillArtifact(t, lintSkill)
	changed := skillArtifact(t, lintSkill+"\nand one more line")
	sk := LoadSkips(env)

	sk.Set([]string{KeyOf(art)}, true)
	if err := sk.Save(env); err != nil {
		t.Fatal(err)
	}
	back := LoadSkips(env)

	if !back.Has(KeyOf(art)) || back.Has(KeyOf(changed)) {
		t.Error("the skip isn't kept, or it holds for a changed artifact")
	}
	back.Set([]string{KeyOf(art)}, false)
	if err := back.Save(env); err != nil {
		t.Fatal(err)
	}
	if LoadSkips(env).Has(KeyOf(art)) {
		t.Error("an undone skip is still kept")
	}
}

func TestABadSkipFileSkipsNothing(t *testing.T) {
	env := fakeEnv(t)
	d, err := jarxdir.Open(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.WriteFile(skipsFile, []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	_ = d.Close()

	if LoadSkips(env).Len() != 0 {
		t.Error("a broken skip file skips something")
	}
}

func TestUnskippedLeavesTheSkippedOut(t *testing.T) {
	arts := []Artifact{skillArtifact(t, lintSkill), skillArtifact(t, "lint the code.")}
	sk := LoadSkips(fakeEnv(t))
	sk.Set([]string{KeyOf(arts[0])}, true)

	got, skipped := Unskipped(arts, sk)

	if skipped != 1 || len(got) != 1 || !slices.Equal([]string{KeyOf(got[0])}, []string{KeyOf(arts[1])}) {
		t.Errorf("Unskipped = %d kept, %d skipped; want the second kept and one skipped", len(got), skipped)
	}
}
