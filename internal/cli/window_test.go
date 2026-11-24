package cli

import (
	"testing"
	"time"

	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
)

func TestAFakeHomesWindowEndsAtItsNewestSession(t *testing.T) {
	env, err := platform.FromHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old := time.Date(2020, 1, 2, 3, 0, 0, 0, time.UTC)
	projects := []model.Project{{Sessions: []model.Session{
		{LastUnix: old.Add(-48 * time.Hour).Unix()}, {LastUnix: old.Unix()}, {},
	}}}

	if got := windowEnd(env, projects); !got.Equal(old) {
		t.Errorf("windowEnd = %s, want %s: a fake home is a snapshot, so its window ends at its newest session", got, old)
	}
}

func TestAFakeHomeWithNoDatesUsesNow(t *testing.T) {
	env, err := platform.FromHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()

	if got := windowEnd(env, []model.Project{{Sessions: []model.Session{{}}}}); got.Before(before) {
		t.Errorf("windowEnd = %s, want now", got)
	}
}
