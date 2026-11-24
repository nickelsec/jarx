package catalog

import (
	"slices"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
)

func ids(as []Advisory) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.ID)
	}
	return out
}

func TestEveryAdvisoryRowParses(t *testing.T) {
	for _, a := range []model.Agent{model.AgentClaude, model.AgentCodex} {
		as := Advisories(a)
		if len(as) == 0 {
			t.Errorf("Advisories(%s) is empty", a)
		}
		for _, adv := range as {
			if adv.ID == "" || adv.Fixed == "" || adv.Summary == "" || len(adv.affected) == 0 {
				t.Errorf("advisory %+v is missing a field", adv)
			}
		}
	}
	if got := AdvisoriesStamp(); got == "" {
		t.Error("AdvisoriesStamp() is empty, want the date the data was checked")
	}
}

func TestAnAffectedVersionMatchesItsAdvisories(t *testing.T) {
	got := ids(AffectedBy(model.AgentClaude, "2.1.120"))

	for _, want := range []string{"GHSA-5j29-h97v-84ch", "GHSA-fg94-h982-f3mm", "GHSA-7835-87q9-rgvv", "GHSA-4vp2-6q8c-pvq2", "GHSA-gfvf-j8jh-jxxw"} {
		if !slices.Contains(got, want) {
			t.Errorf("AffectedBy(2.1.120) = %q, want it to hold %s", got, want)
		}
	}
	if slices.Contains(got, "GHSA-q5hj-mxqh-vv77") {
		t.Errorf("AffectedBy(2.1.120) holds GHSA-q5hj-mxqh-vv77, fixed in 2.1.84")
	}
}

func TestTheFixedVersionIsntAffected(t *testing.T) {
	if got := ids(AffectedBy(model.AgentClaude, "2.1.251")); slices.Contains(got, "GHSA-5xjx-9qx6-jcrv") {
		t.Errorf("AffectedBy(2.1.251) = %q, want no GHSA-5xjx-9qx6-jcrv: 2.1.251 is the fix", got)
	}
	if got := ids(AffectedBy(model.AgentClaude, "2.1.250")); !slices.Contains(got, "GHSA-5xjx-9qx6-jcrv") {
		t.Errorf("AffectedBy(2.1.250) = %q, want GHSA-5xjx-9qx6-jcrv", got)
	}
}

func TestRangeBoundsHoldBothWays(t *testing.T) {
	for _, tc := range []struct {
		agent    model.Agent
		version  string
		id       string
		affected bool
	}{
		{model.AgentCodex, "0.38.0", "GHSA-w5fx-fh39-j5rw", true},    // <= is inclusive
		{model.AgentCodex, "0.39.0", "GHSA-w5fx-fh39-j5rw", false},   // the fix
		{model.AgentCodex, "0.1.9", "GHSA-w5fx-fh39-j5rw", false},    // before the range
		{model.AgentClaude, "0.2.116", "GHSA-9f65-56v6-gxw7", false}, // > is exclusive
		{model.AgentClaude, "0.2.117", "GHSA-9f65-56v6-gxw7", true},
		{model.AgentClaude, "2.1.63", "GHSA-q5hj-mxqh-vv77", true}, // >= is inclusive
		{model.AgentClaude, "2.1.62", "GHSA-q5hj-mxqh-vv77", false},
	} {
		if got := slices.Contains(ids(AffectedBy(tc.agent, tc.version)), tc.id); got != tc.affected {
			t.Errorf("%s %s affected by %s = %v, want %v", tc.agent, tc.version, tc.id, got, tc.affected)
		}
	}
}

func TestAnUnreadableVersionMatchesNothing(t *testing.T) {
	for _, v := range []string{"", "latest", "2.1"} {
		if got := AffectedBy(model.AgentClaude, v); len(got) != 0 {
			t.Errorf("AffectedBy(%q) = %q, want none", v, ids(got))
		}
	}
}

func TestCompareVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{{"2.1.120", "2.1.200", -1}, {"2.1.200", "2.1.120", 1}, {"0.38.0", "0.38.0", 0}, {"2.10.0", "2.9.0", 1}} {
		if got, ok := CompareVersions(tc.a, tc.b); !ok || got != tc.want {
			t.Errorf("CompareVersions(%s, %s) = %d, %v, want %d", tc.a, tc.b, got, ok, tc.want)
		}
	}
	if _, ok := CompareVersions("latest", "2.1.0"); ok {
		t.Error("CompareVersions(latest, ...) ok, want not comparable")
	}
}
