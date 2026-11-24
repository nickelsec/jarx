package llm

import (
	"testing"

	"github.com/nickelsec/jarx/internal/finding"
)

func TestRulesPassTheRegistryChecks(t *testing.T) {
	if _, err := finding.NewRegistry(Rules()...); err != nil {
		t.Errorf("NewRegistry(llm rules) error = %v", err)
	}
}
