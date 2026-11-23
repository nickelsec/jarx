package platform

import "testing"

func TestLookupRealReadsOneVariableWithoutAHome(t *testing.T) {
	t.Setenv("JARX_LOOKUP_REAL_TEST", "1")

	if v, ok := LookupReal("JARX_LOOKUP_REAL_TEST"); !ok || v != "1" {
		t.Errorf("LookupReal = %q, %v; want 1", v, ok)
	}
	if _, ok := LookupReal("JARX_LOOKUP_REAL_NOT_SET"); ok {
		t.Error("an unset variable was found")
	}
}
