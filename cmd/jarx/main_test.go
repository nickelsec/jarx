package main

import (
	"bytes"
	"runtime/debug"
	"strings"
	"testing"
)

func TestRunVersionPrintsVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"version"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	want := "jarx " + resolveVersion() + "\n"
	if got := stdout.String(); got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunNoArgsPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(nil, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage: jarx") {
		t.Errorf("stderr = %q, want usage", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunUnknownCommandNamesItAndPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"frobnicate"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unknown command "frobnicate"`) {
		t.Errorf("stderr = %q, want it to name the command", stderr.String())
	}
	if !strings.Contains(stderr.String(), "usage: jarx") {
		t.Errorf("stderr = %q, want usage", stderr.String())
	}
}

func TestVersionFrom(t *testing.T) {
	tests := []struct {
		name    string
		ldflags string
		info    *debug.BuildInfo
		want    string
	}{
		{
			name:    "ldflags wins over build info",
			ldflags: "v1.2.3",
			info:    &debug.BuildInfo{Main: debug.Module{Version: "v0.9.0"}},
			want:    "v1.2.3",
		},
		{
			name: "module version from go install",
			info: &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}},
			want: "v0.1.0",
		},
		{
			name: "devel build falls back to dev",
			info: &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			want: "dev",
		},
		{
			name: "empty module version falls back to dev",
			info: &debug.BuildInfo{},
			want: "dev",
		},
		{
			name: "no build info falls back to dev",
			want: "dev",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionFrom(tt.ldflags, tt.info); got != tt.want {
				t.Errorf("versionFrom() = %q, want %q", got, tt.want)
			}
		})
	}
}
