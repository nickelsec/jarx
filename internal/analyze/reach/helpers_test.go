package reach

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/redact"
)

func writeFile(path, body string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// catalogScrubber is the scrubber the scan uses, with every secret pattern.
func catalogScrubber() (*redact.Scrubber, error) {
	ps, err := catalog.Secrets()
	if err != nil {
		return nil, fmt.Errorf("secret patterns: %w", err)
	}
	s, err := redact.New(ps, nil)
	if err != nil {
		return nil, fmt.Errorf("scrubber: %w", err)
	}
	return s, nil
}
