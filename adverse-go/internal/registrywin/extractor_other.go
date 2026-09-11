//go:build !windows

package registrywin

import (
	"fmt"
	"runtime"
)

// extractReal is not supported on non-Windows platforms.
func (e *Extractor) extractReal(hiveName string) ([]byte, error) {
	return nil, fmt.Errorf("real extraction not supported on %s (requires Windows)", runtime.GOOS)
}
