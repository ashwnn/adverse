//go:build !windows

package hygiene

import (
	"sync"
	"testing"
)

func TestApplySafeAndIdempotent(t *testing.T) {
	for i := 0; i < 5; i++ {
		Apply()
	}
}

func TestApplyConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Apply()
		}()
	}
	wg.Wait()
}
