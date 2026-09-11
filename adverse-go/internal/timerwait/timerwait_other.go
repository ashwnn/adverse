//go:build !windows

package timerwait

import (
	"context"
	"time"
)

func sleepPlatform(ctx context.Context, d time.Duration) bool {
	return fallbackSleep(ctx, d)
}
