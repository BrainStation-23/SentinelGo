package migrate

import (
	"context"
	"time"
)

// contextWithTimeout is a thin helper so the platform-specific migration code
// can bound a subprocess without importing context directly in several places.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
