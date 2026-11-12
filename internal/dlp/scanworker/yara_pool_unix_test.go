//go:build linux || darwin

package scanworker

import "testing"

func yaraTestPool(t *testing.T) *Pool {
	t.Helper()
	return newPool(t, "serve", 1)
}
