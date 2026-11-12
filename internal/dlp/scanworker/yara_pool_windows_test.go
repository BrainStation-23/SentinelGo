package scanworker

import "testing"

func yaraTestPool(t *testing.T) *Pool {
	t.Helper()
	return newTestPool(t, "serve")
}
