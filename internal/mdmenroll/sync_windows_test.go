package mdmenroll

import (
	"context"
	"strings"
	"testing"
)

// Nothing but a GUID reaches deviceenroller's or schtasks' command line.
func TestStartSession_RejectsBadIDs(t *testing.T) {
	err := startSession(context.Background(), `x" & calc & "`)
	if err == nil || !strings.Contains(err.Error(), "unexpected enrollment ID") {
		t.Errorf("err = %v", err)
	}
}
