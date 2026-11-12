package native

import (
	"context"
	"errors"
	"strings"
	"testing"

	"sentinelgo/internal/adminpassword"
	"sentinelgo/internal/taskstore"
)

func runAdminPasswordRotate(t *testing.T, f AdminPasswordRotator) (string, error) {
	t.Helper()
	SetAdminPasswordRotator(f)
	t.Cleanup(func() { SetAdminPasswordRotator(nil) })
	h := Find(adminpassword.TaskRotate)
	if h == nil {
		t.Fatal("admin-password-rotate is not registered")
	}
	return h.Run(context.Background(), nil, taskstore.Task{})
}

func TestAdminPasswordRotate_NotRunning(t *testing.T) {
	if _, err := runAdminPasswordRotate(t, nil); !errors.Is(err, errAdminPasswordOff) {
		t.Errorf("err = %v, want errAdminPasswordOff", err)
	}
}

func TestAdminPasswordRotate_Results(t *testing.T) {
	cases := []struct {
		res     adminpassword.TaskResult
		wantErr bool
		want    string
	}{
		{adminpassword.TaskResult{State: "active", Rotated: true, RotationID: "r1"}, false, `"rotation_id":"r1"`},
		{adminpassword.TaskResult{State: "active"}, false, "no rotation due"},
		{adminpassword.TaskResult{State: "unavailable"}, false, "doesn't offer"},
		{adminpassword.TaskResult{State: "managed_elsewhere"}, false, "managed_elsewhere"},
		{adminpassword.TaskResult{State: "error", Rotated: true, ErrorCode: "confirm_failed"}, false, "retried"},
		{adminpassword.TaskResult{State: "error", ErrorCode: "escrow_failed"}, true, "escrow_failed"},
	}
	for _, c := range cases {
		out, err := runAdminPasswordRotate(t, func(context.Context) (adminpassword.TaskResult, error) { return c.res, nil })
		got := out
		if err != nil {
			got = err.Error()
		}
		if (err != nil) != c.wantErr || !strings.Contains(got, c.want) {
			t.Errorf("%+v: Run = %q, %v; want %q (error %v)", c.res, out, err, c.want, c.wantErr)
		}
	}
}

func TestAdminPasswordRotate_PollError(t *testing.T) {
	boom := errors.New("offline")
	if _, err := runAdminPasswordRotate(t, func(context.Context) (adminpassword.TaskResult, error) {
		return adminpassword.TaskResult{}, boom
	}); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
}
