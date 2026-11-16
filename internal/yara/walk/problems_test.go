package walk

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"testing"

	"sentinelgo/internal/yara"
)

// A folder that can't be listed is a list_error problem with the OS error
// text (not the path); a privacy refusal is a tcc_denied skip problem.
func TestWalk_ReportsProblems(t *testing.T) {
	oldRead, oldLstat := readDir, lstat
	t.Cleanup(func() { readDir, lstat = oldRead, oldLstat })
	lstat = func(string) (fs.FileInfo, error) { return fakeInfo{fakeEntry{name: "a", dir: true}}, nil }
	readDir = func(dir string) ([]os.DirEntry, error) {
		switch dir {
		case "/Users/a":
			return []os.DirEntry{fakeEntry{name: "Downloads", dir: true}, fakeEntry{name: "proj", dir: true}}, nil
		case "/Users/a/Downloads":
			return nil, &fs.PathError{Op: "open", Path: dir, Err: syscall.EPERM}
		case "/Users/a/proj":
			return nil, &fs.PathError{Op: "open", Path: dir, Err: syscall.EIO}
		}
		return nil, fs.ErrNotExist
	}
	var got []Problem
	st, err := Walk(context.Background(), Options{GOOS: "darwin", Roots: []string{"/Users/a"},
		Problem: func(p Problem) { got = append(got, p) }}, func(File) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if st.Errors != 1 || st.ErrorsBy[yara.ErrList] != 1 {
		t.Fatalf("stats %+v", st)
	}
	want := []Problem{
		{Path: "/Users/a/Downloads", Reason: SkipTCCDenied},
		{Path: "/Users/a/proj", Reason: yara.ErrList, Detail: syscall.EIO.Error(), Error: true},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("problems %+v, want %+v", got, want)
	}
}

func TestErrorReasonAndDetail(t *testing.T) {
	denied := &fs.PathError{Op: "open", Path: "/secret/path.txt", Err: fs.ErrPermission}
	if r := ErrorReason(denied); r != yara.ErrAccessDenied {
		t.Errorf("permission: %q", r)
	}
	if r := ErrorReason(errors.New("boom")); r != yara.ErrRead {
		t.Errorf("other: %q", r)
	}
	if d := ErrorDetail(denied); d != fs.ErrPermission.Error() {
		t.Errorf("detail %q leaks more than the OS error", d)
	}
	if ErrorDetail(nil) != "" {
		t.Error("detail of nil")
	}
}

// The throttle says which limit stopped the scan.
func TestThrottle_RecordsLimit(t *testing.T) {
	th, _ := newTestThrottle(yara.Limits{MaxFilesPerScan: 1}, nil, nil)
	_ = th.Wait(context.Background())
	if err := th.Wait(context.Background()); !errors.Is(err, ErrLimitReached) || th.Limit != yara.EndFileLimit {
		t.Fatalf("err %v, limit %q", err, th.Limit)
	}
}
