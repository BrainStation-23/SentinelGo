package patches

import "testing"

func TestParseWindowsPending_Array(t *testing.T) {
	const sample = `[{"ID":"KB5001234","Description":"2026-08 Cumulative Update","Category":"quality"}]`
	rows, err := parseWindowsPending(sample)
	if err != nil {
		t.Fatalf("parseWindowsPending: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "KB5001234" {
		t.Fatalf("got %+v", rows)
	}
}

func TestParseWindowsPending_SingleObject(t *testing.T) {
	const sample = `{"ID":"KB5001234","Description":"Update","Category":"quality"}`
	rows, err := parseWindowsPending(sample)
	if err != nil {
		t.Fatalf("parseWindowsPending: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %+v", rows)
	}
}

func TestParseWindowsPending_Empty(t *testing.T) {
	rows, err := parseWindowsPending("")
	if err != nil || rows != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", rows, err)
	}
}

func TestParseDpkgLog(t *testing.T) {
	const sample = `2026-08-15 14:23:01 startup archives unpack
2026-08-15 14:23:05 status half-installed vim:amd64 2:8.2.0000-1
2026-08-15 14:23:07 status installed vim:amd64 2:8.2.0000-1
2026-08-15 14:24:00 status installed curl:amd64 7.81.0-1ubuntu1.15
`
	got := parseDpkgLog(sample)
	if len(got) != 2 {
		t.Fatalf("got %d updates, want 2 (only 'status installed' lines): %+v", len(got), got)
	}
	if got[0].ID != "vim" || got[0].InstalledOn != "2026-08-15T14:23:07" {
		t.Errorf("update 0 = %+v", got[0])
	}
	if got[1].ID != "curl" {
		t.Errorf("update 1 = %+v", got[1])
	}
}

func TestParseRpmLast(t *testing.T) {
	const sample = `kernel-5.14.0-284.11.1.el9.x86_64    Wed 20 Aug 2026 03:15:00 PM +06
bash-5.1.8-6.el9.x86_64    Tue 19 Aug 2026 10:00:00 AM +06
`
	got := parseRpmLast(sample)
	if len(got) != 2 {
		t.Fatalf("got %d updates, want 2: %+v", len(got), got)
	}
	if got[0].ID != "kernel-5.14.0-284.11.1.el9.x86_64" {
		t.Errorf("update 0 ID = %q", got[0].ID)
	}
	if got[0].InstalledOn != "Wed 20 Aug 2026 03:15:00 PM +06" {
		t.Errorf("update 0 date = %q", got[0].InstalledOn)
	}
}

func TestParseAptUpgradable(t *testing.T) {
	const sample = `Listing... Done
firefox/stable 118.0-1 amd64 [upgradable from: 117.0-1]
curl/stable 7.81.0-1ubuntu1.16 amd64 [upgradable from: 7.81.0-1ubuntu1.15]
`
	got := parseAptUpgradable(sample)
	if len(got) != 2 {
		t.Fatalf("got %d updates, want 2 (Listing... line must be skipped): %+v", len(got), got)
	}
	if got[0].ID != "firefox" || got[0].Status != "pending" {
		t.Errorf("update 0 = %+v", got[0])
	}
}

func TestParseCheckUpdate(t *testing.T) {
	const sample = `Last metadata expiration check: 0:12:34 ago on Thu 20 Aug 2026.

kernel.x86_64                  5.14.0-284.11.1.el9         baseos
bash.x86_64                    5.1.8-6.el9                 baseos
`
	got := parseCheckUpdate(sample)
	if len(got) != 2 {
		t.Fatalf("got %d updates, want 2 (header line must be skipped): %+v", len(got), got)
	}
	if got[0].ID != "kernel.x86_64" || got[0].Status != "pending" {
		t.Errorf("update 0 = %+v", got[0])
	}
}

func TestParseSoftwareupdateHistory(t *testing.T) {
	const sample = `Software Update Tool

Installed Updates:
* Safari17.6SonomaAuto
	2024-07-29, 13:42:11
* macOS Sonoma 14.6
	2024-07-29, 14:02:33
`
	got := parseSoftwareupdateHistory(sample)
	if len(got) != 2 {
		t.Fatalf("got %d updates, want 2: %+v", len(got), got)
	}
	if got[0].ID != "Safari17.6SonomaAuto" || got[0].InstalledOn != "2024-07-29, 13:42:11" {
		t.Errorf("update 0 = %+v", got[0])
	}
	if got[1].ID != "macOS Sonoma 14.6" {
		t.Errorf("update 1 = %+v", got[1])
	}
}

func TestParseSoftwareupdateList(t *testing.T) {
	const sample = `Software Update Tool

Finding available software
* Label: macOS Sonoma 14.6.1-23B81
	Title: macOS Sonoma, Version: 14.6.1, Size: 3339999KiB, Recommended: YES,
`
	got := parseSoftwareupdateList(sample)
	if len(got) != 1 {
		t.Fatalf("got %d updates, want 1: %+v", len(got), got)
	}
	if got[0].ID != "macOS Sonoma 14.6.1-23B81" || got[0].Status != "pending" {
		t.Errorf("update 0 = %+v", got[0])
	}
}
