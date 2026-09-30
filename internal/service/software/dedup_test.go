package software

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// resetSwDedupState clears the package-level dedup state before/after a test so
// tests don't leak state into each other (SendByRPCIfChanged is not designed to
// be exercised in parallel across tests — these all run sequentially).
func resetSwDedupState(t *testing.T) {
	t.Helper()
	prevInterval := swForceResendInterval
	swInProgress.Store(false)
	swStateMu.Lock()
	swLastHash = ""
	swLastForce = time.Time{}
	swStateMu.Unlock()
	t.Cleanup(func() {
		swInProgress.Store(false)
		swStateMu.Lock()
		swLastHash = ""
		swLastForce = time.Time{}
		swStateMu.Unlock()
		swForceResendInterval = prevInterval
	})
}

// dedupMockSoftware returns a small deterministic software list for dedup
// tests. Defined locally (rather than reusing software_test.go's mockSoftware)
// because this file is white-box (package software) to reach unexported state,
// while software_test.go is black-box (package software_test).
func dedupMockSoftware() []SoftwareInfo {
	return []SoftwareInfo{
		{Name: "test-package", Source: "deb_packages", Type: "deb_packages", InstalledVersion: "1.0.0"},
	}
}

func countingServer(t *testing.T) (srv *httptest.Server, hits *int) {
	t.Helper()
	hits = new(int)
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"msg_id":1}`))
	}))
	t.Cleanup(srv.Close)
	return srv, hits
}

func TestSendByRPCIfChanged_FirstCallSends(t *testing.T) {
	resetSwDedupState(t)
	srv, hits := countingServer(t)
	svc := NewSoftwareService()
	svc.SetSupabaseURL(srv.URL)

	skipped, err := svc.SendByRPCIfChanged(context.Background(), "dev-1", dedupMockSoftware(), nil)
	if err != nil {
		t.Fatalf("SendByRPCIfChanged: %v", err)
	}
	if skipped {
		t.Error("skipped = true, want false on first call")
	}
	if *hits != 1 {
		t.Errorf("hits = %d, want 1", *hits)
	}
}

func TestSendByRPCIfChanged_UnchangedListSkipsSecondSend(t *testing.T) {
	resetSwDedupState(t)
	srv, hits := countingServer(t)
	svc := NewSoftwareService()
	svc.SetSupabaseURL(srv.URL)

	list := dedupMockSoftware()
	if _, err := svc.SendByRPCIfChanged(context.Background(), "dev-1", list, nil); err != nil {
		t.Fatalf("first call: %v", err)
	}
	skipped, err := svc.SendByRPCIfChanged(context.Background(), "dev-1", list, nil)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !skipped {
		t.Error("skipped = false, want true for an unchanged list")
	}
	if *hits != 1 {
		t.Errorf("hits = %d, want 1 (second call should not hit the server)", *hits)
	}
}

func TestSendByRPCIfChanged_ChangedListSendsAgain(t *testing.T) {
	resetSwDedupState(t)
	srv, hits := countingServer(t)
	svc := NewSoftwareService()
	svc.SetSupabaseURL(srv.URL)

	if _, err := svc.SendByRPCIfChanged(context.Background(), "dev-1", dedupMockSoftware(), nil); err != nil {
		t.Fatalf("first call: %v", err)
	}
	changed := append(dedupMockSoftware(), SoftwareInfo{Name: "new-package", Source: "deb_packages", Type: "deb_packages"})
	skipped, err := svc.SendByRPCIfChanged(context.Background(), "dev-1", changed, nil)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if skipped {
		t.Error("skipped = true, want false for a changed list")
	}
	if *hits != 2 {
		t.Errorf("hits = %d, want 2", *hits)
	}
}

func TestSendByRPCIfChanged_ForcedResendAfterInterval(t *testing.T) {
	resetSwDedupState(t)
	swForceResendInterval = 10 * time.Millisecond
	srv, hits := countingServer(t)
	svc := NewSoftwareService()
	svc.SetSupabaseURL(srv.URL)

	list := dedupMockSoftware()
	if _, err := svc.SendByRPCIfChanged(context.Background(), "dev-1", list, nil); err != nil {
		t.Fatalf("first call: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	skipped, err := svc.SendByRPCIfChanged(context.Background(), "dev-1", list, nil)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if skipped {
		t.Error("skipped = true, want false once the force-resend interval has elapsed")
	}
	if *hits != 2 {
		t.Errorf("hits = %d, want 2 (forced resend after interval)", *hits)
	}
}

func TestSendByRPCIfChanged_ConcurrentCallIsSkipped(t *testing.T) {
	resetSwDedupState(t)

	started := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"msg_id":1}`))
	}))
	defer srv.Close()

	svc := NewSoftwareService()
	svc.SetSupabaseURL(srv.URL)

	done := make(chan error, 1)
	go func() {
		_, err := svc.SendByRPCIfChanged(context.Background(), "dev-1", dedupMockSoftware(), nil)
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the first call to reach the server")
	}

	// The first call is now in-flight (swInProgress is true); a concurrent call
	// must be dropped immediately rather than blocking or double-sending.
	skipped, err := svc.SendByRPCIfChanged(context.Background(), "dev-1", dedupMockSoftware(), nil)
	if err != nil {
		t.Fatalf("concurrent call: %v", err)
	}
	if !skipped {
		t.Error("skipped = false, want true for a call concurrent with an in-flight send")
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first call returned an error: %v", err)
	}
}
