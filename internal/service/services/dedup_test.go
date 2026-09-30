package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sentinelgo/internal/models"
)

// resetSvcsDedupState clears the package-level dedup state before/after a test
// so tests don't leak state into each other (these all run sequentially, never
// with t.Parallel(), since the state is package-global).
func resetSvcsDedupState(t *testing.T) {
	t.Helper()
	prevInterval := svcsForceResendInterval
	svcsInProgress.Store(false)
	svcsStateMu.Lock()
	svcsLastHash = ""
	svcsLastForce = time.Time{}
	svcsStateMu.Unlock()
	t.Cleanup(func() {
		svcsInProgress.Store(false)
		svcsStateMu.Lock()
		svcsLastHash = ""
		svcsLastForce = time.Time{}
		svcsStateMu.Unlock()
		svcsForceResendInterval = prevInterval
	})
}

func dedupMockServices() []models.ServiceInfo {
	return []models.ServiceInfo{
		{Name: "sshd", Status: "running", StartType: "automatic", Source: "systemd"},
	}
}

func svcsCountingServer(t *testing.T) (srv *httptest.Server, hits *int) {
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

func TestSvcsSendByRPCIfChanged_FirstCallSends(t *testing.T) {
	resetSvcsDedupState(t)
	srv, hits := svcsCountingServer(t)
	svc := NewServicesService()
	svc.SetSupabaseURL(srv.URL)

	skipped, err := svc.SendByRPCIfChanged(context.Background(), "dev-1", dedupMockServices(), nil)
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

func TestSvcsSendByRPCIfChanged_UnchangedListSkipsSecondSend(t *testing.T) {
	resetSvcsDedupState(t)
	srv, hits := svcsCountingServer(t)
	svc := NewServicesService()
	svc.SetSupabaseURL(srv.URL)

	list := dedupMockServices()
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

func TestSvcsSendByRPCIfChanged_ChangedListSendsAgain(t *testing.T) {
	resetSvcsDedupState(t)
	srv, hits := svcsCountingServer(t)
	svc := NewServicesService()
	svc.SetSupabaseURL(srv.URL)

	if _, err := svc.SendByRPCIfChanged(context.Background(), "dev-1", dedupMockServices(), nil); err != nil {
		t.Fatalf("first call: %v", err)
	}
	changed := append(dedupMockServices(), models.ServiceInfo{Name: "cron", Status: "running", Source: "systemd"})
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

func TestSvcsSendByRPCIfChanged_IgnoresVolatileFields(t *testing.T) {
	resetSvcsDedupState(t)
	srv, hits := svcsCountingServer(t)
	svc := NewServicesService()
	svc.SetSupabaseURL(srv.URL)

	list := dedupMockServices()
	if _, err := svc.SendByRPCIfChanged(context.Background(), "dev-1", list, nil); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Only PID/FirstSeenAt/UpdatedAt changed — hashServiceList excludes these,
	// so this must still be treated as "unchanged" and skipped.
	volatileOnly := dedupMockServices()
	volatileOnly[0].PID = 4242
	volatileOnly[0].FirstSeenAt = "2024-01-01T00:00:00Z"
	volatileOnly[0].UpdatedAt = "2024-06-01T00:00:00Z"

	skipped, err := svc.SendByRPCIfChanged(context.Background(), "dev-1", volatileOnly, nil)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !skipped {
		t.Error("skipped = false, want true when only volatile fields changed")
	}
	if *hits != 1 {
		t.Errorf("hits = %d, want 1 (volatile-only change must not trigger a resend)", *hits)
	}
}

func TestSvcsSendByRPCIfChanged_ForcedResendAfterInterval(t *testing.T) {
	resetSvcsDedupState(t)
	svcsForceResendInterval = 10 * time.Millisecond
	srv, hits := svcsCountingServer(t)
	svc := NewServicesService()
	svc.SetSupabaseURL(srv.URL)

	list := dedupMockServices()
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

func TestSvcsSendByRPCIfChanged_ConcurrentCallIsSkipped(t *testing.T) {
	resetSvcsDedupState(t)

	started := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"msg_id":1}`))
	}))
	defer srv.Close()

	svc := NewServicesService()
	svc.SetSupabaseURL(srv.URL)

	done := make(chan error, 1)
	go func() {
		_, err := svc.SendByRPCIfChanged(context.Background(), "dev-1", dedupMockServices(), nil)
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the first call to reach the server")
	}

	skipped, err := svc.SendByRPCIfChanged(context.Background(), "dev-1", dedupMockServices(), nil)
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
