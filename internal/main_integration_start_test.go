package internal

// White-box tests for the MainIntegration startup flow and the store-backed
// task handlers. The package-level hooks (startupUpdateCheck, defaultTasks,
// collectServices, collectSoftware) are swapped so every path runs hermetically:
// no real update check or binary replacement, no OS service/software scans, and
// the only "backend" is an in-process httptest server on loopback.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	"sentinelgo/internal/scheduler"
	authsvc "sentinelgo/internal/service/auth"
	servicessvc "sentinelgo/internal/service/services"
	swsvc "sentinelgo/internal/service/software"
	"sentinelgo/internal/updater"
)

// ── helpers ─────────────────────────────────────────────────────────────────

// testJWT returns an unsigned JWT whose exp claim is now+ttl. Only the expiry is
// read by the agent (the backend verifies signatures).
func testJWT(ttl time.Duration) string {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := enc.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(ttl).Unix())))
	return header + "." + payload + ".sig"
}

// fakeBackend is a loopback Supabase stand-in. agent-login answers with
// loginStatus (200 => a fresh token pair); every other path answers 200 "[]".
type fakeBackend struct {
	srv         *httptest.Server
	loginStatus int
	logins      atomic.Int32
}

func newFakeBackend(t *testing.T, loginStatus int) *fakeBackend {
	t.Helper()
	fb := &fakeBackend{loginStatus: loginStatus}
	fb.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/functions/v1/agent-login") {
			fb.logins.Add(1)
			if fb.loginStatus != http.StatusOK {
				w.WriteHeader(fb.loginStatus)
				_, _ = w.Write([]byte(`{"error":"rejected"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  testJWT(time.Hour),
				"refresh_token": "fresh-refresh",
				"expires_in":    3600,
			})
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(fb.srv.Close)
	return fb
}

// startTestConfig returns a config that passes ValidateConfiguration, rooted at
// a temp dir and pointed at baseURL (a loopback httptest server).
func startTestConfig(t *testing.T, baseURL string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		Path:        filepath.Join(dir, "config.json"),
		DeviceID:    "test-device-id",
		AgentID:     "test-agent-id",
		AgentSecret: "test-agent-secret",
		SupabaseURL: baseURL,
		SupabaseKey: "test-key",
		TaskDBPath:  filepath.Join(dir, "tasks.sqlite"),
	}
}

// stubDefaultTasks replaces the default scheduler task set with the real task
// names/intervals but no-op handlers, so scheduler.Start's initial run does no
// network or OS collection.
func stubDefaultTasks(t *testing.T) {
	t.Helper()
	orig := defaultTasks
	defaultTasks = func() []*scheduler.Task {
		tasks := scheduler.CreateDefaultTasks()
		for _, task := range tasks {
			task.Handler = func(context.Context, *config.Config, *authsvc.Service) error { return nil }
		}
		return tasks
	}
	t.Cleanup(func() { defaultTasks = orig })
}

// resetUpdaterRetrier undoes initAuth's global updater.SetAuthRetrier.
func resetUpdaterRetrier(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { updater.SetAuthRetrier(nil) })
}

// logWatcher captures the standard logger's output. The original output is
// restored on cleanup.
type logWatcher struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func watchLog(t *testing.T) *logWatcher {
	t.Helper()
	w := &logWatcher{}
	orig := log.Writer()
	log.SetOutput(w)
	t.Cleanup(func() { log.SetOutput(orig) })
	return w
}

func (w *logWatcher) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *logWatcher) contains(s string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.Contains(w.buf.String(), s)
}

// rejectedAuthSvc returns an auth service whose credentials were rejected by
// agent-login, so Healthy() reports false.
func rejectedAuthSvc(t *testing.T) *authsvc.Service {
	t.Helper()
	fb := newFakeBackend(t, http.StatusUnauthorized)
	cfg := startTestConfig(t, fb.srv.URL)
	svc := authsvc.NewService(fb.srv.URL, cfg.SupabaseKey)
	if err := svc.Recover(context.Background(), cfg); err == nil {
		t.Fatal("Recover against a 401 agent-login should fail")
	}
	if svc.Healthy() {
		t.Fatal("auth service should be unhealthy after a rejected agent-login")
	}
	return svc
}

// ── Start ───────────────────────────────────────────────────────────────────

// TestStart_FullFlow drives Start through every enabled component (startup
// update check, agent-login, scheduled tasks, audit logging, task manager,
// scheduler) and then Stop, all against a loopback fake backend.
func TestStart_FullFlow(t *testing.T) {
	stubDefaultTasks(t)
	resetUpdaterRetrier(t)

	updateChecked := make(chan struct{})
	origCheck := startupUpdateCheck
	startupUpdateCheck = func(context.Context, *config.Config) error {
		close(updateChecked)
		return errors.New("stub update check failure")
	}
	t.Cleanup(func() { startupUpdateCheck = origCheck })

	fb := newFakeBackend(t, http.StatusOK)
	cfg := startTestConfig(t, fb.srv.URL)
	cfg.AutoUpdate = true
	cfg.AuditLogsEnabled = true
	cfg.EnableTaskPolling = true
	cfg.SoftwareSyncEnabled = true
	cfg.ServicesSyncEnabled = false

	mi := NewMainIntegration(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mi.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	select {
	case <-updateChecked:
	case <-time.After(10 * time.Second):
		t.Fatal("startup update check was not invoked")
	}
	if fb.logins.Load() != 1 {
		t.Errorf("agent-login calls = %d, want 1 (no stored token)", fb.logins.Load())
	}
	if cfg.GetAccessToken() == "" {
		t.Error("Start should have stored the agent-login access token")
	}
	if mi.authSvc == nil || mi.loggingService == nil || mi.taskManager == nil {
		t.Fatalf("components not started: auth=%v logging=%v tasks=%v",
			mi.authSvc != nil, mi.loggingService != nil, mi.taskManager != nil)
	}
	if mi.servicesStore == nil || mi.softwareStore == nil {
		t.Error("Start should have opened the services and software stores")
	}

	// Stop cancels and joins the TaskManager goroutine itself (#113); ctx is
	// deliberately still live here.
	if err := mi.Stop(); err != nil {
		t.Errorf("Stop() error: %v", err)
	}

	status := mi.GetStatus()
	for _, key := range []string{"scheduler", "authentication", "logging"} {
		if _, ok := status[key]; !ok {
			t.Errorf("GetStatus() missing %q", key)
		}
	}
	sched, ok := status["scheduler"].(map[string]scheduler.TaskStatus)
	if !ok {
		t.Fatalf("scheduler status type = %T", status["scheduler"])
	}
	for _, name := range []string{"token-refresh", "auto-update", "agent-info-update", "software-sync", "services-collect"} {
		if _, ok := sched[name]; !ok {
			t.Errorf("scheduler missing task %q", name)
		}
	}
}

func TestStart_ConfigValidationFails(t *testing.T) {
	cfg := startTestConfig(t, "") // supabase_url is required
	mi := NewMainIntegration(cfg)

	err := mi.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "configuration validation failed") {
		t.Fatalf("Start() error = %v, want configuration validation failure", err)
	}
	if mi.authSvc != nil {
		t.Error("auth must not be initialised when config validation fails")
	}
}

func TestStart_ConfigureScheduledTasksFails(t *testing.T) {
	resetUpdaterRetrier(t)
	origTasks := defaultTasks
	// A default task named like the appended services task makes AddTask fail.
	defaultTasks = func() []*scheduler.Task {
		return []*scheduler.Task{{
			Name:    "services-collect",
			Enabled: false,
			Handler: func(context.Context, *config.Config, *authsvc.Service) error { return nil },
		}}
	}
	t.Cleanup(func() { defaultTasks = origTasks })

	fb := newFakeBackend(t, http.StatusOK)
	mi := NewMainIntegration(startTestConfig(t, fb.srv.URL))

	err := mi.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "failed to add task services-collect") {
		t.Fatalf("Start() error = %v, want duplicate task failure", err)
	}
	_ = mi.Stop()
}

func TestStart_LoggingServiceFails(t *testing.T) {
	stubDefaultTasks(t)
	resetUpdaterRetrier(t)

	// Rejected login: nothing to persist under the unwritable config path.
	fb := newFakeBackend(t, http.StatusUnauthorized)
	cfg := startTestConfig(t, fb.srv.URL)
	// Root the config under a regular file so neither the services store nor
	// the audit-log checkpoint dir can be created.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Path = filepath.Join(blocker, "config.json")
	cfg.AuditLogsEnabled = true

	mi := NewMainIntegration(cfg)
	err := mi.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "failed to create logging service") {
		t.Fatalf("Start() error = %v, want logging service creation failure", err)
	}
	if mi.servicesStore != nil {
		t.Error("services store should not open under a non-directory path")
	}
	_ = mi.Stop()
}

// ── maybeStartupUpdateCheck ─────────────────────────────────────────────────

func TestMaybeStartupUpdateCheck_DisabledDoesNotCheck(t *testing.T) {
	origCheck := startupUpdateCheck
	startupUpdateCheck = func(context.Context, *config.Config) error {
		t.Error("update check must not run when AutoUpdate is false")
		return nil
	}
	t.Cleanup(func() { startupUpdateCheck = origCheck })

	mi := &MainIntegration{cfg: &config.Config{AutoUpdate: false}}
	mi.maybeStartupUpdateCheck(context.Background())
}

func TestMaybeStartupUpdateCheck_SuccessIsQuiet(t *testing.T) {
	done := make(chan struct{})
	origCheck := startupUpdateCheck
	startupUpdateCheck = func(context.Context, *config.Config) error {
		defer close(done)
		return nil
	}
	t.Cleanup(func() { startupUpdateCheck = origCheck })

	mi := &MainIntegration{cfg: &config.Config{AutoUpdate: true}}
	mi.maybeStartupUpdateCheck(context.Background())
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("update check goroutine did not run")
	}
}

// ── initAuth ────────────────────────────────────────────────────────────────

func TestInitAuth_ReusesValidStoredToken(t *testing.T) {
	resetUpdaterRetrier(t)
	fb := newFakeBackend(t, http.StatusOK)
	cfg := startTestConfig(t, fb.srv.URL)
	stored := testJWT(time.Hour)
	cfg.SetTokens(stored, "stored-refresh")

	mi := &MainIntegration{cfg: cfg}
	mi.initAuth(context.Background())

	if mi.authSvc == nil {
		t.Fatal("initAuth should create the auth service")
	}
	if n := fb.logins.Load(); n != 0 {
		t.Errorf("agent-login calls = %d, want 0 (stored token still valid)", n)
	}
	if got := cfg.GetAccessToken(); got != stored {
		t.Error("initAuth should keep the stored access token")
	}
}

func TestInitAuth_ExpiringTokenTriggersLogin(t *testing.T) {
	resetUpdaterRetrier(t)
	fb := newFakeBackend(t, http.StatusOK)
	cfg := startTestConfig(t, fb.srv.URL)
	expiring := testJWT(time.Minute) // inside startupTokenSkew
	cfg.SetTokens(expiring, "stored-refresh")

	mi := &MainIntegration{cfg: cfg}
	mi.initAuth(context.Background())

	if n := fb.logins.Load(); n != 1 {
		t.Errorf("agent-login calls = %d, want 1", n)
	}
	if cfg.GetAccessToken() == expiring {
		t.Error("initAuth should replace a near-expiry token with a fresh one")
	}
	if _, err := os.Stat(cfg.Path); err != nil {
		t.Errorf("agent-login tokens should be persisted to the temp config: %v", err)
	}
}

func TestInitAuth_InitSessionFailsFallsBackToLogin(t *testing.T) {
	resetUpdaterRetrier(t)
	// Empty base URL: InitSession rejects it and Login fails fast offline.
	cfg := startTestConfig(t, "")
	cfg.SetTokens(testJWT(time.Hour), "")

	lw := watchLog(t)
	mi := &MainIntegration{cfg: cfg}
	mi.initAuth(context.Background())

	if !lw.contains("session init from stored token failed") {
		t.Error("expected InitSession failure to be logged")
	}
	if !lw.contains("startup agent-login failed") {
		t.Error("expected the fallback agent-login failure to be logged (non-fatal)")
	}
	if mi.authSvc == nil {
		t.Error("auth service should still be created when login fails")
	}
}

// ── buildServicesTask / servicesCollectHandler ──────────────────────────────

func stubCollectServices(t *testing.T, list []models.ServiceInfo) {
	t.Helper()
	orig := collectServices
	collectServices = func(*servicessvc.ServicesService) []models.ServiceInfo { return list }
	t.Cleanup(func() { collectServices = orig })
}

func newServicesHandler(t *testing.T, cfg *config.Config) (*MainIntegration, scheduler.TaskHandler) {
	t.Helper()
	mi := &MainIntegration{cfg: cfg}
	task := mi.buildServicesTask()
	if task == nil {
		t.Fatal("buildServicesTask() = nil")
	}
	t.Cleanup(func() { _ = mi.servicesStore.Close() })
	return mi, task.Handler
}

func TestBuildServicesTask_NilWhenStoreCannotOpen(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mi := &MainIntegration{cfg: &config.Config{Path: filepath.Join(blocker, "config.json")}}

	if task := mi.buildServicesTask(); task != nil {
		t.Errorf("buildServicesTask() = %+v, want nil when the store cannot be opened", task)
	}
	if mi.servicesStore != nil {
		t.Error("servicesStore should stay nil on open failure")
	}
}

func TestServicesCollectHandler_SkipsWhenAuthDegraded(t *testing.T) {
	collected := false
	orig := collectServices
	collectServices = func(*servicessvc.ServicesService) []models.ServiceInfo {
		collected = true
		return nil
	}
	t.Cleanup(func() { collectServices = orig })

	cfg := miTestConfig(t)
	cfg.ServicesSyncEnabled = true
	_, h := newServicesHandler(t, cfg)

	if err := h(context.Background(), cfg, rejectedAuthSvc(t)); err != nil {
		t.Errorf("handler with degraded auth should no-op, got %v", err)
	}
	if collected {
		t.Error("services must not be collected while auth is degraded")
	}
}

func TestServicesCollectHandler_EmptyListSkipsStore(t *testing.T) {
	stubCollectServices(t, nil)
	cfg := miTestConfig(t)
	cfg.ServicesSyncEnabled = true
	_, h := newServicesHandler(t, cfg)

	if err := h(context.Background(), cfg, nil); err != nil {
		t.Errorf("handler with no services should no-op, got %v", err)
	}
}

func TestServicesCollectHandler_StoresAndSends(t *testing.T) {
	stubCollectServices(t, []models.ServiceInfo{
		{Name: "svc-a", Source: "systemd", Status: "running"},
		{Name: "svc-b", Source: "systemd", Status: "stopped"},
	})
	cfg := miTestConfig(t) // empty SupabaseURL: the send fails fast offline
	cfg.ServicesSyncEnabled = true

	for _, tc := range []struct {
		name string
		auth *authsvc.Service
	}{
		{"without auth", nil},
		{"with auth retry", authsvc.NewService("", cfg.SupabaseKey)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mi, h := newServicesHandler(t, cfg)
			err := h(context.Background(), cfg, tc.auth)
			if err == nil || !strings.Contains(err.Error(), "supabase base URL not configured") {
				t.Fatalf("handler error = %v, want offline send failure", err)
			}
			stored, gerr := mi.servicesStore.GetAll(cfg.DeviceID)
			if gerr != nil {
				t.Fatalf("GetAll: %v", gerr)
			}
			if len(stored) != 2 {
				t.Errorf("stored services = %d, want 2 (upsert before send)", len(stored))
			}
		})
	}
}

func TestServicesCollectHandler_UpsertError(t *testing.T) {
	stubCollectServices(t, []models.ServiceInfo{{Name: "svc-a", Source: "systemd"}})
	cfg := miTestConfig(t)
	cfg.ServicesSyncEnabled = true
	mi, h := newServicesHandler(t, cfg)
	_ = mi.servicesStore.Close() // closed DB makes Upsert fail

	err := h(context.Background(), cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "store upsert") {
		t.Fatalf("handler error = %v, want store upsert failure", err)
	}
}

// ── softwareSyncHandler ─────────────────────────────────────────────────────

func stubCollectSoftware(t *testing.T, list []swsvc.SoftwareInfo, complete bool) *bool {
	t.Helper()
	called := new(bool)
	orig := collectSoftware
	collectSoftware = func(*swsvc.SoftwareService) ([]swsvc.SoftwareInfo, bool) {
		*called = true
		return list, complete
	}
	t.Cleanup(func() { collectSoftware = orig })
	return called
}

func newSoftwareHandler(t *testing.T, cfg *config.Config) (*MainIntegration, scheduler.TaskHandler) {
	t.Helper()
	mi := &MainIntegration{cfg: cfg}
	h := mi.softwareSyncHandler()
	if h == nil {
		t.Fatal("softwareSyncHandler() = nil")
	}
	t.Cleanup(func() { _ = mi.softwareStore.Close() })
	return mi, h
}

func TestSoftwareSyncHandler_NilWhenStoreCannotOpen(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mi := &MainIntegration{cfg: &config.Config{
		Path:                filepath.Join(blocker, "config.json"),
		SoftwareSyncEnabled: true,
	}}

	if h := mi.softwareSyncHandler(); h != nil {
		t.Error("softwareSyncHandler() should be nil when the store cannot be opened")
	}
	if mi.softwareStore != nil {
		t.Error("softwareStore should stay nil on open failure")
	}
}

func TestSoftwareSyncHandler_SkipsWhenAuthDegraded(t *testing.T) {
	called := stubCollectSoftware(t, nil, true)
	cfg := miTestConfig(t)
	cfg.SoftwareSyncEnabled = true
	_, h := newSoftwareHandler(t, cfg)

	if err := h(context.Background(), cfg, rejectedAuthSvc(t)); err != nil {
		t.Errorf("handler with degraded auth should no-op, got %v", err)
	}
	if *called {
		t.Error("software must not be collected while auth is degraded")
	}
}

func TestSoftwareSyncHandler_EmptyListSkipsUpload(t *testing.T) {
	called := stubCollectSoftware(t, nil, true)
	cfg := miTestConfig(t)
	cfg.SoftwareSyncEnabled = true
	_, h := newSoftwareHandler(t, cfg)

	if err := h(context.Background(), cfg, nil); err != nil {
		t.Errorf("handler with no software should no-op, got %v", err)
	}
	if !*called {
		t.Error("software collection should have run")
	}
}

func TestSoftwareSyncHandler_SyncsCatalog(t *testing.T) {
	stubCollectSoftware(t, []swsvc.SoftwareInfo{
		{Name: "app-a", Source: "registry"},
		{Name: "app-b", Source: "registry"},
	}, true)
	cfg := miTestConfig(t) // empty SupabaseURL: the send fails fast offline
	cfg.SoftwareSyncEnabled = true

	for _, tc := range []struct {
		name string
		auth *authsvc.Service
	}{
		{"without auth", nil},
		{"with auth retry", authsvc.NewService("", cfg.SupabaseKey)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, h := newSoftwareHandler(t, cfg)
			err := h(context.Background(), cfg, tc.auth)
			if err == nil || !strings.Contains(err.Error(), "supabase base URL not configured") {
				t.Fatalf("handler error = %v, want offline send failure", err)
			}
		})
	}
}

// ── startLoggingService ─────────────────────────────────────────────────────

func TestStartLoggingService_Disabled(t *testing.T) {
	mi := &MainIntegration{cfg: &config.Config{AuditLogsEnabled: false}}
	if err := mi.startLoggingService(context.Background()); err != nil {
		t.Errorf("startLoggingService() disabled = %v, want nil", err)
	}
	if mi.loggingService != nil {
		t.Error("logging service must not start when audit logs are disabled")
	}
}

func TestStartLoggingService_StartsWithoutAuth(t *testing.T) {
	cfg := miTestConfig(t)
	cfg.AuditLogsEnabled = true
	mi := &MainIntegration{cfg: cfg}

	if err := mi.startLoggingService(context.Background()); err != nil {
		t.Fatalf("startLoggingService() error: %v", err)
	}
	if mi.loggingService == nil {
		t.Fatal("loggingService should be set after a successful start")
	}
	if err := mi.loggingService.Stop(); err != nil {
		t.Errorf("logging Stop() error: %v", err)
	}
}

// ── startTaskManager ────────────────────────────────────────────────────────

func TestStartTaskManager_Disabled(t *testing.T) {
	mi := &MainIntegration{cfg: &config.Config{EnableTaskPolling: false}}
	mi.startTaskManager(context.Background())
	if mi.taskManager != nil {
		t.Error("task manager must not start when task polling is disabled")
	}
}

func TestStartTaskManager_InitFailureIsNonFatal(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := miTestConfig(t)
	cfg.EnableTaskPolling = true
	cfg.TaskDBPath = filepath.Join(blocker, "tasks.sqlite")

	mi := &MainIntegration{cfg: cfg}
	mi.startTaskManager(context.Background())
	if mi.taskManager != nil {
		t.Error("task manager should stay nil when its store cannot be opened")
	}
}

// ── Stop ────────────────────────────────────────────────────────────────────

// TestStop_ClosesStoresAndLogsCloseErrors covers Stop's store-closing branches,
// including the warning paths when a component has already been closed.
func TestStop_ClosesStoresAndLogsCloseErrors(t *testing.T) {
	cfg := miTestConfig(t)
	cfg.SoftwareSyncEnabled = true
	mi := NewMainIntegrationWith(cfg, scheduler.NewScheduler())

	if mi.buildServicesTask() == nil {
		t.Fatal("buildServicesTask() = nil")
	}
	if mi.softwareSyncHandler() == nil {
		t.Fatal("softwareSyncHandler() = nil")
	}

	if err := mi.Stop(); err != nil {
		t.Errorf("Stop() error: %v", err)
	}
	// A second Stop closes the already-closed stores again; it must stay a
	// logged warning, never an error or panic.
	if err := mi.Stop(); err != nil {
		t.Errorf("second Stop() error: %v", err)
	}
}

// ── authTokenRefresher ──────────────────────────────────────────────────────

func TestAuthTokenRefresher_RefreshToken_Success(t *testing.T) {
	fb := newFakeBackend(t, http.StatusOK)
	cfg := startTestConfig(t, fb.srv.URL)
	r := &authTokenRefresher{authSvc: authsvc.NewService(fb.srv.URL, cfg.SupabaseKey), cfg: cfg}

	tok, err := r.RefreshToken(context.Background())
	if err != nil {
		t.Fatalf("RefreshToken() error: %v", err)
	}
	if tok == "" || tok != cfg.GetAccessToken() {
		t.Errorf("RefreshToken() = %q, want the recovered access token", tok)
	}
}
