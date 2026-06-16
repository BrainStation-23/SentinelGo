package scheduler_test

import (
	"context"
	"testing"
	"time"

	"sentinelgo/internal"
	"sentinelgo/internal/config"
	"sentinelgo/internal/scheduler"
	swsvc "sentinelgo/internal/service/software"
)

// TestMainIntegration tests the complete main integration. It starts real
// services (which collect system info via OS shell-outs and may attempt network
// I/O), so it is skipped in -short mode.
func TestMainIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full main-integration test (slow OS collection / network) in -short mode")
	}
	// Create test configuration
	cfg := createTestConfig(t)
	// Disable audit logs to avoid database locking issues in integration test
	cfg.AuditLogsEnabled = false
	// Disable auto-update to prevent long-running network calls in tests
	cfg.AutoUpdate = false

	// Test main integration creation
	integration := internal.NewMainIntegration(cfg)
	if integration == nil {
		t.Fatal("Failed to create main integration")
	}

	// Create context with shorter timeout for faster test
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test starting integration
	if err := integration.Start(ctx); err != nil {
		t.Fatalf("Failed to start main integration: %v", err)
	}

	// Wait a bit for services to initialize
	time.Sleep(500 * time.Millisecond)

	// Test status
	status := integration.GetStatus()
	if status == nil {
		t.Fatal("Status should not be nil")
	}

	// Test stopping integration
	if err := integration.Stop(); err != nil {
		t.Fatalf("Failed to stop main integration: %v", err)
	}

	// Wait for goroutines to clean up
	time.Sleep(200 * time.Millisecond)

	t.Log("Main integration test passed")
}

// TestScheduler tests the task scheduler end-to-end. Starting the scheduler runs
// the default tasks (system-info collection via OS shell-outs, possible network),
// so it is skipped in -short mode.
func TestScheduler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full scheduler run (slow OS collection / network) in -short mode")
	}
	// Create test configuration
	cfg := createTestConfig(t)

	// Create scheduler
	sched := scheduler.NewScheduler()
	if sched == nil {
		t.Fatal("Failed to create scheduler")
	}

	// Create test tasks
	tasks := scheduler.CreateDefaultTasks()
	if len(tasks) == 0 {
		t.Fatal("No default tasks created")
	}

	// Add tasks to scheduler
	for _, task := range tasks {
		if err := sched.AddTask(task); err != nil {
			t.Fatalf("Failed to add task %s: %v", task.Name, err)
		}
	}

	// Test starting scheduler
	if err := sched.Start(cfg, nil); err != nil {
		t.Fatalf("Failed to start scheduler: %v", err)
	}

	// Wait a bit for tasks to run (reduced from 2s to 500ms)
	time.Sleep(500 * time.Millisecond)

	// Test task status
	status := sched.GetTaskStatus()
	if len(status) == 0 {
		t.Fatal("No task status returned")
	}

	// Test stopping scheduler
	sched.Stop()

	// Wait for goroutines to clean up
	time.Sleep(200 * time.Millisecond)

	t.Log("Scheduler test passed")
}

// TestLoggingIntegration tests the logging integration
func TestLoggingIntegration(t *testing.T) {
	// Skip this test due to database locking issues in concurrent test environment
	// The logging integration tests are covered by other unit tests
	t.Skip("Skipping TestLoggingIntegration due to database locking issues in concurrent test environment")
}

// TestSoftwareService tests the software service
func TestSoftwareService(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping software collection (real OS shell-outs) in -short mode")
	}
	// Create software service
	softwareService := swsvc.NewSoftwareService()

	// Test getting software list
	softwareList := softwareService.GetSoftwareList()
	if softwareList == nil {
		t.Fatal("Software list should not be nil")
	}

	// Test filtering changed software (using internal method)
	// Note: filterChangedSoftware is unexported, so we can't test it directly
	// This is expected behavior for unexported methods

	t.Logf("Software service test passed - found %d items", len(softwareList))
}

// createTestConfig creates a test configuration
func createTestConfig(t *testing.T) *config.Config {
	// Load config from audit-config-sample.json
	cfg := loadTestConfig(t)
	return cfg
}
