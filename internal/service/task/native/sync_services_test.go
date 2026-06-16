package native

// White-box tests for the sync-services handler.
// Using package native (not native_test) to access sendServicesFn / getServicesListFn.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	servicessvc "sentinelgo/internal/service/services"
	"sentinelgo/internal/taskstore"
)

func testSvcCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		Path:        dir + "/config.json",
		SupabaseURL: "https://test.supabase.co",
		DeviceID:    "test-device",
		AccessToken: "test-token",
	}
}

func TestSyncServicesHandler_Slugs(t *testing.T) {
	h := &syncServicesHandler{}
	slugs := h.Slugs()
	found := false
	for _, s := range slugs {
		if s == "sync-services" {
			found = true
		}
	}
	if !found {
		t.Errorf("Slugs() does not contain 'sync-services': %v", slugs)
	}
}

func TestSyncServicesHandler_EmptyList_ReturnsSuccess(t *testing.T) {
	origSend := sendServicesFn
	origList := getServicesListFn
	defer func() {
		sendServicesFn = origSend
		getServicesListFn = origList
	}()

	getServicesListFn = func(_ *servicessvc.ServicesService) []models.ServiceInfo { return nil }
	sendServicesFn = func(_ context.Context, _ *servicessvc.ServicesService, _ string, _ []models.ServiceInfo, _ *config.Config) error {
		return errors.New("SendByRPC must not be called for empty list")
	}

	h := &syncServicesHandler{}
	note, err := h.Run(context.Background(), testSvcCfg(t), taskstore.Task{})
	if err != nil {
		t.Fatalf("expected no error for empty list, got: %v", err)
	}
	if note == "" {
		t.Error("expected non-empty note for empty list")
	}
}

func TestSyncServicesHandler_SendFails_ReturnsError(t *testing.T) {
	origSend := sendServicesFn
	origList := getServicesListFn
	defer func() {
		sendServicesFn = origSend
		getServicesListFn = origList
	}()

	getServicesListFn = func(_ *servicessvc.ServicesService) []models.ServiceInfo {
		return []models.ServiceInfo{{Name: "sshd", Source: "systemd", Status: "running"}}
	}

	sendErr := errors.New("RPC unavailable")
	sendServicesFn = func(_ context.Context, _ *servicessvc.ServicesService, _ string, _ []models.ServiceInfo, _ *config.Config) error {
		return sendErr
	}

	h := &syncServicesHandler{}
	_, err := h.Run(context.Background(), testSvcCfg(t), taskstore.Task{})
	if err == nil {
		t.Fatal("expected error when SendByRPC fails")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("expected wrapped sendErr, got: %v", err)
	}
}

func TestSyncServicesHandler_Success(t *testing.T) {
	origSend := sendServicesFn
	origList := getServicesListFn
	defer func() {
		sendServicesFn = origSend
		getServicesListFn = origList
	}()

	called := false
	getServicesListFn = func(_ *servicessvc.ServicesService) []models.ServiceInfo {
		return []models.ServiceInfo{
			{Name: "sshd", Source: "systemd", Status: "running"},
			{Name: "cron", Source: "systemd", Status: "running"},
		}
	}
	sendServicesFn = func(_ context.Context, _ *servicessvc.ServicesService, _ string, list []models.ServiceInfo, _ *config.Config) error {
		called = true
		if len(list) != 2 {
			return fmt.Errorf("expected 2 items, got %d", len(list))
		}
		return nil
	}

	h := &syncServicesHandler{}
	note, err := h.Run(context.Background(), testSvcCfg(t), taskstore.Task{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("sendServicesFn was not called")
	}
	if note == "" {
		t.Error("expected non-empty success note")
	}
}
