package services

import "testing"

func TestGetServiceList_ReturnsPlatformServices(t *testing.T) {
	svc := NewServicesService()
	// The exact contents are OS-dependent (real service enumeration); we only
	// assert the dispatcher delegates to platformServices without panicking
	// and returns a non-nil (possibly empty) slice.
	list := svc.GetServiceList()
	if list == nil {
		t.Error("GetServiceList() = nil, want a non-nil slice (even if empty)")
	}
}

func TestNewServicesService_SettersApply(t *testing.T) {
	svc := NewServicesService()
	svc.SetSupabaseURL("https://example.supabase.co")
	svc.SetAPIKey("test-key")

	if svc.supabaseURL != "https://example.supabase.co" {
		t.Errorf("supabaseURL = %q, want %q", svc.supabaseURL, "https://example.supabase.co")
	}
	if svc.apiKey != "test-key" {
		t.Errorf("apiKey = %q, want %q", svc.apiKey, "test-key")
	}
	if svc.client == nil {
		t.Error("client = nil, want a configured http.Client")
	}
}
