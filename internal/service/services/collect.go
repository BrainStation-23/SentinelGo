package services

import (
	"net/http"
	"time"

	"sentinelgo/internal/httpx"
	"sentinelgo/internal/models"
)

// collectCmdTimeout bounds every external enumeration command so a hung tool
// does not block the services-collect scheduler goroutine indefinitely.
const collectCmdTimeout = 30 * time.Second

// ServicesService collects running OS services on the current platform.
type ServicesService struct {
	client      *http.Client
	supabaseURL string
}

// NewServicesService returns a new ServicesService.
func NewServicesService() *ServicesService {
	return &ServicesService{
		client: httpx.NewClient(30 * time.Second),
	}
}

// SetSupabaseURL sets the Supabase project URL used for RPC calls.
func (s *ServicesService) SetSupabaseURL(url string) { s.supabaseURL = url }

// GetServiceList returns the list of OS services for the current platform.
func (s *ServicesService) GetServiceList() []models.ServiceInfo {
	return s.platformServices()
}
