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
	apiKey      string
}

// NewServicesService returns a new ServicesService.
func NewServicesService() *ServicesService {
	return &ServicesService{
		client: httpx.NewClient(30 * time.Second),
	}
}

// SetSupabaseURL sets the Supabase project URL used for RPC calls.
func (s *ServicesService) SetSupabaseURL(url string) { s.supabaseURL = url }

// SetAPIKey sets the access token used as the Authorization Bearer value.
func (s *ServicesService) SetAPIKey(key string) { s.apiKey = key }

// GetServiceList returns the list of OS services for the current platform.
func (s *ServicesService) GetServiceList() []models.ServiceInfo {
	return s.platformServices()
}
