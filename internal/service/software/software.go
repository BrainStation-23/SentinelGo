package software

import (
	"net/http"
	"strings"
	"time"

	"sentinelgo/internal/httpx"
	"sentinelgo/internal/models"
)

// SoftwareInfo is an alias for models.SoftwareInfo.
type SoftwareInfo = models.SoftwareInfo

// SoftwareService handles software collection and upload.
type SoftwareService struct {
	client      *http.Client
	edgeURL     string
	supabaseURL string
	apiKey      string
}

// NewSoftwareService returns a zero-value SoftwareService ready to be configured.
func NewSoftwareService() *SoftwareService {
	return &SoftwareService{}
}

// SetEdgeFunctionConfig configures the service for edge function communication.
func (s *SoftwareService) SetEdgeFunctionConfig(edgeURL, apiKey string) {
	s.edgeURL = edgeURL
	s.apiKey = apiKey
	if base, _, found := strings.Cut(edgeURL, "/functions/v1/"); found && base != "" {
		s.supabaseURL = base
	}
	if s.client == nil {
		s.client = httpx.NewClient(30 * time.Second)
	}
}

// SetSupabaseURL explicitly sets the Supabase base URL used for REST API fallback.
func (s *SoftwareService) SetSupabaseURL(url string) {
	if url != "" {
		s.supabaseURL = url
	}
}
