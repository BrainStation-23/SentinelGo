package software

import (
	"net/http"
	"time"

	"sentinelgo/internal/httpx"
	"sentinelgo/internal/models"
)

// SoftwareInfo is an alias for models.SoftwareInfo.
type SoftwareInfo = models.SoftwareInfo

// SoftwareService handles software collection and upload.
type SoftwareService struct {
	client      *http.Client
	supabaseURL string
}

// NewSoftwareService returns a SoftwareService ready to be configured.
func NewSoftwareService() *SoftwareService {
	return &SoftwareService{
		client: httpx.NewClient(30 * time.Second),
	}
}

// SetSupabaseURL sets the Supabase project URL used for RPC calls.
func (s *SoftwareService) SetSupabaseURL(url string) {
	if url != "" {
		s.supabaseURL = url
	}
}
