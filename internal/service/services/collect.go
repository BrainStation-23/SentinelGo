package services

import (
	"time"

	"sentinelgo/internal/models"
)

// collectCmdTimeout bounds every external enumeration command so a hung tool
// does not block the services-collect scheduler goroutine indefinitely.
const collectCmdTimeout = 30 * time.Second

// ServicesService collects running OS services on the current platform.
type ServicesService struct{}

// NewServicesService returns a new ServicesService.
func NewServicesService() *ServicesService {
	return &ServicesService{}
}

// GetServiceList returns the list of OS services for the current platform.
func (s *ServicesService) GetServiceList() []models.ServiceInfo {
	return s.platformServices()
}
