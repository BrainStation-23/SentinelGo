//go:build !windows && !darwin && !linux

package epm

import (
	"context"
	"fmt"
	"runtime"
)

// Service is the stub for platforms without an enforcement layer (anything
// besides Windows, macOS, and Linux). It exists so
// internal/main_integration.go can call the same exported API on every
// platform without build tags of its own; Start's error is expected to be
// logged and treated as non-fatal by the caller, exactly like any other
// optional component that failed to initialize.
type Service struct{}

// NewService returns a no-op Service on this platform.
func NewService(_ RuleProvider, _ *Auditor) *Service {
	return &Service{}
}

// Start always fails on this platform: there is no enforcement transport yet.
func (s *Service) Start(_ context.Context) error {
	return fmt.Errorf("epm: enforcement is not yet implemented on %s", runtime.GOOS)
}

// Stop is a no-op: Start never succeeded, so there is nothing to tear down.
func (s *Service) Stop() error {
	return nil
}
