//go:build !windows && !darwin && !linux

package uploadproxy

type noRedirector struct{}

// NewRedirector returns a Redirector that can't redirect here.
func NewRedirector(string) Redirector { return noRedirector{} }

func platformRedirector(ServiceOptions) Redirector { return noRedirector{} }

func (noRedirector) Apply(string) error { return ErrNotImplemented }

// Remove has nothing to undo here.
func (noRedirector) Remove() error { return nil }

type noTruster struct{}

// NewTruster returns a Truster that can't trust here.
func NewTruster() Truster { return noTruster{} }

func (noTruster) Trust(*CA) error { return ErrNotImplemented }

// Untrust has nothing to remove here.
func (noTruster) Untrust() error { return nil }
