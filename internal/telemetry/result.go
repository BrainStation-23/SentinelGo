package telemetry

import "time"

// Status is the outcome of a single collection attempt.
//
// The split between "the feature is not there" (StatusUnsupported) and "we
// tried and failed" (StatusError, StatusPermissionDenied, StatusTimeout) is the
// point of this type. Today both cases reach the backend as an absent field,
// so an operator cannot tell a fleet of desktops without TPMs from a fleet
// whose TPM collector is broken.
type Status string

const (
	// StatusSuccess: the collector produced complete data.
	StatusSuccess Status = "success"
	// StatusPartial: some data was produced, but a sub-query failed or a source
	// was unavailable. The payload is usable but incomplete.
	StatusPartial Status = "partial"
	// StatusUnsupported: this endpoint cannot provide the data — the tool is
	// missing, the OS does not expose it, or the hardware is absent. Not a fault.
	StatusUnsupported Status = "unsupported"
	// StatusPermissionDenied: the data exists but the agent lacks rights to read
	// it. Actionable: the agent needs elevation or a policy change.
	StatusPermissionDenied Status = "permission_denied"
	// StatusTimeout: collection exceeded its deadline.
	StatusTimeout Status = "timeout"
	// StatusError: an unexpected failure.
	StatusError Status = "error"
)

// Valid reports whether s is a recognised status.
func (s Status) Valid() bool {
	switch s {
	case StatusSuccess, StatusPartial, StatusUnsupported,
		StatusPermissionDenied, StatusTimeout, StatusError:
		return true
	default:
		return false
	}
}

// OK reports whether the status represents usable data.
func (s Status) OK() bool { return s == StatusSuccess || s == StatusPartial }

// Failed reports whether the status represents a genuine fault, as opposed to
// the data simply not existing on this endpoint. Telemetry health counts only
// these toward collector failures — a desktop with no battery must not look
// unhealthy forever.
func (s Status) Failed() bool {
	return s == StatusError || s == StatusPermissionDenied || s == StatusTimeout
}

func (s Status) String() string { return string(s) }

// CollectorResult records the outcome of one collector run. It is transmitted
// in the envelope's Meta block, never inside a section payload, because its
// timing fields change on every cycle and would otherwise defeat change
// detection. See Meta in envelope.go.
type CollectorResult struct {
	Collector   string `json:"collector"`
	Section     string `json:"section"`
	Status      Status `json:"status"`
	CollectedAt string `json:"collected_at"`
	DurationMS  int64  `json:"duration_ms"`
	// Source names the mechanism actually used, e.g.
	// "wmi:root/wmi:BatteryStaticData", "sysfs:/sys/class/power_supply",
	// "exec:smartctl". Recording it makes a silent fallback to a weaker source
	// visible server-side instead of looking like a normal success.
	Source    string   `json:"source,omitempty"`
	ItemCount int      `json:"item_count,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	// WarningsDropped counts warnings discarded by the MaxWarnings cap.
	WarningsDropped int `json:"warnings_dropped,omitempty"`
	// Error is a reason code from the Reason* vocabulary, never raw output.
	Error string `json:"error,omitempty"`
}

// NewResult starts a result for a collector run and returns it together with a
// finish function that stamps the duration and sanitizes the outcome.
//
// Usage keeps the timing and sanitization in one place so no collector can
// forget either:
//
//	res, done := telemetry.NewResult("battery", "health")
//	data, err := collect(ctx)
//	done(err, "ioreg:AppleSmartBattery", len(data))
func NewResult(collector, section string) (*CollectorResult, func(err error, source string, itemCount int) *CollectorResult) {
	start := time.Now()
	res := &CollectorResult{
		Collector:   collector,
		Section:     section,
		Status:      StatusSuccess,
		CollectedAt: start.UTC().Format(time.RFC3339),
	}

	finish := func(err error, source string, itemCount int) *CollectorResult {
		res.DurationMS = time.Since(start).Milliseconds()
		res.Source = source
		res.ItemCount = itemCount
		status, reason := SanitizeError(err)
		res.Status = status
		res.Error = reason
		return res
	}

	return res, finish
}

// AddWarning appends a sanitized warning, respecting the MaxWarnings cap and
// counting anything dropped.
func (r *CollectorResult) AddWarning(msg string) {
	clean := SanitizeMessage(msg)
	if clean == "" {
		return
	}
	if len(r.Warnings) >= MaxWarnings {
		r.WarningsDropped++
		return
	}
	r.Warnings = append(r.Warnings, clean)
}

// Sanitize normalises a result that was built by hand rather than via NewResult,
// so every path onto the wire is bounded and redacted. It is idempotent.
func (r *CollectorResult) Sanitize() {
	if !r.Status.Valid() {
		r.Status = StatusError
	}
	r.Collector = SanitizeMessage(r.Collector)
	r.Section = SanitizeMessage(r.Section)
	r.Source = SanitizeMessage(r.Source)
	r.Error = truncateRunes(SanitizeMessage(r.Error), MaxErrorLen)
	kept, dropped := SanitizeWarnings(r.Warnings)
	r.Warnings = kept
	r.WarningsDropped += dropped
}
