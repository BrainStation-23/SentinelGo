// Package scanworker parses files for file DLP in sandboxed worker processes
// (#328), never in the SYSTEM/root service: a parser bug or a hostile file
// then costs a worker, not the machine.
//
// The service runs a small pool of long-lived `sentinelgo dlp-scan` workers.
// Each gets one end of a socket pair as fd 3. The service sends the policy
// bundle, then one scan at a time: a request plus the file's descriptor
// (SCM_RIGHTS). The worker never opens a path; it reads only the descriptor
// it was handed and answers with a filescan.Result (findings, never text).
//
// Before reading anything the worker sandboxes itself (Linux): no new
// privileges, no file writes, no files by path (Landlock), no network (a new
// network namespace, and Landlock where the kernel supports it), and it runs
// as an unprivileged user. Only Linux runs workers so far.
package scanworker

import "errors"

// Command is the hidden subcommand that runs a worker.
const Command = "dlp-scan"

// ReasonWorkerFailed is the unscannable reason when no worker could scan.
const ReasonWorkerFailed = "worker_failed"

// ErrUnsupported is returned where workers can't run (not Linux).
var ErrUnsupported = errors.New("scan workers are only supported on Linux")

// Health is the pool's state for the status report.
type Health struct {
	Workers  int    `json:"workers"`
	Sandbox  string `json:"sandbox,omitempty"`
	Failures int    `json:"failures"`
	Disabled bool   `json:"disabled,omitempty"` // crash loop: no more workers are started
}
