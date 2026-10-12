// Package constants holds values shared across the agent.
package constants

// AgentCapabilities are the task features this binary supports, sent in the
// inventory payload so the backend never queues a task the agent can't run
// (contract v1 §6, #134). The backend matches each entry against
// ^[a-z0-9_]{1,64}$.
//
// Add an entry only in the same change that implements it: advertising a
// capability the binary lacks makes the backend send tasks that fail on
// the device.
var AgentCapabilities = []string{
	"script_inline_body_v1", // inline scripts[<os>].body (#135)
	"task_artifacts_v1",     // verified task artifacts (#136, #137)
}

// Capabilities returns a copy of AgentCapabilities, so callers can't change
// what the agent advertises.
func Capabilities() []string {
	return append([]string{}, AgentCapabilities...)
}
