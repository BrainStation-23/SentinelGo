package taskstore

import (
	"time"

	"sentinelgo/internal/artifact"
)

// Command kinds sent as Task.CommandKind.
const (
	// CommandKindNative is run by a Go handler in the agent, matched by slug.
	CommandKindNative = "native"
	// CommandKindSystem is a seeded script sent by console buttons, toggles
	// and policies. It usually changes the machine.
	CommandKindSystem = "system"
	// CommandKindNormal is a user-authored script.
	CommandKindNormal = "normal"
)

// Task represents a task from agent_get_tasks RPC response
type Task struct {
	ID          string                 `json:"task_id"`
	CommandID   string                 `json:"command_id"`
	Slug        string                 `json:"slug"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Tags        []string               `json:"tags"`
	Payload     map[string]interface{} `json:"payload"`
	Scripts     map[string]interface{} `json:"scripts"`
	// CommandKind is the backend command's kind: CommandKindNative,
	// CommandKindSystem or CommandKindNormal (sentinel-ops#403). "" means
	// unknown: an older backend that doesn't send it, or a JSON null for a
	// command that was deleted.
	CommandKind string `json:"command_kind"`
	// Artifacts are files the agent downloads and verifies before running
	// the script (contract v1 §1, #134). Empty for most tasks.
	Artifacts   []artifact.Spec `json:"artifacts"`
	Status      string          `json:"status"`
	Note        string          `json:"note"`
	AssignedAt  *time.Time      `json:"assigned_at"`
	CompletedAt *time.Time      `json:"completed_at"`
	CreatedAt   *time.Time      `json:"created_at"`
	UpdatedAt   *time.Time      `json:"updated_at"`
	CreatedBy   string          `json:"created_by"`
	// Result is the structured outcome the agent reports with the final
	// status (exit_code plus anything the script wrote, sentinel-ops#49).
	// Agent-side only: kept in the local store so a retried report carries
	// it, never read from the server.
	Result map[string]interface{} `json:"-"`
}

// AgentTasksResponse represents the response from agent_get_tasks RPC
type AgentTasksResponse struct {
	ServerTime string `json:"server_time"`
	Tasks      []Task `json:"tasks"`
}
