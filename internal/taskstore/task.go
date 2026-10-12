package taskstore

import (
	"time"

	"sentinelgo/internal/artifact"
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
	// Artifacts are files the agent downloads and verifies before running
	// the script (contract v1 §1, #134). Empty for most tasks.
	Artifacts []artifact.Spec `json:"artifacts"`
	Status      string                 `json:"status"`
	Note        string                 `json:"note"`
	AssignedAt  *time.Time             `json:"assigned_at"`
	CompletedAt *time.Time             `json:"completed_at"`
	CreatedAt   *time.Time             `json:"created_at"`
	UpdatedAt   *time.Time             `json:"updated_at"`
	CreatedBy   string                 `json:"created_by"`
}

// AgentTasksResponse represents the response from agent_get_tasks RPC
type AgentTasksResponse struct {
	ServerTime string `json:"server_time"`
	Tasks      []Task `json:"tasks"`
}
