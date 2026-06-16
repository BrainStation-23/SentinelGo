package rpcutil

// EnqueueResponse is the JSON shape returned by all agent_enqueue_* Postgres RPCs.
type EnqueueResponse struct {
	Success  bool   `json:"success"`
	Enqueued bool   `json:"enqueued"`
	AgentID  string `json:"agent_id"`
	Queue    string `json:"queue"`
	MsgID    int64  `json:"msg_id"`
}
