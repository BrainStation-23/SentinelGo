package rpcutil

import (
	"encoding/json"

	"sentinelgo/internal/remoteconfig"
)

// EnqueueResponse is the JSON shape returned by all agent_enqueue_* Postgres RPCs.
type EnqueueResponse struct {
	Success  bool   `json:"success"`
	Enqueued bool   `json:"enqueued"`
	AgentID  string `json:"agent_id"`
	Queue    string `json:"queue"`
	MsgID    int64  `json:"msg_id"`
	// Config is the server's agent settings (sentinel-ops#902), absent from
	// older servers. ObserveConfig hands it to the service (#466).
	Config json.RawMessage `json:"config,omitempty"`
}

// ObserveConfig passes the reply's config member, if any, to remoteconfig.
func (r *EnqueueResponse) ObserveConfig() {
	remoteconfig.Observe(r.Config)
}

// ObserveConfigIn reads the config member from any raw RPC reply and passes
// it to remoteconfig. A reply that isn't a JSON object is ignored.
func ObserveConfigIn(raw []byte) {
	var r struct {
		Config json.RawMessage `json:"config"`
	}
	if json.Unmarshal(raw, &r) == nil {
		remoteconfig.Observe(r.Config)
	}
}
