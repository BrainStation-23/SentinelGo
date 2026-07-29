package epm

import (
	"encoding/json"
	"fmt"
)

// Op identifies a v2 message's purpose. v1 had exactly one implicit verb (a
// bare {app_path, command_line, ...} request); Op is what makes a second one
// possible without another wire-format change.
type Op string

const (
	OpHello        Op = "hello"
	OpServerHello  Op = "server_hello"
	OpElevate      Op = "elevate" // v1's single implicit verb, now named
	OpPrompt       Op = "prompt"  // server -> client
	OpPromptResult Op = "prompt_result"
	OpApprovalPoll Op = "approval_poll"
	OpQueryPolicy  Op = "query_policy" // dry run: evaluate, never launch
	OpCancel       Op = "cancel"
	OpStatus       Op = "status"
	OpResult       Op = "result" // server -> client, terminal
	OpError        Op = "error"
)

// Envelope is the v2 frame. Every v2 field is omitempty, and the v1 request's
// top-level fields are carried inline, so a literal v1 request decodes into
// an Envelope whose ProtocolVersion and Op are both zero — DecodeRequest
// interprets that as {protocol_version: 1, op: "elevate"}. No sniffing, no
// heuristics, no version byte: the absence of "protocol_version" and "op" IS
// the v1 signal, because a v1 client never sends either key.
type Envelope struct {
	ProtocolVersion int             `json:"protocol_version,omitempty"`
	Op              Op              `json:"op,omitempty"`
	RequestID       string          `json:"request_id,omitempty"`
	Seq             uint64          `json:"seq,omitempty"`
	Body            json.RawMessage `json:"body,omitempty"`

	// --- v1 compatibility: a v1 client puts these at the envelope's top
	// level instead of inside Body. See pipeRequest/socketRequest, which this
	// reproduces field-for-field.
	AppPath     string `json:"app_path,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	ScriptPath  string `json:"script_path,omitempty"`
	Args        string `json:"args,omitempty"`
}

// ElevateBody is OpElevate's payload — a v2 client sends this inside
// Envelope.Body; a v1 client's equivalent fields are read straight off the
// Envelope by DecodeRequest, so both paths converge on the same struct here.
type ElevateBody struct {
	AppPath     string `json:"app_path"`
	CommandLine string `json:"command_line,omitempty"`
	ScriptPath  string `json:"script_path,omitempty"`
	Args        string `json:"args,omitempty"`
}

// DecodeRequest normalizes a raw v1 or v2 frame into (protocol version, op,
// the operation's own body, request id). version is always 1 or 2 (never 0)
// on a successful decode: a bare v1 frame reports version 1.
func DecodeRequest(raw []byte) (version int, op Op, body json.RawMessage, requestID string, err error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return 0, "", nil, "", fmt.Errorf("malformed request: %w", err)
	}

	if env.ProtocolVersion == 0 && env.Op == "" {
		// v1 frame: no envelope fields at all, everything at the top level.
		elevate := ElevateBody{
			AppPath: env.AppPath, CommandLine: env.CommandLine,
			ScriptPath: env.ScriptPath, Args: env.Args,
		}
		b, marshalErr := json.Marshal(elevate)
		if marshalErr != nil {
			return 0, "", nil, "", fmt.Errorf("re-encode v1 request: %w", marshalErr)
		}
		return 1, OpElevate, b, env.RequestID, nil
	}

	version = env.ProtocolVersion
	if version == 0 {
		version = 2
	}
	op = env.Op
	if op == "" {
		op = OpElevate
	}
	return version, op, env.Body, env.RequestID, nil
}

// Response is the terminal server -> client message. The first five fields
// are byte-identical in name and type to the v1 pipeResponse/socketResponse,
// so a v1 client's plain json.Unmarshal (no DisallowUnknownFields) parses
// exactly the answer it expects and silently ignores everything after —
// see protocol_compat_test.go, which pins this against frozen copies of the
// old response structs.
type Response struct {
	RequestID string `json:"request_id"`
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
	ProcessID uint32 `json:"process_id,omitempty"`
	Error     string `json:"error,omitempty"`

	// --- v2 additions ---
	ProtocolVersion int           `json:"protocol_version,omitempty"`
	Op              Op            `json:"op,omitempty"`
	Verdict         Verdict       `json:"verdict,omitempty"`
	Mode            ElevationMode `json:"mode,omitempty"`
	RuleID          string        `json:"rule_id,omitempty"`
	BundleID        string        `json:"bundle_id,omitempty"`
	GrantID         string        `json:"grant_id,omitempty"`
	ExpiresAt       string        `json:"expires_at,omitempty"`
	ApprovalID      string        `json:"approval_id,omitempty"`
	PollAfter       int           `json:"poll_after_seconds,omitempty"`
	Constraints     *Constraints  `json:"constraints,omitempty"`
	Explain         []ExplainStep `json:"explain,omitempty"`
}

// HelloBody is OpHello's payload: a v2 client announcing itself and what it
// can do, so the server knows whether an interaction verdict (Prompt,
// RequireJustification) can actually be carried out on this connection.
type HelloBody struct {
	ProtocolVersion int      `json:"protocol_version"`
	ClientVersion   string   `json:"client_version"`
	Capabilities    []string `json:"capabilities"` // "prompt", "justification", "approval_poll", "notify"
	Locale          string   `json:"locale,omitempty"`
}

// ServerHelloBody answers HelloBody.
type ServerHelloBody struct {
	ProtocolVersion int      `json:"protocol_version"` // min(client, server)
	Capabilities    []string `json:"capabilities"`
	AgentVersion    string   `json:"agent_version"`
}

// PromptBody is OpPrompt's payload — server to client.
type PromptBody struct {
	Kind        string `json:"kind"` // "confirm" | "justification" | "notice"
	Title       string `json:"title"`
	Message     string `json:"message"`
	AppPath     string `json:"app_path"`
	Publisher   string `json:"publisher,omitempty"`
	MinLength   int    `json:"min_length,omitempty"`
	TimeoutSecs int    `json:"timeout_seconds"`
}

// PromptResultBody answers PromptBody — client to server.
type PromptResultBody struct {
	Accepted      bool   `json:"accepted"`
	Justification string `json:"justification,omitempty"`
	TimedOut      bool   `json:"timed_out,omitempty"`
}

// encodeResponse marshals resp. Kept as a named function (rather than every
// call site doing json.Marshal directly) so the one place that could fail is
// one place to log consistently — mirrors reply() in the old pipe_windows.go.
func encodeResponse(resp Response) ([]byte, error) {
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}
	return data, nil
}
