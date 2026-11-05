package dlp

import (
	"context"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

const rpcRequestException = "agent_request_dlp_exception"

// ExceptionRequest is agent_request_dlp_exception's p_request
// (Compliance-OS#581): {policy_id, channel, event_id?, user, file: {sha256,
// name}, justification}. The server keeps one pending request per device,
// user, policy, channel and file, and at most 50 per device.
type ExceptionRequest struct {
	PolicyID      string        `json:"policy_id"`
	Channel       string        `json:"channel"`
	EventID       string        `json:"event_id,omitempty"`
	User          string        `json:"user,omitempty"`
	File          ExceptionFile `json:"file"`
	Justification string        `json:"justification"`
}

// ExceptionFile identifies the blocked file; Name follows the evidence
// mode (nil leaves it out).
type ExceptionFile struct {
	SHA256 string  `json:"sha256"`
	Name   *string `json:"name,omitempty"`
}

// maxRequestBytes is the server's limit on p_request.
const maxRequestBytes = 8 << 10

// RequestException asks IT for an exception to a blocked file. The
// justification is personal data: it is sent, never logged.
func (s *Service) RequestException(ctx context.Context, r ExceptionRequest) error {
	if n := utf8.RuneCountInString(r.Justification); n < 1 || n > 1000 {
		return fmt.Errorf("%s: justification must be 1 to 1000 characters", rpcRequestException)
	}
	if len(r.File.SHA256) != 64 {
		return fmt.Errorf("%s: the file's sha256 is required", rpcRequestException)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(b) > maxRequestBytes {
		return fmt.Errorf("%s: request too large", rpcRequestException)
	}
	var raw json.RawMessage
	return s.client().RPC(ctx, rpcRequestException, map[string]json.RawMessage{"p_request": b}, &raw, s.deviceHeader())
}
