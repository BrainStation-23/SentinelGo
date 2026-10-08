package supabase

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ErrTooLarge is returned when a response or download exceeds the caller's
// size limit. The data is rejected rather than truncated.
var ErrTooLarge = errors.New("supabase: response exceeds size limit")

// maxErrorBody caps how much of an error response is kept on an APIError.
const maxErrorBody = 4 << 10

// APIError is a non-2xx response from Supabase. It never carries request
// headers or tokens, so it is safe to log.
type APIError struct {
	Status  int    // HTTP status code
	Code    string // PostgREST "code", Storage/GoTrue "error" or "error_code"
	Message string // human-readable message, if the body had one
	Body    string // raw response body, truncated to 4 KB
	Method  string // request method
	Path    string // request path (no host, no query string)
	// RetryAfter is the server's Retry-After hint (0 if absent or invalid),
	// e.g. on a 429 rate limit. It comes from a response header, never from
	// anything the agent sent.
	RetryAfter time.Duration
}

// Error formats as "<METHOD> <path>: status <n>: <code> <message>".
func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s: status %d", e.Method, e.Path, e.Status)
	detail := strings.TrimSpace(e.Code + " " + e.Message)
	if detail == "" {
		detail = strings.TrimSpace(e.Body)
	}
	if detail != "" {
		b.WriteString(": ")
		b.WriteString(detail)
	}
	return b.String()
}

// parseAPIError builds an APIError from an error response. It understands the
// three error shapes Supabase returns:
//
//	PostgREST: {"code":"PGRST301","message":"...","details":...,"hint":...}
//	Storage:   {"statusCode":"400","error":"InvalidJWT","message":"..."}
//	GoTrue:    {"error":"invalid_grant","error_description":"..."}
//	           {"code":401,"error_code":"bad_jwt","msg":"..."}
//
// A body that is not JSON (e.g. a gateway HTML page) only populates Body.
func parseAPIError(method, path string, status int, body []byte) *APIError {
	e := &APIError{Status: status, Method: method, Path: path}
	if len(body) > maxErrorBody {
		e.Body = string(body[:maxErrorBody])
	} else {
		e.Body = string(body)
	}

	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return e
	}
	str := func(key string) string {
		var s string
		if raw, ok := fields[key]; ok && json.Unmarshal(raw, &s) == nil {
			return s
		}
		return ""
	}

	// GoTrue's newer error_code beats its numeric "code"; PostgREST uses a
	// string "code"; Storage and older GoTrue put the code in "error".
	e.Code = firstNonEmpty(str("error_code"), str("code"), str("error"))
	e.Message = firstNonEmpty(str("message"), str("msg"), str("error_description"))
	if e.Message == e.Code {
		e.Message = ""
	}
	return e
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// unauthorizedCodes are error codes that mean the access token itself was
// rejected, whatever HTTP status they arrive with (Storage reports an expired
// JWT as 400 InvalidJWT; GoTrue uses 403 bad_jwt). Provisional until the
// staging probe in #88 confirms the exact list.
var unauthorizedCodes = map[string]bool{
	"PGRST301":   true, // PostgREST: JWT could not be decoded / is invalid or expired
	"PGRST302":   true, // PostgREST: anonymous request with anon role disabled
	"PGRST303":   true, // PostgREST: JWT claims validation failed
	"InvalidJWT": true, // Storage
	"bad_jwt":    true, // GoTrue
}

// notFoundCodes are codes Supabase uses for a missing object or function.
var notFoundCodes = map[string]bool{
	"not_found":    true, // Storage
	"NoSuchKey":    true, // Storage (S3-compatible)
	"NoSuchBucket": true, // Storage (S3-compatible)
	"PGRST202":     true, // PostgREST: function not found
}

// AsAPIError returns the *APIError in err's chain, if any.
func AsAPIError(err error) (*APIError, bool) {
	var e *APIError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// IsUnauthorized reports whether err is a Supabase rejection of the access
// token (HTTP 401, or a JWT error code on any status), meaning a session
// refresh may fix it.
func IsUnauthorized(err error) bool {
	e, ok := AsAPIError(err)
	if !ok {
		return false
	}
	return unauthorizedCodes[e.Code] || e.Status == 401
}

// IsForbidden reports whether err is an authorization denial (HTTP 403 or
// Postgres 42501 insufficient_privilege) for a token that was accepted, so a
// refresh would not help.
func IsForbidden(err error) bool {
	e, ok := AsAPIError(err)
	if !ok || IsUnauthorized(err) {
		return false
	}
	return e.Status == 403 || e.Code == "42501"
}

// IsNotFound reports whether err means the object or function does not exist.
func IsNotFound(err error) bool {
	e, ok := AsAPIError(err)
	if !ok {
		return false
	}
	return e.Status == 404 || notFoundCodes[e.Code]
}

// RetryAfter returns the Retry-After hint carried by err, if any.
func RetryAfter(err error) (time.Duration, bool) {
	if e, ok := AsAPIError(err); ok && e.RetryAfter > 0 {
		return e.RetryAfter, true
	}
	return 0, false
}

// parseRetryAfter parses a Retry-After header: delay-seconds or an HTTP-date.
// Anything unparseable, negative or in the past yields 0.
func parseRetryAfter(h string, now time.Time) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	if secs, err := strconv.ParseInt(h, 10, 64); err == nil {
		// Bound before multiplying so a huge value cannot overflow.
		if secs > int64(maxRetryAfter/time.Second) {
			return maxRetryAfter
		}
		return clampRetryAfter(time.Duration(secs) * time.Second)
	}
	if t, err := http.ParseTime(h); err == nil {
		return clampRetryAfter(t.Sub(now))
	}
	return 0
}

// maxRetryAfter bounds how long a server can ask the agent to wait.
const maxRetryAfter = time.Hour

func clampRetryAfter(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return 0
	case d > maxRetryAfter:
		return maxRetryAfter
	default:
		return d
	}
}

// StatusCode returns the HTTP status carried by err, or 0 when err is not an
// APIError (a network error, timeout or local failure).
func StatusCode(err error) int {
	if e, ok := AsAPIError(err); ok {
		return e.Status
	}
	return 0
}
