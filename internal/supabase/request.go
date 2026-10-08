package supabase

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"sentinelgo/internal/sanitize"
)

// jsonBody marshals v for a request body, stripping NUL escapes Postgres
// rejects. A nil v becomes an empty JSON object.
func jsonBody(v any) ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return sanitize.StripJSONNUL(b), nil
}

// newJSONRequest builds a JSON POST to path (which may carry a query string).
func (c *Client) newJSONRequest(ctx context.Context, path string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// doJSON sends req and, on a 2xx response, decodes the body into out (when
// out is non-nil and the body is not empty). If out is a *[]byte it receives
// the raw body undecoded, so a caller can treat an unparseable success body as
// non-fatal. A non-2xx response becomes an *APIError; transport failures are
// wrapped with the method and path.
func doJSON(hc *http.Client, req *http.Request, out any) error {
	method, path := req.Method, req.URL.Path
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return responseError(method, path, resp, body)
	}

	body, err := readLimited(resp.Body, maxResponseBytes)
	if err != nil {
		return fmt.Errorf("%s %s: read response: %w", method, path, err)
	}
	if raw, ok := out.(*[]byte); ok {
		*raw = body
		return nil
	}
	if out == nil || len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%s %s: decode response: %w", method, path, err)
	}
	return nil
}

// readLimited reads all of r, failing with ErrTooLarge beyond limit bytes.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, ErrTooLarge
	}
	return b, nil
}

// responseError builds the APIError for a non-2xx response, including the
// server's Retry-After hint.
func responseError(method, path string, resp *http.Response, body []byte) *APIError {
	e := parseAPIError(method, path, resp.StatusCode, body)
	e.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
	return e
}
