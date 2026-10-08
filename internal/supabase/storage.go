package supabase

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// StorageURL returns the Storage object URL for bucket/objectPath. With
// authenticatedPrefix the path is /object/authenticated/<bucket>/..., which is
// how private buckets (command-scripts) are read; without it,
// /object/<bucket>/... (agent-releases). The parts are concatenated verbatim,
// with no escaping, so URLs stay byte-identical to the ones the agent has
// always requested — a changed updater URL would strand the fleet.
func (c *Client) StorageURL(bucket, objectPath string, authenticatedPrefix bool) string {
	prefix := "/storage/v1/object/"
	if authenticatedPrefix {
		prefix += "authenticated/"
	}
	return c.baseURL + prefix + bucket + "/" + objectPath
}

// Download streams a Storage object into w and returns the number of bytes
// written. A response larger than limit bytes (when limit > 0) fails with
// ErrTooLarge after writing at most limit bytes; the caller must discard what
// was written. A non-200 response returns an *APIError.
func (c *Client) Download(ctx context.Context, bucket, objectPath string, authenticatedPrefix bool, w io.Writer, limit int64) (int64, error) {
	url := c.StorageURL(bucket, objectPath, authenticatedPrefix)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("build download request: %w", err)
	}
	c.setCommonHeaders(req, true)

	resp, err := c.dl.Do(req)
	if err != nil {
		return 0, fmt.Errorf("GET %s: %w", req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return 0, parseAPIError(http.MethodGet, req.URL.Path, resp.StatusCode, body)
	}

	if limit <= 0 {
		n, err := io.Copy(w, resp.Body)
		if err != nil {
			return n, fmt.Errorf("GET %s: %w", req.URL.Path, err)
		}
		return n, nil
	}
	lw := &limitedWriter{w: w, remaining: limit}
	n, err := io.Copy(lw, resp.Body)
	if err != nil {
		if lw.exceeded {
			return n, fmt.Errorf("GET %s: %w (limit %d bytes)", req.URL.Path, ErrTooLarge, limit)
		}
		return n, fmt.Errorf("GET %s: %w", req.URL.Path, err)
	}
	return n, nil
}

// limitedWriter forwards at most remaining bytes to w and then fails, so an
// oversized download is rejected instead of being silently truncated.
type limitedWriter struct {
	w         io.Writer
	remaining int64
	exceeded  bool
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.remaining {
		l.exceeded = true
		n, err := l.w.Write(p[:l.remaining])
		l.remaining -= int64(n)
		if err != nil {
			return n, err
		}
		return n, ErrTooLarge
	}
	n, err := l.w.Write(p)
	l.remaining -= int64(n)
	return n, err
}
