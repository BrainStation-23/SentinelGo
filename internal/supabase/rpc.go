package supabase

import (
	"context"
	"fmt"
)

// CallOption customises a single request.
type CallOption func(*callOptions)

type callOptions struct {
	headers map[string]string
}

// WithHeader adds a request header (e.g. X-Device-ID). It cannot override the
// apikey or Authorization headers.
func WithHeader(key, value string) CallOption {
	return func(o *callOptions) {
		if o.headers == nil {
			o.headers = map[string]string{}
		}
		o.headers[key] = value
	}
}

// RPC calls the PostgREST function fn (POST /rest/v1/rpc/<fn>) with params as
// the JSON body, authenticated with the current access token. On a 2xx
// response the body is decoded into out (if non-nil); anything else returns an
// *APIError carrying the status.
func (c *Client) RPC(ctx context.Context, fn string, params, out any, opts ...CallOption) error {
	body, err := jsonBody(params)
	if err != nil {
		return fmt.Errorf("rpc %s: marshal params: %w", fn, err)
	}
	req, err := c.newJSONRequest(ctx, "/rest/v1/rpc/"+fn, body)
	if err != nil {
		return err
	}

	var o callOptions
	for _, opt := range opts {
		opt(&o)
	}
	for k, v := range o.headers {
		req.Header.Set(k, v)
	}
	c.setCommonHeaders(req, true)

	return doJSON(c.api, req, out)
}
