package supabase

import (
	"context"
	"fmt"
)

// InvokeFunction calls the edge function name (POST /functions/v1/<name>) with
// body as JSON and decodes a 2xx response into out (if non-nil).
//
// Only the anon apikey is sent, with no bearer: the functions the agent calls
// (agent-login) are how it obtains a session in the first place. The request
// uses the long-lived download transport, so callers bound it with their own
// context deadline.
func (c *Client) InvokeFunction(ctx context.Context, name string, body, out any) error {
	b, err := jsonBody(body)
	if err != nil {
		return fmt.Errorf("invoke %s: marshal body: %w", name, err)
	}
	req, err := c.newJSONRequest(ctx, "/functions/v1/"+name, b)
	if err != nil {
		return err
	}
	c.setCommonHeaders(req, false)
	return doJSON(c.dl, req, out)
}
