package ruleset

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"sentinelgo/internal/supabase"
	"sentinelgo/internal/yara"
)

type fakeSupabase struct {
	params   []map[string]json.RawMessage
	reply    string
	rpcErr   error
	bucket   string
	path     string
	auth     bool
	limit    int64
	dlErr    error
	dlObject string
}

func (f *fakeSupabase) RPC(_ context.Context, fn string, params, out any, _ ...supabase.CallOption) error {
	if fn != yara.RPCGetRuleset {
		return errors.New("wrong rpc " + fn)
	}
	data, _ := json.Marshal(params)
	var p map[string]json.RawMessage
	_ = json.Unmarshal(data, &p)
	f.params = append(f.params, p)
	if f.rpcErr != nil {
		return f.rpcErr
	}
	*(out.(*[]byte)) = []byte(f.reply)
	return nil
}

func (f *fakeSupabase) Download(_ context.Context, bucket, objectPath string, auth bool, w io.Writer, limit int64) (int64, error) {
	f.bucket, f.path, f.auth, f.limit = bucket, objectPath, auth, limit
	if f.dlErr != nil {
		return 0, f.dlErr
	}
	n, err := io.WriteString(w, f.dlObject)
	return int64(n), err
}

func TestClient_FetchRuleset(t *testing.T) {
	f := &fakeSupabase{reply: `{"changed": false}`}
	c := NewClient(func() Supabase { return f })
	res, err := c.FetchRuleset(context.Background(), "", nil)
	if err != nil || res.Changed {
		t.Fatalf("unchanged: %+v %v", res, err)
	}
	if string(f.params[0]["p_known_version"]) != `""` || string(f.params[0]["p_status"]) != "null" {
		t.Errorf("params %s %s", f.params[0]["p_known_version"], f.params[0]["p_status"])
	}
	f.reply = `{"changed": true, "bundle": {"schema_version": 1, "version": "v2"}}`
	st := &yara.Status{State: yara.StateOK, AppliedVersion: "v1"}
	res, err = c.FetchRuleset(context.Background(), "v1", st)
	if err != nil || !res.Changed || bundleVersion(res.Raw) != "v2" {
		t.Fatalf("changed: %+v %v", res, err)
	}
	var sent yara.Status
	if err := json.Unmarshal(f.params[1]["p_status"], &sent); err != nil || sent.AppliedVersion != "v1" || sent.Rulesets == nil {
		t.Errorf("status %s: %v", f.params[1]["p_status"], err)
	}
	f.reply = `{"changed": true}`
	if _, err := c.FetchRuleset(context.Background(), "v1", nil); err == nil {
		t.Error("changed without a bundle accepted")
	}
	f.rpcErr = &supabase.APIError{Status: 400, Code: yara.SQLStateInvalid}
	if _, err := c.FetchRuleset(context.Background(), "v1", st); !errors.Is(err, ErrStatusRejected) {
		t.Errorf("22023 with a status: %v", err)
	}
	if _, err := c.FetchRuleset(context.Background(), "v1", nil); errors.Is(err, ErrStatusRejected) {
		t.Errorf("22023 without a status is not a status rejection: %v", err)
	}
	f.rpcErr = &supabase.APIError{Status: 401}
	if _, err := c.FetchRuleset(context.Background(), "v1", nil); !supabase.IsUnauthorized(err) {
		t.Errorf("401 not passed on for DoWithAuthRetry: %v", err)
	}
}

func TestClient_DownloadRuleset(t *testing.T) {
	f := &fakeSupabase{dlObject: "rule a { condition: true }"}
	c := NewClient(func() Supabase { return f })
	var got []byte
	w := writerFunc(func(p []byte) (int, error) { got = append(got, p...); return len(p), nil })
	if err := c.DownloadRuleset(context.Background(), "yara/default/x/1.yar", w, 100); err != nil {
		t.Fatal(err)
	}
	if f.bucket != Bucket || f.path != "yara/default/x/1.yar" || !f.auth || f.limit != 100 || string(got) != f.dlObject {
		t.Errorf("download %+v %q", f, got)
	}
	f.dlErr = &supabase.APIError{Status: 404}
	if err := c.DownloadRuleset(context.Background(), "p", w, 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("404: %v", err)
	}
	f.dlErr = supabase.ErrTooLarge
	if err := c.DownloadRuleset(context.Background(), "p", w, 1); !errors.Is(err, ErrTooLarge) {
		t.Errorf("too large: %v", err)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
