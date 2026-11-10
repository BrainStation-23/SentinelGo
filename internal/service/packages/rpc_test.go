package packages

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"sentinelgo/internal/supabase"
)

type fakeRPC struct {
	fn     string
	params any
	resp   string
	err    error
}

func (f *fakeRPC) RPC(_ context.Context, fn string, params, out any, _ ...supabase.CallOption) error {
	f.fn, f.params = fn, params
	if f.err != nil {
		return f.err
	}
	if raw, ok := out.(*[]byte); ok {
		*raw = []byte(f.resp)
	}
	return nil
}

func paramsJSON(t *testing.T, p any) string {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestFetchSettings(t *testing.T) {
	r := &fakeRPC{resp: `{"changed":true,"settings":{"version":"abc","enabled":true,"project_scan":false,"roots":["/srv"],"max_depth":6}}`}
	c := NewClient(func() RPC { return r })

	s, changed, err := c.FetchSettings(context.Background(), "")
	if err != nil || !changed || s.Version != "abc" || !s.Enabled || s.MaxDepth != 6 || len(s.Roots) != 1 {
		t.Fatalf("FetchSettings = %+v, %v, %v", s, changed, err)
	}
	if r.fn != rpcGetSettings || paramsJSON(t, r.params) != `{"p_known_version":null}` {
		t.Errorf("call = %s %s", r.fn, paramsJSON(t, r.params))
	}

	r.resp = `{"changed":false}`
	_, changed, err = c.FetchSettings(context.Background(), "abc")
	if err != nil || changed || paramsJSON(t, r.params) != `{"p_known_version":"abc"}` {
		t.Errorf("unchanged = %v, %v, params %s", changed, err, paramsJSON(t, r.params))
	}

	for _, bad := range []string{`{"changed":true}`, `not json`, `{"changed":true,"settings":{"enabled":true}}`} {
		r.resp = bad
		if _, _, err := c.FetchSettings(context.Background(), ""); err == nil {
			t.Errorf("response %s: no error", bad)
		}
	}

	r.err = errors.New("down")
	if _, _, err := c.FetchSettings(context.Background(), ""); err == nil {
		t.Error("RPC error not returned")
	}
}

func TestEnqueue_Payload(t *testing.T) {
	r := &fakeRPC{resp: `{"success":true,"enqueued":true}`}
	c := NewClient(func() RPC { return r })
	u := Upload{Snapshot: snapshotFull, SnapshotID: "id", Part: 1, Parts: 2, CollectedAt: "2026-11-10T08:00:00Z",
		Packages: []Package{{Ecosystem: EcosystemNPM, Name: "keyv", Version: "4.5.4", Scope: ScopeGlobal, Location: "/x", User: "alice"}}}
	if err := c.Enqueue(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	want := `{"payload":{"snapshot":"full","snapshot_id":"id","part":1,"parts":2,"collected_at":"2026-11-10T08:00:00Z",` +
		`"packages":[{"ecosystem":"npm","name":"keyv","version":"4.5.4","scope":"global","location":"/x","user":"alice"}]}}`
	if r.fn != rpcEnqueue || paramsJSON(t, r.params) != want {
		t.Errorf("call = %s\n%s\nwant\n%s", r.fn, paramsJSON(t, r.params), want)
	}
}

func TestEnqueue_RejectedPayloadIsDropped(t *testing.T) {
	r := &fakeRPC{err: &supabase.APIError{Status: 400, Code: "22023", Message: "bad"}}
	c := NewClient(func() RPC { return r })
	if err := c.Enqueue(context.Background(), Upload{Snapshot: snapshotDelta}); err != nil {
		t.Errorf("a rejected payload should be dropped, got %v", err)
	}
}

func TestEnqueue_UnauthorizedPropagates(t *testing.T) {
	r := &fakeRPC{err: &supabase.APIError{Status: 401, Message: "JWT expired"}}
	c := NewClient(func() RPC { return r })
	if err := c.Enqueue(context.Background(), Upload{}); !supabase.IsUnauthorized(err) {
		t.Errorf("401 = %v, want it returned for DoWithAuthRetry", err)
	}
}
