package adminpassword

import (
	"context"
	"encoding/json"
	"testing"

	"sentinelgo/internal/supabase"
)

type fakeRPC struct {
	fn     string
	params []byte
	answer string
}

func (f *fakeRPC) RPC(_ context.Context, fn string, params, out any, _ ...supabase.CallOption) error {
	f.fn = fn
	f.params, _ = json.Marshal(params)
	if p, ok := out.(*[]byte); ok {
		*p = []byte(f.answer)
	}
	return nil
}

func TestClient_FetchPolicyParams(t *testing.T) {
	f := &fakeRPC{answer: `{"changed":false,"rotate_after":null}`}
	c := NewClient(func() RPC { return f })
	if _, err := c.FetchPolicy(context.Background(), "", nil); err != nil {
		t.Fatal(err)
	}
	if f.fn != RPCGetPolicy || string(f.params) != `{"p_known_version":null,"p_status":null}` {
		t.Fatalf("%s %s", f.fn, f.params)
	}
	if _, err := c.FetchPolicy(context.Background(), "v1", &Status{SchemaVersion: 1, State: StateActive}); err != nil {
		t.Fatal(err)
	}
	var p struct {
		Known  string `json:"p_known_version"`
		Status Status `json:"p_status"`
	}
	if err := json.Unmarshal(f.params, &p); err != nil || p.Known != "v1" || p.Status.State != StateActive {
		t.Fatalf("params %s (%v)", f.params, err)
	}
}

func TestClient_EscrowAndConfirmParams(t *testing.T) {
	f := &fakeRPC{answer: `{"accepted":true}`}
	c := NewClient(func() RPC { return f })
	if err := c.Escrow(context.Background(), Escrow{RotationID: "r", AccountSID: "S-1-5-21-1-2-3-500", Password: "pw", Reason: ReasonInitial}); err != nil {
		t.Fatal(err)
	}
	var e struct {
		P map[string]any `json:"p_payload"`
	}
	if err := json.Unmarshal(f.params, &e); err != nil || f.fn != RPCEscrow || e.P["password"] != "pw" || e.P["rotation_id"] != "r" || e.P["reason"] != ReasonInitial {
		t.Fatalf("%s %s", f.fn, f.params)
	}
	if err := c.Confirm(context.Background(), Confirm{RotationID: "r", State: ConfirmFailed, ErrorCode: ErrCodeNotApplied}); err != nil {
		t.Fatal(err)
	}
	if f.fn != RPCConfirm || string(f.params) != `{"p_payload":{"rotation_id":"r","state":"failed","error_code":"not_applied"}}` {
		t.Fatalf("%s %s", f.fn, f.params)
	}
}
