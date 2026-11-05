package native

import (
	"context"
	"errors"
	"slices"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/localadmin"
	"sentinelgo/internal/taskstore"
)

func TestLocalAdminHandler(t *testing.T) {
	h := Find(localAdminAddSlug)
	if h == nil || Find(localAdminRemoveSlug) != h {
		t.Fatal("local-admin slugs not registered")
	}
	if pr, ok := h.(PostRunner); !ok || !slices.Equal(pr.PostRun(), []string{"sync-inventory"}) {
		t.Fatal("no sync-inventory post-run")
	}

	var gotAdd bool
	var got localadmin.Request
	orig := localAdminApplyFn
	t.Cleanup(func() { localAdminApplyFn = orig })
	localAdminApplyFn = func(_ context.Context, _ *config.Config, add bool, r localadmin.Request) (localadmin.Outcome, error) {
		gotAdd, got = add, r
		return localadmin.Outcome{Success: true, State: localadmin.StateAdded, Member: r.Member}, nil
	}
	note, err := h.Run(context.Background(), &config.Config{}, taskstore.Task{Slug: localAdminAddSlug,
		Payload: map[string]interface{}{"member": "alice", "source": "local", "sign_out": false, "grant_id": "a1b2"}})
	if err != nil || !gotAdd || got.Member != "alice" || note != `{"Success":true,"State":"added","Member":"alice"}` {
		t.Fatalf("add: %q %v %+v", note, err, got)
	}

	_, err = h.Run(context.Background(), &config.Config{}, taskstore.Task{Slug: localAdminRemoveSlug,
		Payload: map[string]interface{}{"member": "alice", "sign_out": true}})
	if err != nil || gotAdd || !got.SignOut {
		t.Fatalf("remove: %v %+v", err, got)
	}

	if _, err := h.Run(context.Background(), &config.Config{}, taskstore.Task{Slug: localAdminAddSlug, Payload: map[string]interface{}{}}); err == nil {
		t.Fatal("empty payload accepted")
	}

	localAdminApplyFn = func(context.Context, *config.Config, bool, localadmin.Request) (localadmin.Outcome, error) {
		return localadmin.Outcome{}, localadmin.ErrBuiltinAdmin
	}
	if _, err := h.Run(context.Background(), &config.Config{}, taskstore.Task{Slug: localAdminRemoveSlug,
		Payload: map[string]interface{}{"member": "Administrator"}}); !errors.Is(err, localadmin.ErrBuiltinAdmin) {
		t.Fatalf("guard error lost: %v", err)
	}
}
