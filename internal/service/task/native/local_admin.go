package native

import (
	"context"
	"path/filepath"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/localadmin"
	"sentinelgo/internal/taskstore"
)

// Slugs of the console's commands (Compliance-OS#715). The executor picks a
// native handler by slug before it falls back to scripts, so this agent runs
// them natively and older agents keep running the commands' scripts.
const (
	localAdminAddSlug    = "local-admin-add"
	localAdminRemoveSlug = "local-admin-remove"
)

const localAdminTimeout = 3 * time.Minute

// localAdminApplyFn applies one request; tests replace it.
var localAdminApplyFn = func(ctx context.Context, cfg *config.Config, add bool, r localadmin.Request) (localadmin.Outcome, error) {
	m, err := localadmin.ForConfigDir(filepath.Dir(cfg.Path))
	if err != nil {
		return localadmin.Outcome{}, err
	}
	return m.Apply(ctx, add, r)
}

// localAdminHandler adds an account to, or removes it from, the local
// administrators (#388). An add with expires_at is also removed by the agent
// itself at that time, even offline.
type localAdminHandler struct{}

func init() { Register(&localAdminHandler{}) }

func (h *localAdminHandler) Slugs() []string {
	return []string{localAdminAddSlug, localAdminRemoveSlug}
}

// PostRun reports the new membership (local_admin_members, admin_grants) at
// once: the console confirms a grant from it.
func (h *localAdminHandler) PostRun() []string { return []string{"sync-inventory"} }

func (h *localAdminHandler) Run(ctx context.Context, cfg *config.Config, task taskstore.Task) (string, error) {
	add := task.Slug == localAdminAddSlug
	r, err := localadmin.ParseRequest(task.Payload, add)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, localAdminTimeout)
	defer cancel()
	out, err := localAdminApplyFn(ctx, cfg, add, r)
	if err != nil {
		return "", err
	}
	return out.JSON(), nil
}
