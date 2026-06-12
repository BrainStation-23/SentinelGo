Add a new native task handler to this project. Arguments: $ARGUMENTS

The first token of the arguments is the task slug (e.g. `collect-logs`). Everything after it is the human-readable description. If no arguments are provided, ask the user for the slug and description before proceeding.

## Pattern Reference

Native task handlers live in `internal/service/task/native/`. Each handler is one file in that package. Adding a new file is the **only** change required — no other files need to be modified.

**Key files to understand the pattern:**
- `internal/service/task/native/registry.go` — defines `Handler` and `PostRunner` interfaces
- `internal/service/task/native/sync_inventory.go` — cleanest minimal example
- `internal/service/task/native/sync_software.go` — example that calls existing services

**Interfaces (defined in `registry.go`):**
```go
// Required — every handler must implement both methods
type Handler interface {
    Slugs() []string
    Run(ctx context.Context, cfg *config.Config, task taskstore.Task) (string, error)
}

// Optional — implement this to auto-run other handlers after success
type PostRunner interface {
    PostRun() []string  // return slugs to run after Run() succeeds
}
```

**Self-registration:** `func init() { Register(&myHandler{}) }` — runs automatically at startup. No central list to update.

## Steps

1. **Read** `internal/service/task/native/sync_inventory.go` to see the exact file structure.

2. **Derive the filename** from the slug: replace every `-` with `_`, append `.go`.
   - `collect-logs` → `collect_logs.go`
   - `sync-software` → `sync_software.go`

3. **Derive the struct name** from the slug: convert to UpperCamelCase and append `Handler`.
   - `collect-logs` → `CollectLogsHandler` (but keep it unexported: `collectLogsHandler`)

4. **Create** `internal/service/task/native/<filename>` with this structure:
```go
package native

import (
    "context"
    "fmt"

    "sentinelgo/internal/config"
    "sentinelgo/internal/taskstore"
)

type <camelSlug>Handler struct{}

func init() { Register(&<camelSlug>Handler{}) }

func (h *<camelSlug>Handler) Slugs() []string {
    return []string{"<slug>"}
}

// <description>
func (h *<camelSlug>Handler) Run(ctx context.Context, cfg *config.Config, _ taskstore.Task) (string, error) {
    // TODO: implement
    return "", fmt.Errorf("<slug>: not implemented")
}
```

5. **Ask the user:** "Should this handler automatically trigger any post-run tasks after it succeeds (e.g. `sync-inventory`)?" If yes, add:
```go
func (h *<camelSlug>Handler) PostRun() []string {
    return []string{"<post-run-slug>"}
}
```

6. **Run** `go build ./internal/service/task/native/...` to confirm the new file compiles without errors.

7. **Tell the user** the scaffold is ready and point them to implement the `Run` body. Reference `internal/service/task/native/sync_software.go` as an example of a handler that opens a local store and calls an RPC service, or `internal/service/task/native/sync_inventory.go` for one that collects system info. Both show the correct pattern for using `cfg *config.Config` to access Supabase credentials and config paths.
