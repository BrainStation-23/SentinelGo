# Design — Enterprise Endpoint Privilege Management (EPM)

## 1. Summary

EPM adds a policy-gated privilege-elevation capability to the existing SentinelGo agent. The design splits cleanly into a **platform-agnostic core** (policy model, evaluation engine, hashing, audit, storage, distribution via the existing task pipeline) and a **platform-specific enforcement layer** (session discovery, token/credential handling, process launch, local IPC), following the same `_windows.go` / `_linux.go` / `_darwin.go` split already used throughout `internal/osinfo`, `internal/winsec`, and `internal/service/task`.

```
                         ┌─────────────────────────────┐
                         │   Supabase (policy source)  │
                         └──────────────┬──────────────┘
                                        ▼
                         ┌─────────────────────────────┐
                         │  internal/service/task       │  existing pipeline, reused as-is
                         │  (polling, retry, watchdog)  │
                         └──────────────┬──────────────┘
                                        │ Task{Slug:"epm-policy-sync"}
                                        ▼
                         ┌─────────────────────────────┐
                         │  native.epmPolicySyncHandler │  Phase 0 (this doc's focus)
                         └──────────────┬──────────────┘
                                        │ UpsertRules / DeleteRulesNotIn
                                        ▼
                         ┌─────────────────────────────┐
                         │  internal/store.EPMStore     │  SQLite: epm_policies, epm_audit_log
                         │  (sentinelgo_epm.db)         │
                         └──────────────┬──────────────┘
                                        │ GetRules
                                        ▼
                         ┌─────────────────────────────┐
                         │  internal/epm.Engine         │  platform-agnostic decision
                         │  (policy.go, hash.go)        │
                         └──────────────┬──────────────┘
                                        │ ElevationResponse
                                        ▼
       ┌────────────────────────────────┴────────────────────────────────┐
       │                Platform enforcement layer (Phase 1+)             │
       │  Windows: session_windows / token_windows / launcher_windows /   │
       │           pipe_windows / codesign_windows                        │
       │  Linux:   session_linux / launcher_linux (setresuid+execve) /    │
       │           socket_linux                                           │
       │  macOS:   session_darwin / launcher_darwin (AuthServices) /       │
       │           socket_darwin                                          │
       └────────────────────────────────┬────────────────────────────────┘
                                        │ AuditEntry
                                        ▼
                         ┌─────────────────────────────┐
                         │  internal/epm.Auditor         │  writes through EPMStore,
                         │  (audit.go)                   │  synced by existing log
                         └─────────────────────────────┘  upload pipeline
```

## 2. Phase 0 — Shared Foundation (this implementation pass)

Phase 0 builds every platform-agnostic piece so later phases only add enforcement code. Nothing in Phase 0 changes agent behavior when `enable_epm` is `false`, and nothing in Phase 0 touches an existing file's behavior beyond additive fields/constants.

### 2.1 `internal/config` — feature flag & sync interval

Two additive fields on the existing `Config` struct (`internal/config/config.go`), following the exact `Duration` + `Get*Interval()` pattern already used for `TaskPollingInterval`/`GetTaskPollingInterval()`:

```go
EPMEnabled             bool     `json:"enable_epm"`
EPMPolicySyncInterval  Duration `json:"epm_policy_sync_interval"`
```

`GetEPMPolicySyncInterval() time.Duration` defaults to 5 minutes when the stored value is zero, matching `GetSoftwareInfoUpdateInterval`'s fallback style. No default is set in `Load()`'s literal struct for `EPMEnabled` (zero value `false` is the correct default — mirrors how new opt-in features should ship). `EPMPolicySyncInterval` does get a default in `Load()` (`Duration(5 * time.Minute)`) so a fresh config.json is self-documenting, consistent with how `TaskPollingInterval` is defaulted today.

### 2.2 `internal/store/epm.go` — local durable cache

New file, new package-level constant `EPMDBName = "sentinelgo_epm.db"`, separate database file from `software`/`services`/`tasks` (FR-6.2). Two tables:

```sql
CREATE TABLE IF NOT EXISTS epm_policies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    app_path    TEXT NOT NULL DEFAULT '',
    app_hash    TEXT NOT NULL DEFAULT '',
    publisher   TEXT NOT NULL DEFAULT '',
    user_id     TEXT NOT NULL DEFAULT '',
    decision    TEXT NOT NULL,              -- 'allow' | 'deny'
    expires_at  TEXT NOT NULL DEFAULT '',    -- RFC3339, empty = never
    priority    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE(app_path, app_hash, publisher, user_id)
);

CREATE TABLE IF NOT EXISTS epm_audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id   TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    app_path     TEXT NOT NULL DEFAULT '',
    app_hash     TEXT NOT NULL DEFAULT '',
    decision     TEXT NOT NULL,
    policy_id    INTEGER,
    launched_at  TEXT NOT NULL,
    synced       INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_epm_audit_request ON epm_audit_log(request_id);
CREATE INDEX IF NOT EXISTS idx_epm_audit_synced ON epm_audit_log(synced);
```

`EPMStore` mirrors `SoftwareStore`'s shape exactly:

- `NewEPMStore(dbPath string) (*EPMStore, error)` — opens via `store.Open` + `store.Migrate`, same as every other store.
- `UpsertRules(rules []models... /* PolicyRule */) error` — `ON CONFLICT` upsert keyed on the same tuple as the unique index, transaction-wrapped like `SoftwareStore.Upsert`.
- `DeleteRulesNotIn(activeIDs []string) error` — prunes rows whose natural key isn't in the latest full payload, same "full replace" semantics as `SoftwareStore.DeleteNotIn` (empty slice wipes the table, matching FR-3.2's "reflects the latest full rule set" requirement).
- `GetRules() ([]PolicyRule, error)` — used by `internal/epm.Engine` at evaluation time.
- `InsertAuditLog(entry AuditEntry) error`, `GetUnsyncedAuditLogs(limit int) ([]AuditEntry, error)`, `MarkAuditLogSynced(ids []int64) error` — same insert/query/mark-done shape as `AuditLogStore`'s pending/upload cycle in `internal/store/auditlogs.go`.
- `Close() error`.

This store implements the `epm.AuditSink` interface (section 2.5) structurally — no import cycle, since `internal/epm` depends on `internal/store` only through the interface, not a concrete type.

### 2.3 `internal/models` — one additive constant

```go
LogCategoryEPM = "EPM_ELEVATION_LOG"
```

Added alongside the existing `LogCategory*` constants in `internal/models/model.go`. No existing constant or type changes (FR-5.3, FR-6.1).

### 2.4 `internal/epm/policy.go` — platform-agnostic decision engine

Types:

```go
type PolicyDecision string
const (
    DecisionAllow PolicyDecision = "allow"
    DecisionDeny  PolicyDecision = "deny"
)

type PolicyRule struct {
    ID         string
    AppPath    string    // exact path, or glob (contains * or ?), or "" if matching by hash/publisher only
    AppHash    string    // SHA-256, lowercase hex, "" if not hash-based
    Publisher  string    // signer/publisher identity, "" if not publisher-based
    UserID     string    // user this rule applies to; "" = wildcard (any user)
    Decision   PolicyDecision
    ExpiresAt  time.Time // zero value = never expires
    Priority   int
}

type ElevationRequest struct {
    RequestID string
    UserID    string
    AppPath   string
    AppHash   string
    Publisher string
    Now       time.Time // injected for testability
}

type ElevationResponse struct {
    Allowed  bool
    PolicyID string
    Reason   string
}

type Engine struct {
    rules []PolicyRule
}

func NewEngine(rules []PolicyRule) *Engine
func (e *Engine) Evaluate(req ElevationRequest) ElevationResponse
```

`Evaluate` walks `e.rules`, skips any rule where `!rule.ExpiresAt.IsZero() && rule.ExpiresAt.Before(req.Now)`, skips any rule whose `UserID` is set and doesn't match `req.UserID`, computes a match-tier score per FR-2.2 (hash=300, publisher=200, exact path=100, glob=50, wildcard/no-target=10), and picks the highest `tier, then rule.Priority` combination. No match → `ElevationResponse{Allowed: false, Reason: "no matching policy (default deny)"}`. This mirrors the priority table in the task brief exactly and keeps the engine a pure function of `(rules, request)` with no I/O, so it is trivially unit-testable and identical on every OS.

### 2.5 `internal/epm/hash.go`

```go
func ComputeFileHash(path string) (string, error)
```

Streams the file through `crypto/sha256` (stdlib, no cgo) and returns lowercase hex — same primitive already used for update-binary verification in `internal/updater`, reused here for app identity instead of release integrity.

### 2.6 `internal/epm/audit.go`

```go
type AuditEntry struct {
    RequestID  string
    UserID     string
    AppPath    string
    AppHash    string
    Decision   PolicyDecision
    PolicyID   string
    LaunchedAt time.Time
}

type AuditSink interface {
    InsertAuditLog(entry AuditEntry) error
}

type Auditor struct {
    sink AuditSink
}

func NewAuditor(sink AuditSink) *Auditor
func (a *Auditor) Log(entry AuditEntry) error
```

`internal/store.EPMStore` satisfies `AuditSink` structurally (same duck-typing pattern used for `swsvc.Catalog` in `sync_software.go`). This keeps `internal/epm` free of any dependency on `database/sql` or `modernc.org/sqlite`, so the policy/audit types stay usable from test code and from every platform-specific launcher without pulling in storage machinery.

### 2.7 `internal/service/task/native/epm_policy_sync.go`

Follows `sync_software.go`'s handler shape:

```go
type epmPolicySyncHandler struct{}
func init() { Register(&epmPolicySyncHandler{}) }
func (h *epmPolicySyncHandler) Slugs() []string { return []string{"epm-policy-sync"} }
func (h *epmPolicySyncHandler) Run(ctx context.Context, cfg *config.Config, task taskstore.Task) (string, error)
```

`Run` marshals `task.Payload["rules"]` back to JSON and unmarshals into `[]epm.PolicyRule` (same round-trip idiom as `executor.go:226`'s `json.Marshal(task.Payload)`, since `Payload` is a loosely-typed `map[string]interface{}` coming off JSON already). It opens `store.NewEPMStore(filepath.Join(filepath.Dir(cfg.Path), store.EPMDBName))`, calls `UpsertRules` with the parsed rules, then `DeleteRulesNotIn` with their IDs so a full-payload sync prunes anything the server no longer sends (FR-3.2). Errors from parsing or storage are wrapped and returned; an empty rule list is treated as "prune everything" exactly like `SoftwareStore.DeleteNotIn(nil)`.

This handler is registered unconditionally (registration has no side effects and costs nothing when EPM is disabled); whether it ever *runs* is gated by whether the server ever assigns an `epm-policy-sync` task, which in turn is an operational decision, not something the agent needs to gate on `cfg.EPMEnabled` inside the handler itself. (Later phases may add an explicit `if !cfg.EPMEnabled { skip }` guard once the scheduler wires up automatic sync — out of scope for Phase 0, which only adds the handler.)

## 3. Phase 1+ — Platform Enforcement Layers (design intent, implemented in later passes)

Not implemented in this pass; captured here so Phase 0's interfaces are shaped correctly for what comes next.

### 3.1 Windows

- `session_windows.go`: `WTSEnumerateSessions` / `WTSGetActiveConsoleSessionId` to find the interactive session; `WTSQueryUserToken` to get that session's user token.
- `token_windows.go`: `DuplicateTokenEx` (primary token, `SecurityImpersonation` → `TokenPrimary`), `CreateEnvironmentBlock` for the user's environment.
- `launcher_windows.go`: `CreateProcessAsUser` with the duplicated token; requires `SeAssignPrimaryTokenPrivilege`/`SeIncreaseQuotaPrivilege` on the SYSTEM service token, which the agent already holds when installed as a Windows service.
- `pipe_windows.go`: Named Pipe (`\\.\pipe\sentinelgo-epm`) server with an ACL restricting connections to authenticated users; one request/response per elevation attempt.
- `codesign_windows.go`: Authenticode verification (`WinVerifyTrust`) feeding `Publisher` into `ElevationRequest`.
- `cmd/sentinelgo-epm/main_windows.go`: unprivileged CLI/tray client run in the user's own session; talks to the pipe, never touches SYSTEM state directly.

### 3.2 Linux / macOS (sketched for continuity, not this pass)

- Session discovery via `loginctl`/`utmp` (Linux) or `SCDynamicStoreCopyConsoleUser` (macOS).
- Launch via `fork`+`setresuid`+`execve` (Linux) or Authorization Services (macOS).
- IPC via Unix Domain Socket, credential-checked with `SO_PEERCRED` (Linux) / equivalent.

## 4. Data Flow Summary (Phase 0 slice only)

1. Supabase assigns a task with `slug = "epm-policy-sync"` and `payload.rules = [...]`.
2. Existing task-polling pipeline persists and later executes it — no changes to that pipeline.
3. `epmPolicySyncHandler.Run` parses the payload, calls `EPMStore.UpsertRules` + `DeleteRulesNotIn`.
4. `internal/epm.Engine` (used later by the enforcement layer) is constructed by calling `EPMStore.GetRules()` and can evaluate `ElevationRequest`s.
5. Any evaluation result is logged via `Auditor.Log`, which calls `EPMStore.InsertAuditLog`; a not-yet-built sync task (mirroring the existing audit-log upload cycle) will later call `GetUnsyncedAuditLogs` / `MarkAuditLogSynced`.

## 5. Testing Strategy

- `internal/epm`: pure unit tests, no I/O — table-driven tests over `Engine.Evaluate` covering each priority tier, expiry, user-scoping, and default-deny; `ComputeFileHash` tested against a known SHA-256 fixture.
- `internal/store/epm_test.go`: in-memory SQLite (`:memory:"`) tests mirroring `software_test.go` — upsert/get round trip, prune-not-in, audit insert/get-unsynced/mark-synced.
- `internal/service/task/native/epm_policy_sync_test.go`: white-box tests in `package native` (not `native_test`) following `sync_software_test.go`'s seam-stubbing style, using a temp-dir config and a real (in-file) `EPMStore` since the handler opens its own store per run.
- Cross-platform: `make verify-cross` must stay green — Phase 0 has no `_windows.go`/`_linux.go`/`_darwin.go` files at all, so this is trivially satisfied; it becomes load-bearing starting Phase 1.
