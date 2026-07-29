# SentinelOps EPM – Frontend & Database Implementation Report

## 1. Executive Summary

The Endpoint Privilege Management (EPM) module in SentinelOps has reached a high level of maturity on the web application (Frontend) and data persistence (Database) layers. The implementation spans policy authoring, software catalog integration, self-service Just-In-Time (JIT) elevation requests, role-based access control (RBAC), and detailed audit logging. 

**Overall Architecture & Status:**
- **Frontend (Fully Implemented):** Provides comprehensive UI for policy management, a multi-step rule wizard, approval queues, and fleet-wide analytics.
- **Database (Fully Implemented):** Uses Supabase with extensive schema definitions, Row Level Security (RLS), and a suite of PostgreSQL RPCs for secure data mutation and retrieval.
- **Agent Integration (Pending/Ready):** The backend is fully primed to dispatch configuration tasks (`epm-policy-sync`) and receive telemetry (`epm_elevation_log`) from the SentinelGo agent. The system relies on the agent to parse the rules, enforce privileges locally, and upload logs.

## 2. Frontend Implementation

The frontend is built using React, `@tanstack/react-router`, `@tanstack/react-query`, and custom UI components.

### Pages & Routes
- `_app.epm.tsx`: The layout and root navigation wrapper for all EPM views.
- `_app.epm.index.tsx`: Dashboard providing fleet-wide analytics, rule breakdowns by tier, recent user activity, and elevations over time.
- `_app.epm.$policyId.tsx`: Detailed policy editor supporting configuration of target scope (Device vs. Group) and an embedded rule editor.
- `_app.epm.approvals.tsx`: Queue for administrators to review, approve, or deny pending JIT elevation requests.
- `_app.epm.logs.tsx`: Searchable and filterable table of EPM elevation events (allow/deny actions).
- `_app.epm.requests.tsx`: Self-service portal for end-users to view their own elevation requests.

### Dialogs & Wizards
- `CreateEPMPolicyWizardDialog`: A multi-step wizard (Name -> Scope -> Select Applications -> Rules) streamlining policy creation and auto-populating app metadata from the Software Catalog.
- `RequestEPMElevationDialog`: Self-service request form allowing users to select a device, input application details, provide justification, and set urgency/duration.
- `EPMElevationRequestApproveSheet`: Side-sheet for administrators to review a request and modify the resulting rule constraints (e.g., hash, path, expiry) before approving.
- `ExplainDenialDialog`: Allows admins to provide reasoning when denying a request, or to prefill a new policy rule directly from a denied event log.

### Components
- `EPMRuleEditor` & `EPMRuleDraftsTable`: Complex forms to manage rule logic (Hash, Path, Publisher, Script, Wildcard), priorities, and arguments.
- `EPMRuleTemplatesPanel`: Provides out-of-the-box rule configurations for common tools.
- `EPMPolicyTable` & `EPMElevationLogTable`: Data grids with pagination and filtering.
- **Badges**: `EPMDecisionBadge`, `EPMExpiryBadge`, `EPMMatchTypeBadge` to standardize UI states.

### Workflow & Missing Features
- **Workflow:** Admins can author policies from scratch, from templates, or dynamically from software catalog data. They can then deploy them, which inserts a job in the agent task queue.
- **Missing Features:** Real-time feedback from the endpoint indicating successful policy application is limited to the generic command task status. Policy versioning history is currently not implemented in the UI.

## 3. Database Architecture

The EPM data layer resides in PostgreSQL (Supabase).

### Tables
- `epm_policies`: Top-level policy container holding `name`, `target_scope` (either `device_group_id` or `device_id`), and state (`enabled`).
- `epm_policy_rules`: Granular matching conditions tied to a policy. Contains fields like `app_hash`, `app_path`, `publisher`, `script_hash`, `allowed_args`, `decision`, `priority`, and `expires_at`.
- `epm_elevation_requests`: Tracks self-service JIT requests, including `justification`, `urgency`, `requested_duration_minutes`, and `status`. References the resulting rule upon approval.

### Views
- `epm_elevation_logs`: A view over the `audit_logs` table (where `log_category = 'epm_elevation_log'`), cleanly extracting JSON payload data (`app_hash`, `decision`, `policy_id`, `request_id`) into columns for easy querying.

### RPCs (Remote Procedure Calls)
All mutations and complex queries are encapsulated in `SECURITY DEFINER` RPCs to enforce RBAC and bypass direct table manipulation. (See Section 7 for details).

### RLS & Triggers
- **RLS:** Policies restrict `SELECT`/`INSERT`/`UPDATE`/`DELETE` based on a user's RBAC permissions (`epm_policies:manage`, `epm_policies:view`). `epm_policy_rules` table access is blocked from direct API calls; it is only accessible via RPCs.
- **Triggers:** Automatic maintenance of `updated_at` columns on all tables.

## 4. EPM Policy Architecture

- **Creation & Editing:** Handled via `upsert_epm_policy` and `upsert_epm_policy_rules`. Rule updates are performed as a "full-replace" strategy (delete all rules for a policy and re-insert) to ensure consistency.
- **Target Scope:** A policy is strictly mutually exclusive to either one `device_group_id` or one `device_id`.
- **Rule Association:** Rules define evaluation hierarchy. Prioritization is numeric, but logically evaluated by agents typically in the order: `Script/Hash` (300) > `Publisher` (200) > `Path` (100) > `Wildcard` (0).
- **JIT & Expiry:** Temporary grants are supported via the `expires_at` timestamp on rules.
- **Agent Synchronization:** Policies are not pushed instantly. A `deploy` action generates an `epm-policy-sync` native command task in `agent_command_tasks` for each targeted device, which the agent pulls on its next heartbeat.

## 5. Application Selection System

The application selection flow tightly integrates with the platform's Software Catalog.
- **Integration:** When creating a policy, the UI calls `list_software_catalog_rule_sources(uuid[])`. 
- **Rule Generation:** This RPC aggregates data across all active installations of the software (via `agent_software`) to determine the *representative path*, *representative hash*, and *publisher*.
- **Authoring:** The UI converts this metadata into `DraftRule` objects, drastically reducing manual data entry and preventing typos in critical hash/path rules.

## 6. Elevation Rules

- **Available Types:** 
  1. `script`: Exact hash of a script executed via a defined interpreter.
  2. `hash`: SHA-256 of the binary.
  3. `publisher`: Code-signing certificate/vendor (Windows Publisher, macOS Team ID).
  4. `path`: Absolute file path or glob pattern.
  5. `wildcard`: Matches any application (highly restricted use).
- **Service Scoping:** Rules can be scoped to specific services (`allowed_service_name`) and execution arguments (`allowed_args`).
- **Limitations:** OS-specific validation (e.g., preventing Windows paths on Linux policies) relies mostly on user awareness, though templates help mitigate this.

## 7. Backend APIs & RPCs

| RPC Name | Purpose | Parameters | Status |
| :--- | :--- | :--- | :--- |
| `upsert_epm_policy` | Creates/Updates top-level policy. | `p_name`, `p_description`, `p_device_group_id`, `p_device_id`, `p_enabled`, `p_id` | ✅ Fully Implemented |
| `upsert_epm_policy_rules` | Full-replaces rules for a policy. | `p_policy_id`, `p_rules` (JSONB) | ✅ Fully Implemented |
| `list_epm_policies` | Fetches policies with nested rules. | `p_search` | ✅ Fully Implemented |
| `get_epm_policy` | Fetches a single policy with rules. | `p_id` | ✅ Fully Implemented |
| `delete_epm_policy` | Deletes policy and cascades rules. | `p_id` | ✅ Fully Implemented |
| `push_epm_policy_to_devices` | Generates sync tasks for agents. | `p_policy_id` | ✅ Fully Implemented |
| `list_epm_elevation_logs` | Queries the elevation logs view. | `device_id`, `decision`, `app_search`, `from`, `to`, `limit`, `offset` | ✅ Fully Implemented |
| `request_epm_elevation` | Submits a new self-service request. | `agent_id`, `app_name`, `justification`, `urgency`, etc. | ✅ Fully Implemented |
| `list_my_epm_elevation_requests` | Retrieves user's own requests. | `status`, `limit`, `offset` | ✅ Fully Implemented |
| `list_pending_epm_elevation_requests`| Retrieves queue for admins. | `urgency`, `agent_id`, `limit`, `offset` | ✅ Fully Implemented |
| `approve_epm_elevation_request` | Approves request & creates JIT rule. | `request_id`, `review_reason`, constraints, `expires_at` | ✅ Fully Implemented |
| `deny_epm_elevation_request` | Denies request with reasoning. | `request_id`, `review_reason` | ✅ Fully Implemented |

## 8. Security Model

- **RBAC Integrations:** Implements 5 key permissions via `rbac_role_permissions`:
  - `epm_policies:view`, `epm_policies:manage`, `epm_policies:deploy`
  - `epm_elevation_requests:request` (assigned broadly, including to `employee` role)
  - `epm_elevation_requests:review` (assigned to admins/operators)
- **RLS & RPCs:** The `epm_policy_rules` table is completely locked down by RLS. Standard users cannot read it directly; they must use the `SECURITY DEFINER` RPCs which rigorously check `public.has_permission()`.
- **Approval Flow:** The approval RPC dynamically provisions a singleton policy named `"Self-Service Elevation Grants"` on the target device, inserts the approved rule, and triggers an immediate agent task sync.

## 9. Current Feature Matrix

| Feature | Frontend | Database | Backend | Status | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Policy CRUD | ✅ | ✅ | ✅ | ✅ Fully Implemented | Full-replace strategy used for rules. |
| Rule Editor & Validation | ✅ | ✅ | ✅ | ✅ Fully Implemented | Supports all match tiers (Hash, Path, etc.) |
| App Catalog Integration | ✅ | ✅ | ✅ | ✅ Fully Implemented | Extracts Hashes/Paths from DB natively. |
| Elevation Requests (Self-Service) | ✅ | ✅ | ✅ | ✅ Fully Implemented | Workflows for requesting and approving. |
| Agent Policy Deployment | ✅ | ✅ | ✅ | 🟡 Partially Implemented | Platform enqueues tasks; Agent must process them. |
| Endpoint Audit Log Ingestion | ✅ | ✅ | ✅ | 🟡 Partially Implemented | DB view is ready; Agent must upload correct JSON. |
| Rule Versioning | 🔴 | 🔴 | 🔴 | 🔴 Not Implemented | Only tracks `updated_at`, no historical diffs. |

## 10. Current User Workflow

**A. Creating a Policy:**
1. User opens **CreateEPMPolicyWizardDialog**.
2. Inputs Name & Target Scope (Group/Device).
3. Selects applications from the Software Catalog (optional).
4. Configures Rule constraints (Hash, Path, JIT Expiry).
5. Clicks "Save", triggering `upsert_epm_policy` and `upsert_epm_policy_rules`.
6. Clicks "Deploy", triggering `push_epm_policy_to_devices` which queues the task.

**B. Self-Service JIT Elevation:**
1. End-user attempts to run an app, is blocked, and opens the UI to Request Elevation.
2. Form calls `request_epm_elevation`.
3. Admin sees request in Approvals queue (`list_pending_epm_elevation_requests`).
4. Admin modifies constraints and approves (`approve_epm_elevation_request`).
5. DB automatically creates/updates the "Self-Service Elevation Grants" policy and enqueues a sync task to the specific device.

## 11. Current Limitations

- **Missing Functionality:** No built-in rule versioning or rollback capability.
- **UI Limitations:** "Permanent" JIT grants are technically stored as a 100-year expiration rather than a native `NULL` value from the UI dropdown. 
- **Database Limitations:** Polices rely heavily on `JSONB` for `rules` updates which removes ability to natively track individual rule IDs easily unless fetched.
- **Agent Dependency:** The UI assumes the agent receives and applies policies successfully upon task dispatch. There is no cryptographic receipt or strict verification of policy state on the endpoint side currently reflected in the EPM dashboard.
- **Offline Approvals:** No support for offline approval codes (e.g., generating a time-based PIN for the agent when disconnected from the network).

## 12. Features Ready for Agent Integration

The following features require zero additional platform work and rely entirely on the **SentinelGo** agent for operationalization:

1. **Policy Enforcement:** The agent must pull `agent_command_tasks` with slug `epm-policy-sync`, parse the JSONB payload containing `rules`, and implement the OS-level hooking (Windows API, Linux polkit/sudoers, macOS endpoint security framework) to intercept and evaluate process execution.
2. **Telemetry Upload:** The agent must upload elevation event logs to the existing `agent_ingest_audit_logs` pipeline with `log_category = 'epm_elevation_log'` and a JSONB payload containing `user_id`, `app_path`, `app_hash`, `decision`, `policy_id`, and `request_id`.
3. **JIT Expiration Handling:** The agent must actively honor the `expires_at` timestamp on rules and revoke permissions locally when the time passes.

## 13. Overall Implementation Readiness

- **Frontend Completion:** ~95% 
- **Database Completion:** ~100% (Schema, RPCs, and RLS are strictly enforced and secure).
- **Production Readiness:** The backend system is fully production-ready from a management and administrative standpoint.
- **Next Development Priorities:**
  1. Build and test the OS-level EPM enforcement modules in the SentinelGo agent.
  2. Implement an agent-to-server acknowledgment mechanism to confirm policy application success.
  3. Introduce policy version control or audit-diffing for compliance tracking.
