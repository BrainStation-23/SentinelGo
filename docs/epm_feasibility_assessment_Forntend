# Enterprise Endpoint Privilege Management (EPM) Feasibility Assessment & Implementation Plan

## Executive Summary
This document provides a comprehensive architecture and codebase assessment for introducing Enterprise Endpoint Privilege Management (EPM) into the SentinelOps platform. The objective is to allow Standard Users to run specific applications with elevated privileges (like Local Administrator or root) without granting them permanent administrative rights.

Based on the assessment of the existing SentinelOps architecture (Supabase backend, React/TanStack frontend, RPC-based API, robust RBAC, and agent command pipeline), **this feature is highly technically feasible.** The backend architecture is well-prepared for this capability, although it will require significant enhancements to the endpoint agents (Windows, macOS, and Linux) to handle process interception and secure token elevation.

## Overall Feasibility Assessment
- **Windows:** Feasible. Requires a privileged agent daemon (running as SYSTEM) and a user-facing launcher (Context Menu Shell Extension or a custom UI) to securely spawn processes with an elevated token (e.g., using `CreateProcessWithTokenW`). 
- **macOS / Linux:** Feasible. Can be implemented by having the root agent daemon dynamically manage configuration files in `/etc/sudoers.d/` or by providing a custom `sentinel-sudo` binary that communicates with the daemon via local IPC.
- **Backend / Platform:** Fully Feasible. The platform's existing modules (Software Inventory, Command Tasks, RBAC, and Approval Workflows) provide a strong foundation that can be reused almost entirely.

---

## Current Architecture Review
The SentinelOps platform currently consists of:
1. **Frontend:** React-based web application using Vite, TanStack Router, and Tailwind CSS.
2. **Backend:** Supabase-powered PostgreSQL database leveraging heavily on Row Level Security (RLS) and Remote Procedure Calls (RPCs).
3. **Agent Integration:** An asynchronous command execution pipeline (`agent_command_tasks`), a software inventory ingestion system (`agent_ingest_runs`, `software`), and comprehensive audit logging.
4. **Security Model:** A robust RBAC system with policies, JIT elevation, and approval workflows.

### Existing Components That Can Be Reused
1. **Application Database & Software Inventory:** 
   The existing `software` table and Application Database module can be leveraged to define the allowed applications. Administrators can select software from the existing inventory to create EPM policies.
2. **Command Execution Pipeline:** 
   The `agent_command_tasks` architecture can be reused to push EPM policy updates down to the endpoint agents in near real-time.
3. **RBAC & Policies:** 
   The `src/lib/policies.ts` and `rbac` tables (`roles`, `permissions`) can be extended. The EPM policies can use the same matching and targeting logic currently used for existing policies.
4. **Approval Workflow:** 
   The existing JIT (Just-In-Time) elevation and approval workflow components (`20260720_rbac5_004_approval_workflow.sql`) are perfectly suited for "Request Elevation" scenarios where a user requests to run an unknown app as admin.
5. **Audit Logging:** 
   The extensive audit triggers (`user_activity_logs`) can be expanded to ingest execution events from the endpoint agent (e.g., "User A launched IIS Manager as Admin").

### Missing Components & Gap Analysis
1. **Agent EPM Module:** The current agent primarily handles software inventory and command execution. It lacks a module for process interception and secure token manipulation.
2. **EPM Database Schema:** Missing tables for `epm_policies` (mapping users/groups to allowed software hashes/paths) and `epm_execution_logs`.
3. **User-Facing Interceptor (OS Level):** 
   - *Windows:* A custom context menu entry ("Run with SentinelOps") or an interceptor driver.
   - *macOS/Linux:* A PAM module or sudoers manager.

---

## Operating System Capability Assessment

### Windows
- **Limitations:** Windows UAC (User Account Control) strictly segregates Standard User and Administrator tokens. 
- **Agent Capability Needs:** The Windows Agent must run a background service as `NT AUTHORITY\SYSTEM`. When a user requests elevation, the user-space app communicates with the SYSTEM service via named pipes. The SYSTEM service verifies the application hash/path against the SentinelOps EPM policy, duplicates an Administrator token, and launches the application within the user's active session (`WTSGetActiveConsoleSessionId`).

### macOS & Linux
- **Limitations:** Modifying root privileges requires careful handling of `sudo` or setuid binaries to avoid arbitrary execution vulnerabilities.
- **Agent Capability Needs:** The Linux/macOS agent daemon (running as `root`) can dynamically write strict rules to `/etc/sudoers.d/sentinelops-epm`. Alternatively, a custom binary (e.g., `sentinel-exec`) can be provided with `setuid` root, which asks the local agent daemon for permission before executing the target binary via `execve`.

---

## Security Assessment & Risks
1. **Child Process Escalation:** An application launched as Administrator (e.g., Command Prompt) can spawn other applications as Administrator. *Mitigation:* The agent must optionally monitor child processes or administrators must be warned not to elevate applications like `cmd.exe` or `powershell.exe` indiscriminately.
2. **DLL Hijacking:** If an elevated application loads a malicious DLL from a user-writable directory, privilege escalation occurs. *Mitigation:* EPM policies should strictly enforce application hashes and verify file signatures before elevation.
3. **Agent IPC Spoofing:** Standard users might attempt to spoof the local IPC (named pipes/sockets) to trick the SYSTEM agent into elevating a rogue app. *Mitigation:* The IPC mechanism must validate the caller's process ID and session ID securely.

---

## Implementation Plan

### Phase 1: Database & Backend Architecture
1. **Database Schema Additions:**
   - Create `epm_policies` table (links to `device_groups` and specific users).
   - Create `epm_policy_rules` table (links policy to `software` table via path, publisher, or SHA-256 hash).
   - Create `epm_execution_logs` table (for auditing elevation events).
2. **RPC and API Endpoints:**
   - Develop RPCs for `upsert_epm_policy`, `list_epm_policies`, and `log_epm_execution`.
   - Update RLS policies to ensure only administrators can modify EPM policies.
3. **Approval Integration:**
   - Wire the existing approval workflow to allow JIT "Request Elevation" events from the agent.

### Phase 2: Frontend Management Interface
1. **EPM Policy Dashboard:**
   - Create a new route (e.g., `_app.epm.tsx`) for managing Endpoint Privilege Management.
2. **Policy Creation Wizard:**
   - Integrate the existing Application Database to allow admins to search and select software to elevate.
   - Provide configuration options (Match by Hash, Match by Certificate Publisher, Match by Path).
3. **EPM Audit Logs View:**
   - Add a tab in the Device Detail page (`_app.devices.$agentId.tsx`) to show historical EPM elevations.

### Phase 3: Agent Enhancements (Windows/macOS/Linux)
1. **Policy Sync Mechanism:**
   - Enhance the agent to poll or receive EPM policies and cache them locally (encrypted) so elevation works offline.
2. **Windows Implementation:**
   - Develop a Shell Context Menu extension (`Run Elevated (SentinelOps)`).
   - Implement the SYSTEM daemon logic: Receive request -> Verify Hash -> Check Policy -> Duplicate Token -> `CreateProcessAsUser`.
3. **macOS/Linux Implementation:**
   - Implement the sudoers management logic or a local `setuid` wrapper binary.
4. **Execution Auditing:**
   - Instrument the agent to send telemetry back to `agent_ingest_runs` or a new endpoint whenever an elevation occurs (success or blocked).

### Phase 4: Testing & Rollout
1. Validate against DLL hijacking by enforcing code signing requirements on elevated binaries.
2. Test JIT workflows (user requests access -> admin approves in dashboard -> agent elevates instantly).

## Final Recommendation
The current SentinelOps architecture is highly robust and uniquely well-suited to absorb an EPM capability. Because the platform already handles software inventory, robust RBAC, and agent task dispatching, the backend effort is relatively minimal. The primary engineering focus should be directed toward the low-level operating system agent development (C++/Rust/Go) to ensure secure process interception and token elevation across Windows, macOS, and Linux.
