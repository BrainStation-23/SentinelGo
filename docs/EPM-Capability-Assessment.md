# SentinelGo Agent — Enterprise Endpoint Privilege Management (EPM) Capability Assessment

**তৈরির তারিখ:** ২০২৫
**Repository:** `github.com/SentinelGo`
**ভাষা:** Go (সমস্ত source file `.go`)
**Assessment ধরন:** Read-only codebase inspection  — কোনো code পরিবর্তন করা হয়নি
**Scope:** Windows + Linux + macOS (তিনটি platform একসাথে)

---

## ১. Executive Summary

SentinelGo একটি cross-platform (Windows / Linux / macOS) endpoint monitoring agent যা প্রতিটি platform-এ privileged system daemon হিসেবে চলে। Agent মূলত hardware inventory, software inventory, audit log collection, এবং remote task execution-এর জন্য তৈরি। EPM (Enterprise Endpoint Privilege Management) হলো এমন একটি capability যা standard (non-admin) user-কে নির্দিষ্ট application elevated privilege-এ চালানোর অনুমতি দেয় — Windows UAC bypass, Linux sudo replacement, macOS Authorization Services-এর বিকল্প হিসেবে।

### ১.১ Per-Platform Readiness Scores (সংক্ষিপ্ত)

| Platform | Overall Score | Foundation | Critical Missing | Verdict |
|----------|---------------|------------|-----------------|---------|
| **Windows** | **4.0 / 10** | SCM SYSTEM service, WinAPI access | Token APIs, Named Pipe IPC, user-space client | EPM-buildable, major work দরকার |
| **Linux** | **3.5 / 10** | systemd root daemon, bash executor, sudo detection | polkit/D-Bus, capability APIs, IPC | EPM-buildable, different approach দরকার |
| **macOS** | **3.0 / 10** | launchd root daemon, bash executor | Authorization Services, XPC, SMJobBless | EPM-buildable, hardest platform |

### ১.২ সামগ্রিক Verdict

> ⚠️ **Partially Feasible — Platform-specific major gaps রয়েছে**

Agent-এর বিদ্যমান architecture সব platform-এ privileged daemon, task pipeline, audit logging, এবং SQLite storage প্রদান করে — EPM-এর জন্য একটি solid foundation। কিন্তু EPM-এর সবচেয়ে critical অংশ — user context-এ elevated process launch, local IPC, এবং policy enforcement engine — **তিনটি platform-এই সম্পূর্ণ অনুপস্থিত।**

**মোট অনুমানিত development সময়:**
- Windows: ২৪–৩৬ সপ্তাহ
- Linux: ১৮–২৮ সপ্তাহ
- macOS: ২০–৩২ সপ্তাহ
- Shared components: ৮–১২ সপ্তাহ

---

## ২. Agent Architecture Review

### ২.১ Startup Flow (তিনটি Platform)

```
main.go
  └─ parseFlags()
  └─ config.Load()                     [platform-specific path]
  └─ NewProgram(cfg)
  └─ NewAgentService(prg, svcCfg)
  └─ RunAsService(svc)
       └─ svc.Run()                    [Windows: SCM | Linux: systemd | macOS: launchd]
            └─ Program.Start()
                 └─ MainIntegration.Start(ctx)
                      ├─ emergencylog.Init()
                      ├─ cfg.ValidateConfiguration()
                      ├─ updater.StartupUpdateCheck()  [goroutine]
                      ├─ authsvc.Login()
                      ├─ scheduler.Start()
                      ├─ logging.Start()               [audit logs]
                      └─ taskManager.Run()             [goroutine]
```

Startup sequence তিনটি platform-এ প্রায় অভিন্ন। Platform-specific পার্থক্য শুধু `svc.Run()` call-এ — বাকি সব shared।

### ২.২ Modular Design (সব Platform-এ Shared)

| Module | Path | দায়িত্ব | EPM Reuse |
|--------|------|---------|-----------|
| `main_integration` | `internal/main_integration.go` | Service orchestration | ✅ EPM service এখানে plug-in করা যাবে |
| `scheduler` | `internal/scheduler/` | Background tasks | ✅ EPM policy sync schedule করা যাবে |
| `task` | `internal/service/task/` | Task polling + execution | ✅ EPM policy delivery channel হিসেবে |
| `auditlogs` | `internal/auditlogs/` | Log collection | ✅ EPM events log করা যাবে |
| `winsec` | `internal/winsec/` | File ACL hardening | ✅ Windows-এ, Linux/macOS-এ NO-OP |
| `config` | `internal/config/` | Configuration management | ✅ EPM flags সহজে যোগ করা যাবে |
| `updater` | `internal/updater/` | Self-update + signature verify | ✅ SHA-256/ed25519 EPM policy signing-এ reuse |
| `store` | `internal/store/` | SQLite persistence | ✅ EPM policy table migration যোগ করা যাবে |

### ২.৩ EPM-এর জন্য Architecture Suitability

Agent architecture EPM hosting-এর জন্য structurally উপযুক্ত কারণ:
- প্রতিটি platform-এ privileged daemon (`SYSTEM` / `root`) হিসেবে চলে
- Modular design নতুন EPM component সংযোজনকে natural করে তোলে
- `init()` pattern-ভিত্তিক native handler registry extensible
- SQLite-backed durable task queue offline EPM policy storage-এর জন্য কাজে লাগবে

**কিন্তু:** Platform-specific IPC, token/session management, এবং elevated process launch mechanism — কোনোটিই নেই।

---

## ৩. Platform-Specific Service Assessment

### ৩.১ Windows — Windows Service (SCM)

**File:** `cmd/sentinelgo/service/svc_windows.go`

```go
m.CreateService(ws.name, exePath, mgr.Config{
    StartType:   mgr.StartAutomatic,  // boot-এ auto-start
    DisplayName: ws.cfg.DisplayName,
    Description: ws.cfg.Description,
}, ws.cfg.Arguments...)
```

- **Runtime:** `golang.org/x/sys/windows/svc` package
- **Start type:** `Automatic` — OS boot-এ শুরু হয়
- **Account:** Default installation-এ `LocalSystem` (SYSTEM)
- **Stop/Shutdown:** SCM commands handle করে gracefully
- **Session:** Windows Session 0 (non-interactive service session)

**EPM Suitability:** ✅ উত্তম। SYSTEM account-এ `SeImpersonatePrivilege` ও `SeAssignPrimaryTokenPrivilege` থাকে — EPM-এর `CreateProcessAsUser` call-এর জন্য এই দুটি privilege অপরিহার্য।

### ৩.২ Linux — systemd Service

**File:** `cmd/sentinelgo/service/svc_linux.go`

Agent systemd unit file generate করে `/etc/systemd/system/sentinelgo.service`-এ:

```ini
[Unit]
Description=SentinelGo Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sentinelgo
Restart=always

[Install]
WantedBy=multi-user.target
```

- **Managed via:** `systemctl start/stop/enable/disable`
- **User:** unit file-এ `User=` নেই → default `root` হিসেবে চলে
- **Restart policy:** `Restart=always` — crash হলে auto-restart
- **Session:** system session, cgroup-এর অধীনে

**EPM Suitability:** ✅ ভালো। root process হিসেবে চলা Linux-এ EPM-এর জন্য আদর্শ — `setuid`, `fork()+execve()`, `setresuid()` সব call করার permission আছে। তবে systemd cgroup restriction EPM process spawning-এ বাধা দিতে পারে।

### ৩.৩ macOS — launchd Daemon

**Files:** `cmd/sentinelgo/service/svc_darwin.go`, `cmd/sentinelgo/service/launchd.go`

Agent LaunchDaemon plist generate করে `/Library/LaunchDaemons/com.sentinelgo.agent.plist`-এ:

```xml
<dict>
    <key>Label</key>         <string>com.sentinelgo.agent</string>
    <key>UserName</key>      <string>root</string>
    <key>KeepAlive</key>     <true/>
    <key>RunAtLoad</key>     <true/>
    <key>ProgramArguments</key>
    <array><string>/usr/local/bin/sentinelgo</string></array>
</dict>
```

- **Managed via:** `launchctl bootstrap system` / `launchctl bootout system`
- **UserName:** `root` — explicitly set
- **KeepAlive:** `true` — crash হলে launchd auto-restart করে
- **Session:** System-level daemon (not user session)

**EPM Suitability:** ⚠️ Moderate। root daemon-এ চলা ভালো, কিন্তু macOS SIP (System Integrity Protection) এবং Sandbox restriction EPM-এর কিছু operation block করতে পারে। Authorization Services / SMJobBless pattern ছাড়া macOS-এ proper EPM করা কঠিন।

---

## ৪. Current Privilege Model

### ৪.১ Windows — SYSTEM Account

**File:** `internal/winsec/winsec_windows.go`

```go
func SecurePath(path string) error {
    // SY = SYSTEM only, BA = Built-in Administrators
    sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    sd, _ := windows.SecurityDescriptorFromString(sddl)
    windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, ...)
}

func currentUserSID() (string, error) {
    tok := windows.GetCurrentProcessToken()  // SYSTEM token
    user, _ := tok.GetTokenUser()
    return user.User.Sid.String(), nil
}
```

**বর্তমানে ব্যবহৃত Windows privilege APIs:**
- `windows.GetCurrentProcessToken()` — process token read করা
- `windows.SecurityDescriptorFromString()` — SDDL parse
- `windows.SetNamedSecurityInfo()` — file/dir ACL set

**EPM-এর জন্য প্রয়োজনীয় Windows APIs (বর্তমানে অনুপস্থিত):**

| API | প্রয়োজন কেন |
|-----|------------|
| `WTSGetActiveConsoleSessionId()` | Active user session ID পেতে |
| `WTSQueryUserToken()` | User session token পেতে |
| `DuplicateTokenEx()` | Token duplicate করতে |
| `AdjustTokenPrivileges()` | Token privileges modify করতে |
| `CreateEnvironmentBlock()` | User environment block তৈরি করতে |
| `CreateProcessAsUser()` | Specific user context-এ process launch |
| `CreateProcessWithTokenW()` | Token সহ process launch |
| `GetTokenInformation()` | Token info পড়তে |
| `WTSEnumerateSessions()` | সব active sessions list করতে |
| `OpenProcessToken()` | Process token handle পেতে |

### ৪.২ Linux — root Process

**File:** `cmd/sentinelgo/service/svc_linux.go` (unit file-এ `User=` নেই → root)

**Executor:** `internal/service/task/executor_linux.go`

```go
// Linux executor privileged command detect করে sudo ব্যবহার করে
func needsSudo(cmd string) bool { ... }
if needsSudo(cmd) {
    args = append([]string{"-S", cmd}, args...)
    cmd = "sudo"
}
```

**বর্তমান privilege model:**
- Agent নিজে root হিসেবে চলে
- Task execution-এ `sudo -S` ব্যবহার করে (stdin password injection)
- কোনো `setuid`, `setresuid`, `capabilities` API ব্যবহার নেই

**EPM-এর জন্য প্রয়োজনীয় Linux APIs (বর্তমানে অনুপস্থিত):**

| API / Mechanism | প্রয়োজন কেন |
|----------------|------------|
| `setuid()`/`setresuid()` | Specific user context-এ process execute করতে |
| `fork()` + `execve()` | User context-এ child process spawn করতে |
| Linux Capabilities (`CAP_SETUID`, `CAP_SETGID`) | Fine-grained privilege দিতে |
| `polkit` (PolicyKit) D-Bus API | User authorization request handle করতে |
| PAM (Pluggable Authentication Modules) | User authentication verify করতে |
| `getpwuid()` / `getgrnam()` | User/group info পেতে |
| `/proc/[pid]/status` parsing | Process privilege info পেতে |

### ৪.৩ macOS — root Daemon

**File:** `cmd/sentinelgo/service/launchd.go` (`UserName=root` in plist)

**Executor:** `internal/service/task/executor_darwin.go`

Darwin executor root context-এ চলে, তাই `sudo` ব্যবহার করতে হয় না। `bash` এবং `python3` script সরাসরি execute করা যায়।

**EPM-এর জন্য প্রয়োজনীয় macOS APIs (বর্তমানে অনুপস্থিত):**

| API / Framework | প্রয়োজন কেন |
|----------------|------------|
| `AuthorizationCreate()` | Authorization right তৈরি করতে |
| `AuthorizationCopyRights()` | Right check করতে |
| `SMJobBless()` | Privileged helper tool install করতে |
| `AuthorizationExecuteWithPrivileges()` | Elevated process launch করতে (deprecated but used) |
| XPC Services | User agent ↔ root daemon IPC-এর জন্য |
| `setuid()`/`fork()` | User context process spawn করতে |
| Security.framework | Code signing verification |

---

## ৫. Process Execution Capability

### ৫.১ Windows

**File:** `internal/service/task/executor_windows.go`

```go
func (s *TaskExecutorService) executeLocalScript(ctx context.Context, scriptPath, payloadPath string) (string, error) {
    if filepath.Ext(scriptPath) == ".ps1" {
        cmd = exec.CommandContext(ctx, "powershell", "-NoProfile",
              "-ExecutionPolicy", "Bypass", "-File", scriptPath, "-PayloadPath", payloadPath)
    } else {
        cmd = exec.CommandContext(ctx, "cmd", "/C", scriptPath, payloadPath)
    }
    cmd.WaitDelay = 30 * time.Second
    output, err := cmd.CombinedOutput()
    return string(output), err
}
```

| Capability | Status |
|-----------|--------|
| PowerShell (.ps1) execute | ✅ আছে |
| CMD (.bat/.cmd) execute | ✅ আছে |
| Context-based timeout | ✅ আছে |
| stdout/stderr capture | ✅ আছে |
| User context process launch | ❌ নেই — সব SYSTEM context-এ |
| Token-based process creation | ❌ নেই |
| Session ID-aware launch | ❌ নেই |

**EPM-এর জন্য missing:** `exec.Command` সরাসরি SYSTEM child process তৈরি করে। User desktop-এ elevated process launch করতে `CreateProcessAsUser`/`WTSQueryUserToken` pipeline দরকার — **সম্পূর্ণ অনুপস্থিত।**

### ৫.২ Linux

**File:** `internal/service/task/executor_linux.go`

```go
func (s *TaskExecutorService) executeLocalScript(ctx context.Context, scriptPath, payloadPath string) (string, error) {
    ext := filepath.Ext(scriptPath)
    switch ext {
    case ".sh":
        cmd = exec.CommandContext(ctx, "bash", scriptPath, payloadPath)
    case ".py":
        cmd = exec.CommandContext(ctx, "python3", scriptPath, payloadPath)
    }
    if needsSudo(cmd_name) {
        // sudo -S দিয়ে privileged execution
    }
    output, err := cmd.CombinedOutput()
    return string(output), err
}
```

| Capability | Status |
|-----------|--------|
| bash (.sh) execute | ✅ আছে |
| python3 (.py) execute | ✅ আছে |
| Privileged command detection | ✅ আছে (`needsSudo`) |
| sudo -S wrapper | ✅ আছে |
| Specific user context execution | ❌ নেই — root বা sudo context |
| `setuid`/`setresuid` user drop | ❌ নেই |
| polkit authorization | ❌ নেই |

**EPM-এর জন্য missing:** Linux-এ user-specific process execution-এর জন্য `fork()` + `setresuid()` + `execve()` প্যাটার্ন দরকার। বর্তমানে শুধু root বা sudo context-এ সব চলে — নির্দিষ্ট user-এর context-এ process spawn করার কোনো mechanism নেই।

### ৫.৩ macOS

**File:** `internal/service/task/executor_darwin.go`

Darwin executor Linux executor-এর মতোই — `bash` এবং `python3` script execute করে। পার্থক্য হলো agent ইতিমধ্যেই root হিসেবে চলে, তাই `sudo` wrapper দরকার হয় না।

| Capability | Status |
|-----------|--------|
| bash (.sh) execute | ✅ আছে |
| python3 (.py) execute | ✅ আছে |
| root context execution | ✅ আছে (launchd UserName=root) |
| User context process spawn | ❌ নেই |
| Authorization Services integration | ❌ নেই |
| XPC-based privileged helper | ❌ নেই |

**EPM-এর জন্য missing:** macOS-এ proper EPM-এর জন্য `AuthorizationExecuteWithPrivileges()` অথবা XPC + SMJobBless pattern দরকার। শুধু `fork`+`execve` যথেষ্ট নয় কারণ macOS Gatekeeper এবং notarization requirement থাকে।

---

## ৬. Platform-Specific API Capability Assessment

### ৬.১ Windows API (বর্তমান + missing)

**Dependency:** `golang.org/x/sys v0.46.0`

**বর্তমানে ব্যবহৃত Windows APIs:**

| API / Package | File | উদ্দেশ্য |
|--------------|------|---------|
| `wevtapi.dll` (LazyDLL) | `collector_windows.go` | Windows Event Log query |
| `procEvtQuery/Next/Render/Close` | `collector_windows.go` | Event log read |
| `procEvtSubscribe` | `collector_windows.go` | Real-time event subscription |
| `windows.CreateEvent()` | `collector_windows.go` | Event signaling |
| `windows.WaitForSingleObject()` | `collector_windows.go` | Event wait |
| `windows.UTF16PtrFromString()` | `collector_windows.go` | UTF-16 string conversion |
| `windows.SecurityDescriptorFromString()` | `winsec_windows.go` | SDDL parse |
| `windows.SetNamedSecurityInfo()` | `winsec_windows.go` | ACL set |
| `windows.GetCurrentProcessToken()` | `winsec_windows.go` | Current process token |
| `svc.Run()`, `svc.ChangeRequest` | `svc_windows.go` | SCM service control |
| `eventlog.Open()`, `eventlog.Info()` | `svc_windows.go` | Windows Event Log write |
| `mgr.Connect()`, `mgr.CreateService()` | `svc_windows.go` | Service management |

**EPM-এর জন্য Missing Windows APIs:**

| API | প্রয়োজন কেন | Complexity |
|-----|------------|-----------|
| `WTSGetActiveConsoleSessionId()` | Active user session ID | কম |
| `WTSQueryUserToken()` | User session token | মাঝারি |
| `WTSEnumerateSessions()` | সব sessions list | কম |
| `DuplicateTokenEx()` | Token duplicate | মাঝারি |
| `AdjustTokenPrivileges()` | Privilege modify | মাঝারি |
| `CreateEnvironmentBlock()` | User env block | কম |
| `CreateProcessAsUser()` | User context process | উচ্চ |
| `CreateProcessWithTokenW()` | Token-based process | উচ্চ |
| `GetTokenInformation()` | Token details | কম |
| `OpenProcessToken()` | Process token handle | কম |
| `WinVerifyTrust()` | Authenticode verify | উচ্চ |
| `CryptQueryObject()` | Certificate info | উচ্চ |
| `CreateNamedPipe()` / `ConnectNamedPipe()` | IPC channel | উচ্চ |
| `ImpersonateNamedPipeClient()` | Pipe impersonation | মাঝারি |

### ৬.২ Linux API / System Calls (বর্তমান + missing)

**বর্তমানে ব্যবহৃত Linux capabilities:**

| Mechanism | File | উদ্দেশ্য |
|----------|------|---------|
| `exec.Command("journalctl", "-o", "json")` | `collector_linux.go` | Journal log read |
| `exec.Command("journalctl", "-f", "-p", "3")` | `collector_linux.go` | Real-time log follow |
| File tail: `/var/log/auth.log`, `/var/log/syslog` | `collector_linux.go` | syslog tailing |
| `exec.Command("dpkg-query", ...)` | `collect_linux.go` | Debian package list |
| `exec.Command("rpm", "-qa", ...)` | `collect_linux.go` | RPM package list |
| `exec.Command("snap", "list", ...)` | `collect_linux.go` | Snap package list |
| `exec.Command("flatpak", "list", ...)` | `collect_linux.go` | Flatpak package list |
| `exec.Command("bash", scriptPath, ...)` | `executor_linux.go` | Script execution |
| `exec.Command("sudo", "-S", ...)` | `executor_linux.go` | Privileged execution |
| `/home/*` + `/root` directory scan | `userhomes_linux.go` | User home detection |

**EPM-এর জন্য Missing Linux APIs/Mechanisms:**

| Mechanism | প্রয়োজন কেন | Complexity |
|----------|------------|-----------|
| `setuid()`/`setresuid()` syscall | User context drop | মাঝারি |
| `fork()` + `execve()` pattern | User process spawn | মাঝারি |
| polkit (PolicyKit) D-Bus API | User authorization | উচ্চ |
| `org.freedesktop.PolicyKit1` D-Bus | polkit authorization | উচ্চ |
| Linux Capabilities (`cap_setuid`) | Fine-grained privilege | মাঝারি |
| PAM API (`libpam`) | User authentication | মাঝারি |
| Unix Domain Socket server/client | IPC channel | মাঝারি |
| `getpwuid_r()` / `getgrnam_r()` | User/group lookup | কম |
| `/proc/[pid]/status` UID parsing | Process user check | কম |
| `nsenter` / namespace handling | Container environments | উচ্চ |

### ৬.৩ macOS API / Framework (বর্তমান + missing)

**বর্তমানে ব্যবহৃত macOS capabilities:**

| Mechanism | File | উদ্দেশ্য |
|----------|------|---------|
| `exec.Command("log", "show", "--style", "ndjson")` | `collector_darwin.go` | Unified log read |
| File read: `/var/log/system.log`, `/var/log/install.log` | `collector_darwin.go` | System log tailing |
| `/Library/Logs/DiagnosticReports` scan | `collector_darwin.go` | Crash report collection |
| `exec.Command("system_profiler", "SPApplicationsDataType", "-json")` | `collect_darwin.go` | App inventory |
| `exec.Command("brew", "list", "--versions")` | `collect_darwin.go` | Homebrew packages |
| `exec.Command("mdls", "-name", "kMDItemLastUsedDate", ...)` | `collect_darwin.go` | Last-opened time |
| `exec.Command("bash", scriptPath, ...)` | `executor_darwin.go` | Script execution |
| `/Users/*` directory scan | `userhomes_darwin.go` | User home detection |
| `launchctl bootstrap/bootout` | `launchd.go` | Service lifecycle |

**EPM-এর জন্য Missing macOS APIs/Frameworks:**

| Framework / API | প্রয়োজন কেন | Complexity |
|----------------|------------|-----------|
| `Security.framework` — `AuthorizationCreate()` | Authorization right তৈরি | উচ্চ |
| `Security.framework` — `AuthorizationCopyRights()` | Right check | উচ্চ |
| `Security.framework` — `AuthorizationExecuteWithPrivileges()` | Elevated execution | উচ্চ |
| `ServiceManagement.framework` — `SMJobBless()` | Helper tool install | উচ্চ |
| XPC Services (`xpc_connection_create()`) | IPC channel | উচ্চ |
| `setuid()`/`fork()`/`execve()` | User context spawn | মাঝারি |
| `Security.framework` — code signing check | App signature verify | উচ্চ |
| `SecCodeCheckValidity()` | Code signature validation | উচ্চ |
| `SecCertificateCopySubjectSummary()` | Certificate info | মাঝারি |
| `dscl` / Directory Services | User/group info | কম |


---

## ৭. User Session Management Assessment

### ৭.১ Windows — User Session Awareness

**File:** `internal/service/software/userhomes_windows.go`

```go
// C:\Users\ scan করে user profiles পায় — disk-based, না WTS-based
func platformUserHomeDirs() []string {
    drive := os.Getenv("SystemDrive")
    usersDir := drive + `\Users`
    entries, _ := os.ReadDir(usersDir)
    // filter করে profile directories return করে
}
```

| Capability | Status | EPM-তে দরকার |
|-----------|--------|-------------|
| User home directory detection | ✅ disk scan দিয়ে | ✅ দরকার |
| Active console session ID | ❌ নেই | ✅ অবশ্যই দরকার |
| Logged-in user enumeration | ❌ নেই | ✅ দরকার |
| Interactive session token | ❌ নেই | ✅ অবশ্যই দরকার |
| Session 0 isolation awareness | ❌ নেই | ✅ দরকার |
| WTS session information | ❌ নেই | ✅ দরকার |
| Desktop/window station access | ❌ নেই | ✅ দরকার |
| Multi-user (RDP) session handling | ❌ নেই | ✅ দরকার |

**সিদ্ধান্ত:** Agent জানে কোন users আছে (disk scan থেকে), কিন্তু কোনো user বর্তমানে logged in কিনা, কোন session-এ আছে, তার token কী — কিছুই জানে না। WTS API সম্পূর্ণ missing।

### ৭.২ Linux — User Session Awareness

**File:** `internal/service/software/userhomes_linux.go`

```go
// /root এবং /home/* scan করে
func platformUserHomeDirs() []string {
    homes := []string{"/root"}
    entries, _ := os.ReadDir("/home")
    // /home/username directories add করে
}
```

| Capability | Status | EPM-তে দরকার |
|-----------|--------|-------------|
| User home directory detection | ✅ `/home/*` scan | ✅ দরকার |
| Active login session detection | ❌ নেই | ✅ দরকার |
| `who`/`w` command integration | ❌ নেই | ✅ দরকার |
| `/var/run/utmp` parsing | ❌ নেই | ✅ দরকার |
| loginctl session management | ❌ নেই | ✅ দরকার |
| D-Bus session detection | ❌ নেই | ✅ দরকার |

### ৭.৩ macOS — User Session Awareness

**File:** `internal/service/software/userhomes_darwin.go`

```go
// /Users/* scan করে, Shared এবং Guest exclude করে
func platformUserHomeDirs() []string {
    entries, _ := os.ReadDir("/Users")
    // "Shared", "Guest" skip করে
}
```

| Capability | Status | EPM-তে দরকার |
|-----------|--------|-------------|
| User home directory detection | ✅ `/Users/*` scan | ✅ দরকার |
| Active GUI session detection | ❌ নেই | ✅ দরকার |
| `SCDynamicStoreCopyConsoleUser()` | ❌ নেই | ✅ console user পেতে |
| `utmpx` parsing | ❌ নেই | ✅ দরকার |
| Fast User Switching awareness | ❌ নেই | ✅ দরকার |

---

## ৮. IPC Assessment

### ৮.১ বর্তমান IPC — শুধুমাত্র Outbound HTTP

তিনটি platform-এই agent শুধুমাত্র **outbound HTTP/HTTPS** ব্যবহার করে Supabase backend-এর সাথে communicate করে।

- **HTTP client:** `internal/httpx/` — custom HTTP wrapper
- **PostgREST:** `github.com/supabase-community/postgrest-go`
- **Supabase client:** `github.com/supabase-community/supabase-go`

**স্থানীয় IPC-র কোনো mechanism নেই।**

### ৮.২ Platform-Specific IPC Status

| IPC Mechanism | Windows | Linux | macOS | EPM-তে দরকার |
|--------------|---------|-------|-------|-------------|
| Named Pipes | ❌ নেই | N/A | N/A | ✅ Windows-এ critical |
| Unix Domain Sockets | N/A | ❌ নেই | ❌ নেই | ✅ Linux/macOS-এ critical |
| XPC Services | N/A | N/A | ❌ নেই | ✅ macOS-এ preferred |
| gRPC (local) | ❌ নেই | ❌ নেই | ❌ নেই | ⚠️ বিকল্প |
| Shared Memory | ❌ নেই | ❌ নেই | ❌ নেই | ⚠️ security risk |
| D-Bus | N/A | ❌ নেই | N/A | ✅ Linux polkit-এর জন্য |
| COM/DCOM | ❌ নেই | N/A | N/A | ⚠️ complex |

### ৮.৩ EPM-এর জন্য IPC কেন Critical

EPM architecture-এ দুটি component থাকে:

```
[Windows]
User-space EPM client (standard user desktop)
    ↕ Named Pipe  (\\.\\pipe\\sentinelgo-epm)
SYSTEM EPM service (Session 0)

[Linux]
User-space EPM client  
    ↕ Unix Domain Socket (/var/run/sentinelgo/epm.sock)
root daemon

[macOS]
User-space EPM client
    ↕ XPC Service (com.sentinelgo.epm)
root launchd daemon
```

তিনটি platform-এই এই IPC layer সম্পূর্ণ নতুনভাবে implement করতে হবে।

---

## ৯. Policy Management Assessment

### ৯.১ বিদ্যমান Policy/Config System (সব Platform)

**File:** `internal/config/config.go`

```go
type Config struct {
    EnableTaskPolling    bool     `json:"enable_task_polling"`
    SoftwareSyncEnabled bool     `json:"software_sync_enabled"`
    AuditLogsEnabled    bool     `json:"audit_logs_enabled"`
    AutoUpdate          bool     `json:"auto_update"`
    TaskPollingInterval Duration `json:"task_polling_interval"`
    AccessToken         string   `json:"access_token"`
    RefreshToken        string   `json:"refresh_token"`
}
```

- Atomic write: `SaveAtomic()` — temp file + rename
- File permission hardening: `winsec.SecurePath()` (Windows only, NO-OP অন্যত্র)
- Remote config update: task payload দিয়ে indirect

### ৯.২ EPM Policy Requirements vs Existing (সব Platform)

| Policy Feature | বর্তমান | EPM-তে দরকার |
|---------------|---------|-------------|
| Remote config receive | ✅ task payload-এ | ✅ EPM policy ঐভাবেই পাঠানো যাবে |
| Local policy cache | ✅ SQLite task store | ✅ EPM policy table যোগ করা যাবে |
| Offline execution | ✅ task store থেকে | ✅ EPM-এও দরকার |
| Application allowlist | ❌ নেই | ✅ core EPM feature |
| Per-user policy | ❌ নেই | ✅ দরকার |
| Time-based policy expiry | ❌ নেই | ✅ দরকার |
| Hash-based app matching | ❌ নেই | ✅ দরকার |
| Publisher/cert-based matching | ❌ নেই | ✅ দরকার |
| Policy version control | ❌ নেই | ✅ দরকার |
| Conflict resolution | ❌ নেই | ✅ দরকার |

**সিদ্ধান্ত:** Policy receive ও local storage infrastructure পুনর্ব্যবহারযোগ্য — তিনটি platform-এই। কিন্তু EPM-specific policy schema (application rules, user grants, expiry) সম্পূর্ণ নতুন।

---

## ১০. Command Pipeline Assessment

### ১০.১ বিদ্যমান Task Pipeline (সব Platform)

```
Server (Supabase)
    → agent_get_tasks RPC
    → TaskPollingService.PollAndStoreTasks()
    → SQLite store (tasks.sqlite)
    → TaskExecutorService.ExecutePendingTasks()
    → runTask()
         ├─ Native handler (firewall, reboot, sync, etc.)
         └─ Script execution (platform-specific executor)
    → ReportTaskStatus() → server update
```

### ১০.২ Pipeline Features (সব Platform)

| Feature | Status | EPM Reuse |
|---------|--------|-----------|
| Durable SQLite queue | ✅ | ✅ EPM policy delivery |
| Retry logic (max 3) | ✅ | ✅ EPM policy sync retry |
| Per-task timeout | ✅ | ✅ EPM request timeout |
| Watchdog (overdue task kill) | ✅ | ✅ Hung EPM request cancel |
| Interrupt recovery | ✅ | ✅ Agent restart recovery |
| Result reporting | ✅ | ✅ EPM policy sync result |
| Offline queue sync | ✅ | ✅ EPM offline support |
| Native handler registry | ✅ | ✅ EPM native handler যোগ করা |
| Token refresh on 401 | ✅ | ✅ EPM policy sync auth |

**সিদ্ধান্ত:** Task pipeline EPM policy management-এর জন্য ✅ সরাসরি পুনর্ব্যবহারযোগ্য। Real-time user elevation request (IPC path) এই pipeline-এ fit করে না।


---

## ১১. Software Inventory Assessment

### ১১.১ Windows (Registry, AppxPackage)

**File:** `internal/service/software/collect_windows.go`

**Data Model:**
```go
type SoftwareInfo struct {
    Name             string
    InstalledVersion string
    FilePath         string   // install location
    Source           string   // "programs", "microsoft_store"
    Type             string
    FirstSeenAt      string
}
```

**Collection Sources:**
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (machine-wide)
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (per-user)
- `HKEY_USERS` hive scan (সব users-এর software)
- `Get-AppxPackage -AllUsers` (Microsoft Store apps)
- Chrome/Edge/Brave/Firefox browser extensions
- UserAssist last-opened timestamps

| Field | বর্তমান | EPM matching-এর জন্য |
|-------|---------|---------------------|
| Name | ✅ আছে | ✅ name-based rule |
| Version | ✅ আছে | ✅ version-based rule |
| FilePath | ✅ আছে | ✅ path-based rule |
| Publisher/Vendor | ❌ নেই | ✅ publisher-based allow |
| File SHA-256 hash | ❌ নেই | ✅ hash-based allow |
| Digital signature info | ❌ নেই | ✅ code signing check |
| Certificate thumbprint | ❌ নেই | ✅ cert-based rule |
| Process name (runtime) | ❌ নেই | ✅ runtime matching |

### ১১.২ Linux (dpkg, rpm, snap, flatpak)

**File:** `internal/service/software/collect_linux.go`

**Collection Sources:**
- `dpkg-query -W -f='...'` — Debian/Ubuntu packages
- `rpm -qa --queryformat='...'` — Red Hat/SUSE packages
- `snap list --color=never` — Snap packages
- `flatpak list --columns=...` — Flatpak apps

| Field | বর্তমান | EPM matching-এর জন্য |
|-------|---------|---------------------|
| Name | ✅ আছে | ✅ name-based rule |
| Version | ✅ আছে | ✅ version-based rule |
| FilePath | ❌ নেই (packages-এর জন্য) | ✅ path-based rule দরকার |
| Publisher/Maintainer | ❌ নেই | ✅ দরকার |
| File hash | ❌ নেই | ✅ দরকার |
| RPM/DEB package signature | ❌ নেই | ✅ দরকার |

### ১১.৩ macOS (system_profiler, brew)

**File:** `internal/service/software/collect_darwin.go`

**Collection Sources:**
- `system_profiler SPApplicationsDataType -json` — installed .app bundles
- `brew list --versions` — Homebrew formulae
- `brew list --cask --versions` — Homebrew casks
- `mdls -name kMDItemLastUsedDate` — last-opened time via Spotlight

| Field | বর্তমান | EPM matching-এর জন্য |
|-------|---------|---------------------|
| Name | ✅ আছে | ✅ name-based rule |
| Version | ✅ আছে | ✅ version-based rule |
| FilePath | ✅ আছে (.app path) | ✅ path-based rule |
| Publisher/Developer | ❌ নেই | ✅ দরকার |
| File hash | ❌ নেই | ✅ দরকার |
| Code signature / Team ID | ❌ নেই | ✅ Team ID-based rule দরকার |
| Notarization status | ❌ নেই | ✅ macOS EPM-এ দরকার |

---

## ১২. Security Capability Assessment

### ১২.১ Shared (সব Platform)

**File:** `internal/updater/downloader.go`, `internal/updater/pubkey.go`

```go
// ed25519 public key hardcoded
var PublicKey = ed25519.PublicKey{0x62, 0x19, 0xa3, ...}

// SHA-256 checksum + ed25519 signature verification
func verifySignatureBytes(binaryBytes, sigBytes []byte, pubKey ed25519.PublicKey) error {
    if !ed25519.Verify(pubKey, binaryBytes, sigBytes) {
        return fmt.Errorf("ed25519 signature verification failed")
    }
    return nil
}
```

**সব platform-এ আছে:**
- ✅ ed25519 signature verification (binary update)
- ✅ SHA-256 checksum validation
- ✅ JWT-based authentication
- ✅ Circuit breaker (5 failures → 5 min lockout)
- ✅ Atomic config save
- ✅ Token rotation on refresh

### ১২.২ Windows-specific Security

**File:** `internal/winsec/winsec_windows.go`

- ✅ SDDL DACL (SY+BA) — SYSTEM ও Administrators শুধু file access পাবে
- ✅ `windows.SetNamedSecurityInfo()` — file ACL enforce
- ✅ `windows.GetCurrentProcessToken()` — process token read

**Missing:**
- ❌ Windows Authenticode verification (`WinVerifyTrust`, `CryptQueryObject`)
- ❌ Named Pipe security descriptor
- ❌ Token impersonation security

### ১২.৩ Linux-specific Security

**File:** `internal/winsec/winsec_other.go`

```go
// Linux/macOS-এ SecurePath() সম্পূর্ণ NO-OP
func SecurePath(path string) error { return nil }
```

File permission enforcement caller দ্বারা করা হয় (0600/0700 mode)।

**Missing:**
- ❌ RPM/DEB package signature verification
- ❌ AppArmor/SELinux policy integration
- ❌ Linux capability-based security (`libcap`)
- ❌ Unix socket credential verification (SO_PEERCRED)

### ১২.৪ macOS-specific Security

**File:** `internal/winsec/winsec_other.go` (same NO-OP as Linux)

**Missing:**
- ❌ `codesign` / `SecCodeCheckValidity()` — code signature verification
- ❌ Notarization check
- ❌ Gatekeeper bypass prevention
- ❌ XPC connection security

---

## ১৩. Logging & Telemetry Assessment

### ১৩.১ Windows (Event Log, 4688)

**File:** `internal/auditlogs/collector/collector_windows.go`

**Collected Event Channels:**

| Channel | Event IDs | EPM Relevance |
|---------|-----------|---------------|
| Security | 4688 | ✅ **Process creation — EPM audit-এ সরাসরি reuse** |
| Security | 4624/4625/4634 | ✅ Logon/logoff tracking |
| Security | 4672 | ✅ Privilege use |
| Security | 4656/4663/4670 | Object access |
| PowerShell/Operational | 4103/4104 | PowerShell activity |
| TerminalServices | 1149 | RDP session tracking |
| Windows Defender | `*` | Malware detection |

**Real-time subscription:** ✅ `procEvtSubscribe` দিয়ে Security channel real-time monitoring।

### ১৩.২ Linux (journald, auth.log)

**File:** `internal/auditlogs/collector/collector_linux.go`

**Collection Sources:**
- `journalctl -o json` — structured journal logs
- `journalctl -f -p 3` — real-time critical events
- `/var/log/auth.log` — authentication events (tail)
- `/var/log/syslog` — system events (tail)
- `/var/log/messages` — general system log (tail)
- `/var/log/kern.log` — kernel events (tail)

**EPM Relevance:**
- ✅ `auth.log` — `sudo` usage, PAM events — EPM audit-এ reuse সম্ভব
- ✅ `journalctl` — systemd service events
- ❌ Real-time subscription নেই (polling only — `journalctl -f` subprocess)

### ১৩.৩ macOS (unified log, system.log)

**File:** `internal/auditlogs/collector/collector_darwin.go`

**Collection Sources:**
- `log show --style ndjson` — Apple Unified Logging System
- `/var/log/system.log` — system log (tail)
- `/var/log/install.log` — software install log (tail)
- `/Library/Logs/DiagnosticReports` — crash reports

**EPM Relevance:**
- ✅ Unified log — process execution events ধরা যায়
- ❌ Real-time subscription **নেই** — polling only (`log show` repeated run)
- ❌ `BSM audit` (macOS audit subsystem) integration নেই

### ১৩.৪ EPM-specific Audit Requirements (সব Platform)

| Audit Event | Windows | Linux | macOS | EPM-তে দরকার |
|------------|---------|-------|-------|-------------|
| Process creation (system) | ✅ Event 4688 | ✅ auth.log/journal | ✅ unified log | ✅ reuse |
| Elevated process launch (EPM) | ❌ নেই | ❌ নেই | ❌ নেই | ✅ নতুন |
| Policy lookup/match | ❌ নেই | ❌ নেই | ❌ নেই | ✅ নতুন |
| Elevation request (who, what) | ❌ নেই | ❌ নেই | ❌ নেই | ✅ নতুন |
| Policy denial event | ❌ নেই | ❌ নেই | ❌ নেই | ✅ নতুন |
| Token/privilege grant audit | ❌ নেই | ❌ নেই | ❌ নেই | ✅ নতুন |

---

## ১৪. Configuration Management Assessment

### ১৪.১ বিদ্যমান Config (সব Platform)

**File:** `internal/config/config.go`

**Platform-specific config paths:**
- Windows: `C:\SentinelGo\.sentinelgo\config.json`
- Linux: `/etc/sentinelgo/config.json`
- macOS: `/Library/Application Support/sentinelgo/config.json`

**Features:**
- ✅ Atomic save (`SaveAtomic()`) — temp file + rename, race condition-safe
- ✅ File permission hardening (Windows DACL, other 0600)
- ✅ Feature flag toggle
- ✅ Runtime config update via task payload
- ✅ Config validation (`ValidateConfiguration()`)

### ১৪.২ EPM Config Requirements

| Config Feature | বর্তমান | EPM-তে দরকার |
|---------------|---------|-------------|
| `enable_epm` feature flag | ❌ নেই | ✅ সহজে যোগ করা যাবে |
| EPM policy sync interval | ❌ নেই | ✅ Duration field যোগ করতে হবে |
| EPM policy file path | ❌ নেই | ✅ platform-specific path দরকার |
| Atomic policy save | ✅ `SaveAtomic()` reuse | ✅ policy file-এও দরকার |
| Policy file permission hardening | ✅ (Windows) / ❌ (Linux/macOS) | ✅ সব platform-এ দরকার |
| Remote policy push | ⚠️ task-based (indirect) | ✅ EPM policy push channel দরকার |

**সিদ্ধান্ত:** Config infrastructure সব platform-এ ✅ EPM extension-এর জন্য ready। শুধু নতুন fields যোগ করতে হবে।


---

## ১৫. Cross-Platform Architecture Assessment

### ১৫.১ Build Tag Pattern

সমস্ত platform-specific code Go file naming convention (`_windows`, `_linux`, `_darwin`) অনুসরণ করে:

```
internal/auditlogs/collector/
    collector_windows.go     ← Windows Event Log API (wevtapi.dll)
    collector_linux.go       ← journald + syslog tail
    collector_darwin.go      ← macOS unified log + system.log

internal/service/software/
    collect_windows.go       ← Registry + PowerShell + AppxPackage
    collect_linux.go         ← dpkg + rpm + snap + flatpak
    collect_darwin.go        ← system_profiler + brew + mdls

internal/service/task/
    executor_windows.go      ← PowerShell + CMD
    executor_linux.go        ← bash + python3 + sudo
    executor_darwin.go       ← bash + python3 (root, no sudo needed)

internal/winsec/
    winsec_windows.go        ← SDDL DACL, SetNamedSecurityInfo
    winsec_other.go          ← NO-OP for Linux + macOS

cmd/sentinelgo/service/
    svc_windows.go           ← SCM Windows Service
    svc_linux.go             ← systemd unit file
    svc_darwin.go            ← launchd plist

internal/service/software/
    userhomes_windows.go     ← C:\Users\ scan
    userhomes_linux.go       ← /root + /home/* scan
    userhomes_darwin.go      ← /Users/* scan (Shared/Guest exclude)
```

### ১৫.২ Shared Layer (Platform-Agnostic)

| Component | Path | সব Platform-এ কাজ করে |
|-----------|------|----------------------|
| Task queue + polling | `internal/service/task/` | ✅ |
| SQLite store + migration | `internal/store/` | ✅ |
| Config management | `internal/config/` | ✅ |
| Auth + JWT + circuit breaker | `internal/service/auth/` | ✅ |
| SHA-256 + ed25519 crypto | `internal/updater/` | ✅ |
| HTTP client (Supabase) | `internal/httpx/` | ✅ |
| Audit log pipeline | `internal/logging/` | ✅ |
| Native handler registry | `internal/service/task/native/` | ✅ |
| Scheduler | `internal/scheduler/` | ✅ |
| Models / data types | `internal/models/` | ✅ |

### ১৫.৩ Platform-Specific Layer

| Capability | Windows | Linux | macOS |
|-----------|---------|-------|-------|
| Service daemon | SCM (`svc_windows.go`) | systemd (`svc_linux.go`) | launchd (`svc_darwin.go`, `launchd.go`) |
| Privilege level | SYSTEM | root | root |
| Process execution | PowerShell/CMD | bash/python3/sudo | bash/python3 |
| Audit collection | wevtapi.dll | journald/syslog | unified log/system.log |
| Software inventory | Registry/AppxPackage | dpkg/rpm/snap/flatpak | system_profiler/brew |
| File security | SDDL DACL (winsec) | chmod 0600 | chmod 0600 |
| User home detection | `C:\Users\` scan | `/home/*` scan | `/Users/*` scan |
| IPC (EPM-তে দরকার) | Named Pipe | Unix Socket | XPC Service |
| Process launch (EPM) | `CreateProcessAsUser` | `fork`+`setresuid`+`execve` | `AuthorizationExecuteWithPrivileges` |
| App signature (EPM) | Authenticode | RPM/DEB signing | `SecCodeCheckValidity` |
| User auth (EPM) | WTS token | PAM / polkit | Authorization Services |

### ১৫.৪ Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    SentinelGo Agent                          │
├─────────────────────┬─────────────────┬─────────────────────┤
│   SHARED LAYER      │                 │                      │
│ (সব platform-এ same)│                 │                      │
│ ─────────────────── │                 │                      │
│ • Task Pipeline     │                 │                      │
│ • SQLite Store      │                 │                      │
│ • Config Mgmt       │                 │                      │
│ • Auth/JWT/CB       │                 │                      │
│ • SHA-256/ed25519   │                 │                      │
│ • HTTP/Supabase     │                 │                      │
│ • Audit Pipeline    │                 │                      │
├─────────────────────┼─────────────────┼─────────────────────┤
│   WINDOWS LAYER     │   LINUX LAYER   │   macOS LAYER        │
│ ─────────────────── │ ─────────────── │ ─────────────────── │
│ • SCM Service       │ • systemd       │ • launchd            │
│ • SYSTEM account    │ • root process  │ • root daemon        │
│ • PowerShell/CMD    │ • bash/python3  │ • bash/python3       │
│ • wevtapi.dll       │ • journald      │ • unified log        │
│ • Registry+AppxPkg  │ • dpkg/rpm/snap │ • system_profiler    │
│ • SDDL DACL         │ • chmod 0600    │ • chmod 0600         │
│                     │                 │                      │
│   [EPM MISSING]     │  [EPM MISSING]  │  [EPM MISSING]       │
│ • WTS/token APIs    │ • polkit/D-Bus  │ • Auth Services      │
│ • CreateProcAsUser  │ • setresuid     │ • SMJobBless/XPC     │
│ • Named Pipe IPC    │ • Unix Socket   │ • XPC Service        │
│ • Authenticode      │ • PAM/caps      │ • SecCodeCheckValid  │
└─────────────────────┴─────────────────┴─────────────────────┘
```

---

## ১৬. Existing Components That Can Be Reused (সব Platform)

| Component | File Path | Reuse Type | Platform Coverage |
|-----------|-----------|-----------|------------------|
| Windows Service Infrastructure | `cmd/sentinelgo/service/svc_windows.go` | ✅ Direct | Windows |
| systemd Service Infrastructure | `cmd/sentinelgo/service/svc_linux.go` | ✅ Direct | Linux |
| launchd Daemon Infrastructure | `cmd/sentinelgo/service/svc_darwin.go`, `launchd.go` | ✅ Direct | macOS |
| File ACL Hardening | `internal/winsec/winsec_windows.go` | ✅ Direct | Windows |
| Config Management + Atomic Save | `internal/config/config.go` | ✅ Extend | All |
| SQLite Store + Migration | `internal/store/schema.go` | ✅ Direct | All |
| Task Polling Pipeline | `internal/service/task/polling.go` | ✅ Direct | All |
| Native Handler Registry | `internal/service/task/native/registry.go` | ✅ Direct | All |
| SHA-256 + ed25519 Verification | `internal/updater/downloader.go` | ✅ Direct | All |
| Audit Log Pipeline | `internal/logging/logging.go` | ✅ Direct | All |
| Event 4688 Collection | `internal/auditlogs/collector/collector_windows.go` | ✅ Direct | Windows |
| journald/auth.log Collection | `internal/auditlogs/collector/collector_linux.go` | ✅ Direct | Linux |
| Unified Log Collection | `internal/auditlogs/collector/collector_darwin.go` | ✅ Direct | macOS |
| Auth + Circuit Breaker | `internal/service/auth/auth.go` | ✅ Direct | All |
| Software Inventory Base | `internal/service/software/collect_*.go` | ✅ Extend | Per-platform |
| User Home Detection | `internal/service/software/userhomes_*.go` | ✅ Direct | Per-platform |
| Context Cancellation Pattern | Throughout codebase | ✅ Direct | All |
| Watchdog Pattern | `internal/service/task/executor.go` | ✅ Direct | All |
| Task Retry Logic | `internal/service/task/executor.go` | ✅ Direct | All |
| HTTP Client Wrapper | `internal/httpx/` | ✅ Direct | All |

---

## ১৭. Platform-Specific Missing Components

### ১৭.১ Windows Missing

| Missing Component | Complexity | বিবরণ |
|------------------|-----------|-------|
| WTS Session Management | উচ্চ | `WTSGetActiveConsoleSessionId`, `WTSQueryUserToken`, `WTSEnumerateSessions` |
| Token Manipulation | উচ্চ | `DuplicateTokenEx`, `AdjustTokenPrivileges`, `ImpersonateLoggedOnUser` |
| `CreateProcessAsUser` / `CreateProcessWithTokenW` | উচ্চ | User context-এ elevated process launch |
| `CreateEnvironmentBlock` | কম | User environment block |
| Named Pipe IPC Server (SYSTEM side) | উচ্চ | `CreateNamedPipe`, `ConnectNamedPipe`, security descriptor |
| Named Pipe IPC Client (user-space) | উচ্চ | `CreateFile(\\.\\pipe\\...)`, reconnect logic |
| Windows Authenticode Verification | উচ্চ | `WinVerifyTrust`, `CryptQueryObject`, `WTHelperProvDataFromStateData` |
| Session 0 Isolation Handling | উচ্চ | Service → User desktop launch, window station |
| User-space EPM Client Binary | উচ্চ | Separate binary, user desktop-এ চলবে |

### ১৭.২ Linux Missing

| Missing Component | Complexity | বিবরণ |
|------------------|-----------|-------|
| `setuid`/`setresuid` User Drop | মাঝারি | Specific user context-এ process spawn |
| `fork()` + `execve()` Pattern | মাঝারি | User process launch without shell |
| polkit / D-Bus Authorization | উচ্চ | `org.freedesktop.PolicyKit1` D-Bus API |
| PAM Authentication | মাঝারি | User identity verify |
| Linux Capabilities (`cap_setuid`) | মাঝারি | Fine-grained privilege management |
| Unix Domain Socket IPC | মাঝারি | `/var/run/sentinelgo/epm.sock` server/client |
| User-space EPM Client | উচ্চ | Standard user context-এ চলবে |
| Package Signature Verification | মাঝারি | RPM/DEB signing check |
| `getpwuid`/`getgrnam` lookup | কম | User/group info |
| Real-time audit log subscription | মাঝারি | `journalctl -f` replacement |

### ১৭.৩ macOS Missing

| Missing Component | Complexity | বিবরণ |
|------------------|-----------|-------|
| Authorization Services Integration | উচ্চ | `AuthorizationCreate`, `AuthorizationCopyRights` |
| `AuthorizationExecuteWithPrivileges` | উচ্চ | Elevated process launch (deprecated but functional) |
| SMJobBless / Privileged Helper | উচ্চ | `ServiceManagement.framework` — proper macOS EPM pattern |
| XPC Service IPC | উচ্চ | Root daemon ↔ User agent communication |
| `SecCodeCheckValidity` | উচ্চ | Code signature verification |
| `SecCertificateCopySubjectSummary` | মাঝারি | Certificate/Team ID extraction |
| Notarization Check | উচ্চ | `spctl --assess` or Security framework |
| User-space EPM Client (Login Item) | উচ্চ | User session-এ চলবে |
| Real-time Log Subscription | উচ্চ | `log stream` replacement (polling এখন আছে) |
| SIP bypass-aware policy | উচ্চ | System Integrity Protection compatibility |

### ১৭.৪ Shared Missing (সব Platform)

| Missing Component | Complexity | বিবরণ |
|------------------|-----------|-------|
| EPM Policy Engine | উচ্চ | Rule evaluation: hash → publisher → path → wildcard priority |
| EPM Policy SQLite Schema | কম | `epm_policies` table, `epm_grants` table, `epm_audit` table |
| Application Hash Computation (runtime) | কম | SHA-256 of executable file before launch |
| EPM Audit Event Logger | কম | Existing audit pipeline-এ নতুন category |
| Policy Sync Native Handler | কম | `epm-policy-sync` handler — existing registry reuse |
| Per-user Policy Enforcement | মাঝারি | User SID/UID-based policy lookup |
| Time-based Policy Expiry | মাঝারি | JIT access, expiry enforcement |
| EPM Config Fields | কম | `enable_epm`, `epm_policy_sync_interval` in config.go |


---

## ১৮. Gap Analysis

### ১৮.১ Critical Gaps per Platform

**Windows — সবচেয়ে বড় gap:**

```
[বর্তমান]
SYSTEM service → exec.Command("powershell", ...) → SYSTEM context child process

[EPM-তে দরকার]
SYSTEM service
    → WTSQueryUserToken(WTSGetActiveConsoleSessionId())  → user's token
    → DuplicateTokenEx(userToken, TOKEN_PRIMARY)          → elevated token
    → AdjustTokenPrivileges(elevatedToken)                → privilege add
    → CreateEnvironmentBlock(elevatedToken)               → user environment
    → CreateProcessAsUser(
          elevatedToken,
          appPath,
          desktop = "winsta0\\default"                    → user desktop
      )
    → process launches elevated on user's interactive desktop
```

**Linux — সবচেয়ে বড় gap:**

```
[বর্তমান]
root daemon → exec.Command("bash", ...) → root child process
                                          OR sudo wrapper

[EPM-তে দরকার]
root daemon
    → getpwnam(username)              → user info (uid, gid, home)
    → fork()
         → child:
              setgroups(gid)
              setresuid(uid, uid, uid)  → drop to user
              setresgid(gid, gid, gid)
              setenv("HOME", ...)       → user environment
              execve(appPath, ...)      → run as user (with specific caps)
    → parent: wait for result
              report elevation to audit log
```

**macOS — সবচেয়ে বড় gap:**

```
[বর্তমান]
launchd root daemon → exec.Command("bash", ...) → root child process

[EPM-তে দরকার — SMJobBless pattern]
User-space EPM client (Login Item, user session)
    → AuthorizationCreate()                    → authorization ref
    → AuthorizationCopyRights(right)           → check policy
    → XPC message to root helper
         → root helper (SMJobBless-installed)
              → SecCodeCheckValidity(appPath)  → verify signature
              → policy lookup
              → fork()+setuid()+execve()       → launch as user with caps
         → result via XPC
    → client notifies user
```

### ১৮.২ Gap Summary Table

| Gap | Windows | Linux | macOS | Impact | Effort |
|-----|---------|-------|-------|--------|--------|
| User session token / credential | 🔴 Blocker | 🔴 Blocker | 🔴 Blocker | Critical | Large |
| Elevated process launch | 🔴 Blocker | 🔴 Blocker | 🔴 Blocker | Critical | Large |
| Local IPC layer | 🔴 Blocker | 🔴 Blocker | 🔴 Blocker | Critical | Large |
| User-space EPM client | 🔴 Blocker | 🔴 Blocker | 🔴 Blocker | Critical | Large |
| EPM policy engine | 🟠 High | 🟠 High | 🟠 High | High | Medium |
| App signature verification | 🟠 High | 🟡 Medium | 🔴 High | High | Medium–High |
| Policy storage schema | 🟡 Medium | 🟡 Medium | 🟡 Medium | Medium | Small |
| EPM audit events | 🟡 Medium | 🟡 Medium | 🟡 Medium | Medium | Small |
| Session management | 🔴 Windows-only critical | 🟡 Medium | 🟠 High | Platform-specific | Medium |
| Platform-specific IPC | Named Pipe | Unix Socket | XPC | Critical | Large |

---

## ১৯. Estimated Development Complexity

### ১৯.১ Windows Effort

| Component | Effort |
|-----------|--------|
| WTS session management wrapper | ২–৩ সপ্তাহ |
| Token manipulation + `CreateProcessAsUser` | ৩–৪ সপ্তাহ |
| Named Pipe IPC server (SYSTEM side) | ২–৩ সপ্তাহ |
| Named Pipe IPC client (user-space binary) | ২–৩ সপ্তাহ |
| Windows Authenticode verification | ১–২ সপ্তাহ |
| Session 0 isolation + UI dialog | ৩–৪ সপ্তাহ |
| Integration testing (real Windows env) | ৩–৪ সপ্তাহ |
| Security audit | ২–৩ সপ্তাহ |
| **Windows subtotal** | **১৮–২৬ সপ্তাহ** |

### ১৯.২ Linux Effort

| Component | Effort |
|-----------|--------|
| `fork`+`setresuid`+`execve` user launch | ২–৩ সপ্তাহ |
| polkit / D-Bus authorization | ৩–৪ সপ্তাহ |
| Unix Domain Socket IPC | ২–৩ সপ্তাহ |
| User-space EPM client (Linux) | ২–৩ সপ্তাহ |
| PAM integration | ১–২ সপ্তাহ |
| RPM/DEB signature verification | ১–২ সপ্তাহ |
| Integration testing | ২–৩ সপ্তাহ |
| **Linux subtotal** | **১৩–২০ সপ্তাহ** |

### ১৯.৩ macOS Effort

| Component | Effort |
|-----------|--------|
| Authorization Services integration | ৩–৪ সপ্তাহ |
| SMJobBless privileged helper | ৩–৪ সপ্তাহ |
| XPC Service IPC | ৩–৪ সপ্তাহ |
| `SecCodeCheckValidity` + notarization | ২–৩ সপ্তাহ |
| User-space EPM client (macOS Login Item) | ২–৩ সপ্তাহ |
| Apple Developer signing + notarization | ১–২ সপ্তাহ |
| Integration testing | ২–৩ সপ্তাহ |
| **macOS subtotal** | **১৬–২৩ সপ্তাহ** |

### ১৯.৪ Shared Components Effort

| Component | Effort |
|-----------|--------|
| EPM policy engine (rule evaluation) | ৩–৪ সপ্তাহ |
| EPM SQLite schema + migration | ১ সপ্তাহ |
| App hash computation (SHA-256 on-demand) | ০.৫ সপ্তাহ |
| EPM audit event logger | ১ সপ্তাহ |
| Policy sync native handler | ১ সপ্তাহ |
| EPM config fields | ০.৫ সপ্তাহ |
| **Shared subtotal** | **৭–৮ সপ্তাহ** |

### ১৯.৫ Total Timeline

| Approach | Duration |
|----------|----------|
| Windows only | ২৫–৩৪ সপ্তাহ (shared + Windows) |
| Linux only | ২০–২৮ সপ্তাহ (shared + Linux) |
| macOS only | ২৩–৩১ সপ্তাহ (shared + macOS) |
| সব তিনটি platform (sequential) | ৪৪–৫৭ সপ্তাহ |
| সব তিনটি platform (parallel 3-dev team) | ২৫–৩৪ সপ্তাহ |

---

## ২০. Risks & Limitations

### ২০.১ Windows Risks

| Risk | Severity | বিবরণ |
|------|---------|-------|
| Token security vulnerability | 🔴 High | `CreateProcessAsUser` ভুলভাবে implement হলে privilege escalation |
| Session 0 isolation complexity | 🔴 High | Service (Session 0) থেকে user desktop (Session 1+) UI interaction |
| Named Pipe race condition | 🟠 Medium | TOCTOU attack সম্ভব — pipe security descriptor critical |
| Multi-session (RDP) confusion | 🟠 Medium | একাধিক logged-in user — কোন session-এ launch করবে? |
| CGO constraint on Authenticode | 🟠 Medium | `WinVerifyTrust` CGO-free কিনা verify করতে হবে |
| Anti-tampering of user-space client | 🟠 Medium | Client tamper → policy bypass |

### ২০.২ Linux Risks

| Risk | Severity | বিবরণ |
|------|---------|-------|
| polkit version fragmentation | 🟠 Medium | Ubuntu, RHEL, openSUSE-তে polkit API ভিন্ন হতে পারে |
| sudo vs polkit conflict | 🟠 Medium | `sudo -S` বর্তমান pattern-এর সাথে polkit conflict হতে পারে |
| Container/systemd-nspawn | 🟡 Low | Container environment-এ `setuid` কাজ না করতে পারে |
| distro diversity | 🟠 Medium | 10+ distro — dpkg/rpm/snap/flatpak testing complex |
| Unix socket symlink attack | 🟠 Medium | Socket path অবশ্যই hardened directory-তে থাকতে হবে |

### ২০.৩ macOS Risks

| Risk | Severity | বিবরণ |
|------|---------|-------|
| SIP (System Integrity Protection) | 🔴 High | `/System`, `/usr` directory-তে write block — EPM path constraint |
| Gatekeeper / notarization | 🔴 High | unsigned helper tool macOS-এ চলবে না |
| `AuthorizationExecuteWithPrivileges` deprecated | 🟠 Medium | Apple deprecated করেছে — SMJobBless preferred কিন্তু complex |
| Apple Developer Program requirement | 🟠 Medium | Notarization-এর জন্য paid Apple Developer account দরকার |
| macOS version fragmentation | 🟡 Low | API availability macOS 12+ vs 13+ vs 14+ ভিন্ন হতে পারে |

### ২০.৪ Cross-Platform Risks

| Risk | Severity | বিবরণ |
|------|---------|-------|
| Separate user-space binary | 🟠 Medium | Installation, update, versioning complexity তিনটি platform-এই |
| Security audit requirement | 🔴 High | Privilege escalation code — mandatory external audit |
| Go UI framework limitation | 🟠 Medium | EPM dialog UI — Go-তে native Windows/Linux/macOS UI limited |
| CI/CD environment complexity | 🟡 Low | Real OS + standard user account-এ test করতে হবে |


---

## ২১. Overall Readiness Score

### ২১.১ Per-Platform Score (বিস্তারিত category table)

**Windows:**

| Category | Score | বিবরণ |
|---------|-------|-------|
| Service Infrastructure (SCM/SYSTEM) | 9/10 | Production-ready, SCM-managed SYSTEM service |
| Process Execution (basic) | 5/10 | PowerShell/CMD আছে, user-context launch নেই |
| Windows API Usage | 2/10 | শুধু ACL + Event Log — token/WTS API নেই |
| User Session Management | 1/10 | Home dir detection শুধু — WTS সম্পূর্ণ absent |
| IPC Layer | 0/10 | Named Pipe সম্পূর্ণ অনুপস্থিত |
| Policy Management | 4/10 | Task pipeline আছে, EPM schema নেই |
| Software Inventory | 5/10 | Path/version আছে, hash/publisher/signature নেই |
| Security Features | 6/10 | SHA-256/ed25519 আছে, Authenticode নেই |
| Logging & Telemetry | 8/10 | Event 4688 captured, EPM-specific log নেই |
| Configuration Management | 8/10 | Mature, extension-ready |
| **Windows Overall** | **4.0/10** | Foundation শক্ত, token/IPC/process-launch missing |

**Linux:**

| Category | Score | বিবরণ |
|---------|-------|-------|
| Service Infrastructure (systemd/root) | 8/10 | systemd unit, root process, auto-restart |
| Process Execution (basic) | 5/10 | bash/python3/sudo আছে, user-context spawn নেই |
| Linux API/Syscall Usage | 2/10 | exec.Command শুধু — setuid/setresuid/fork নেই |
| User Session Management | 1/10 | Home dir scan শুধু — loginctl/utmp/polkit নেই |
| IPC Layer | 0/10 | Unix Socket সম্পূর্ণ অনুপস্থিত |
| Policy Management | 4/10 | Task pipeline আছে, EPM schema নেই |
| Software Inventory | 4/10 | name/version আছে, FilePath/hash নেই |
| Security Features | 5/10 | SHA-256/ed25519 আছে, cap/polkit/PAM নেই |
| Logging & Telemetry | 7/10 | journald/auth.log আছে, real-time subscription নেই |
| Configuration Management | 8/10 | Mature, extension-ready |
| **Linux Overall** | **3.5/10** | Foundation ভালো, platform-specific EPM APIs সব missing |

**macOS:**

| Category | Score | বিবরণ |
|---------|-------|-------|
| Service Infrastructure (launchd/root) | 8/10 | LaunchDaemon, root, KeepAlive |
| Process Execution (basic) | 5/10 | bash/python3 আছে, user-context spawn নেই |
| macOS API/Framework Usage | 1/10 | exec.Command শুধু — Security.framework/XPC সম্পূর্ণ absent |
| User Session Management | 1/10 | /Users/* scan শুধু — SCDynamicStore/loginctl নেই |
| IPC Layer | 0/10 | XPC Service সম্পূর্ণ অনুপস্থিত |
| Policy Management | 4/10 | Task pipeline আছে, EPM schema নেই |
| Software Inventory | 5/10 | FilePath + name + version আছে, Team ID/codesign নেই |
| Security Features | 4/10 | SHA-256/ed25519 আছে, SecCodeCheckValidity/notarization নেই |
| Logging & Telemetry | 6/10 | unified log আছে, real-time subscription নেই |
| Configuration Management | 8/10 | Mature, extension-ready |
| **macOS Overall** | **3.0/10** | Foundation আছে, macOS security framework সম্পূর্ণ absent |

### ২১.২ Summary Score Table

| Platform | Overall Score | Foundation | EPM-Critical Missing | Verdict |
|----------|---------------|------------|---------------------|---------|
| **Windows** | **4.0 / 10** | SCM + SYSTEM + Event Log + ACL | WTS token, CreateProcessAsUser, Named Pipe | EPM-buildable |
| **Linux** | **3.5 / 10** | systemd + root + journald | setresuid, polkit, Unix Socket | EPM-buildable |
| **macOS** | **3.0 / 10** | launchd + root + unified log | Authorization Services, SMJobBless, XPC | EPM-buildable (hardest) |

**EPM Readiness Breakdown (সব platform combined):**

```
✅ Ready (~30% of EPM scope) — সব platform-এ:
   • Privileged daemon infrastructure
   • Task delivery and command pipeline
   • SQLite durable storage
   • Audit logging pipeline
   • Crypto primitives (SHA-256, ed25519)
   • Config management

⚠️ Partially Ready (~20% of EPM scope) — per-platform:
   • Software inventory (needs hash/publisher/signature)
   • Policy storage (needs EPM schema)
   • Platform-specific security (needs extension)

❌ Not Ready (~50% of EPM scope) — সব platform-এ:
   • User session management (WTS / loginctl / SCDynamicStore)
   • Token/credential-based process launch
   • Local IPC (Named Pipe / Unix Socket / XPC)
   • User-space EPM client binary
   • EPM policy engine
   • Platform-specific signature verification
   • Session isolation handling
```

---

## ২২. Recommended Implementation Strategy

### ২২.১ Phased Approach

**Phase 1 — Windows First (২৫–৩৪ সপ্তাহ)**

Windows-এ প্রথমে implement করার কারণ:
- WTS API সবচেয়ে mature ও documented
- `golang.org/x/sys/windows` package-এ most bindings আছে
- EPM concept Windows-এ সবচেয়ে সুপরিচিত (UAC replacement)
- Enterprise market Windows-centric

**মূল deliverables:**
1. `internal/winsec/token_windows.go` — WTS + token manipulation
2. `internal/epm/pipe_windows.go` — Named Pipe IPC server
3. `cmd/sentinelgo-epm/main_windows.go` — user-space client binary
4. `internal/epm/policy.go` — shared policy engine
5. `internal/store/epm_schema.go` — SQLite EPM tables

**Phase 2 — Linux (১৩–২০ সপ্তাহ, Windows-এর পরে)**

Linux-এ দ্বিতীয় কারণ:
- `fork`+`setresuid`+`execve` pattern Windows WTS-এর চেয়ে conceptually simpler
- Policy engine (Phase 1-এ তৈরি) reuse করা যাবে
- Enterprise Linux (RHEL, Ubuntu Server) EPM demand growing

**মূল deliverables:**
1. `internal/epm/process_linux.go` — fork+setresuid+execve
2. `internal/epm/polkit_linux.go` — PolicyKit D-Bus integration
3. `internal/epm/socket_linux.go` — Unix Domain Socket IPC
4. `cmd/sentinelgo-epm/main_linux.go` — user-space client

**Phase 3 — macOS (১৬–২৩ সপ্তাহ, সবার শেষে)**

macOS সবার শেষে কারণ:
- SMJobBless + XPC সবচেয়ে complex
- Apple Developer notarization overhead
- SIP restriction সবচেয়ে restrictive

**মূল deliverables:**
1. `internal/epm/authorization_darwin.go` — Authorization Services
2. `cmd/sentinelgo-epm-helper/main_darwin.go` — SMJobBless helper
3. `internal/epm/xpc_darwin.go` — XPC Service IPC
4. `cmd/sentinelgo-epm/main_darwin.go` — user Login Item

### ২২.২ Shared Layer Design

তিনটি platform-এর আগে এই shared components তৈরি করুন (৭–৮ সপ্তাহ):

```go
// internal/epm/policy.go — platform-agnostic policy engine
type PolicyRule struct {
    ID          string
    AppHash     string         // SHA-256
    AppPath     string         // path glob
    Publisher   string         // publisher/team ID
    UserSID     string         // Windows SID or Linux UID or macOS user
    AllowDeny   PolicyDecision // ALLOW | DENY | PROMPT
    ExpiresAt   *time.Time     // JIT access expiry
    CreatedAt   time.Time
}

type PolicyEngine interface {
    Evaluate(ctx context.Context, req ElevationRequest) (PolicyDecision, error)
    Sync(ctx context.Context, rules []PolicyRule) error
    LoadFromStore(ctx context.Context) error
}

// internal/store/epm_schema.go — SQLite migration
const epmMigration = `
CREATE TABLE IF NOT EXISTS epm_policies (
    id          TEXT PRIMARY KEY,
    app_hash    TEXT,
    app_path    TEXT,
    publisher   TEXT,
    user_id     TEXT,
    decision    TEXT NOT NULL,
    expires_at  DATETIME,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS epm_audit (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id   TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    app_path     TEXT NOT NULL,
    app_hash     TEXT,
    decision     TEXT NOT NULL,
    policy_id    TEXT,
    launched_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    synced       BOOLEAN DEFAULT 0
);
`
```

**Shared layer elements:**
- Policy engine (rule evaluation, priority: hash → publisher → path → wildcard)
- SQLite schema (epm_policies, epm_audit, epm_grants)
- SHA-256 on-demand hash computation
- EPM config fields (`enable_epm`, `epm_policy_sync_interval`)
- EPM audit logger (existing pipeline-এ নতুন category)
- Policy sync native handler (existing `registry.go` pattern)

### ২২.৩ Quick Wins (প্রথম সপ্তাহে করা যাবে — সব platform)

1. **`internal/config/config.go`-তে EPM flags যোগ করুন:**
   ```go
   EPMEnabled           bool     `json:"enable_epm"`
   EPMPolicySyncInterval Duration `json:"epm_policy_sync_interval"`
   ```

2. **`internal/store/schema.go`-তে migration যোগ করুন:**
   `epm_policies` এবং `epm_audit` tables।

3. **`internal/service/task/native/registry.go`-তে handler register করুন:**
   `epm-policy-sync` slug।

4. **`internal/models/model.go`-তে constants যোগ করুন:**
   ```go
   LogCategoryEPM = "EPM_ELEVATION"
   ```

5. **`internal/winsec/winsec_other.go`-কে extend করুন:**
   Linux/macOS-এ file permission hardening যোগ করুন (বর্তমানে NO-OP)।

### ২২.৪ Avoid করুন

- ❌ UAC bypass technique ব্যবহার করবেন না — `WTSQueryUserToken` → `CreateProcessAsUser` legitimate flow ব্যবহার করুন
- ❌ Token handle disk-এ লিখবেন না — memory-only
- ❌ User password collect বা store করবেন না
- ❌ Named Pipe-এ impersonation ছাড়া request accept করবেন না
- ❌ Linux-এ `sudo -S` password injection EPM-এর জন্য ব্যবহার করবেন না — polkit/setresuid pattern ব্যবহার করুন
- ❌ macOS-এ `AuthorizationExecuteWithPrivileges` deprecation ignore করবেন না — SMJobBless long-term path
- ❌ Security audit skip করবেন না — privilege escalation code mandatory review দরকার
- ❌ CGO না ভেঙে Authenticode implement করার চেষ্টা না করে আগে `golang.org/x/sys/windows` দিয়ে feasibility verify করুন

---

## ২৩. Conclusion

SentinelGo agent তিনটি platform-এই EPM feature implement করার জন্য একটি **solid infrastructure foundation** প্রদান করে। প্রতিটি platform-এ privileged daemon (SYSTEM/root), robust task pipeline, SQLite durable storage, audit logging, এবং cryptographic primitives (SHA-256, ed25519) বিদ্যমান।

তবে EPM-এর core mechanism — **user context-এ elevated process launch**, **local IPC**, এবং **platform-specific authorization** — তিনটি platform-এই **সম্পূর্ণ অনুপস্থিত**।

**Per-platform summary:**

- **Windows (4.0/10):** SYSTEM service ও Windows API access সবচেয়ে EPM-friendly। `golang.org/x/sys/windows` package-এ WTS ও token API bindings আছে। Named Pipe IPC + `CreateProcessAsUser` pipeline implement করা technically straightforward — কিন্তু security-critical।

- **Linux (3.5/10):** systemd root daemon ও `fork`+`setresuid`+`execve` pattern conceptually simple। কিন্তু polkit/D-Bus integration এবং distro diversity (Debian/RHEL/Arch) complexity বাড়ায়।

- **macOS (3.0/10):** launchd root daemon আছে, কিন্তু Apple-এর SIP, Gatekeeper, notarization requirement, এবং SMJobBless/XPC complexity তিনটির মধ্যে সবচেয়ে challenging platform।

**সংক্ষেপে:**

> Agent "EPM-ready" নয়, কিন্তু "EPM-buildable" — বিদ্যমান foundation-এর উপর দাঁড়িয়ে EPM implement করা feasible। Windows দিয়ে শুরু করুন, shared policy layer আগে তৈরি করুন, এবং security audit কোনো অবস্থাতেই skip করবেন না।

**মোট অনুমানিত timeline (sequential):** ৪৪–৫৭ সপ্তাহ | **Parallel 3-team:** ২৫–৩৪ সপ্তাহ

---

_এই document শুধুমাত্র existing codebase-এর inspection-ভিত্তিক assessment। কোনো source file পরিবর্তন করা হয়নি।_
_Scope: Windows (`svc_windows.go`, `executor_windows.go`, `winsec_windows.go`, `collector_windows.go`, `collect_windows.go`) + Linux (`svc_linux.go`, `executor_linux.go`, `collector_linux.go`, `collect_linux.go`) + macOS (`svc_darwin.go`, `launchd.go`, `executor_darwin.go`, `collector_darwin.go`, `collect_darwin.go`) + Shared (`config.go`, `store/schema.go`, `task/native/registry.go`, `updater/downloader.go`, `logging/logging.go`)_

---

## Addendum — Implementation Status (post-assessment)

*Added after this assessment, once EPM was actually implemented. Everything above is the original, pre-implementation gap analysis and is left unmodified as the historical record; this section reconciles it against what shipped. See `.kiro/specs/epm/{requirements,design,tasks}.md` for the full spec and task-by-task status, and `docs/EPM-Operator-Guide.md` for how to use it.*

### What shipped, against each "missing" item this assessment identified

**Shared layer (§22.2's proposed design, §16 reuse table) — built as designed, with one addition:**
- `internal/epm/policy.go` — the exact `PolicyRule`/priority-tiered `Engine.Evaluate` design proposed here, plus a `RuleProvider` interface (not anticipated in this assessment) so the enforcement layer always evaluates against live rules rather than a cached snapshot.
- `internal/store/epm.go` — `epm_policies` and `epm_audit_log` tables, matching this document's proposed schema closely (the audit table's `synced` flag and `request_id` unique index came from cross-referencing the existing `internal/store/auditlogs.go` pattern rather than being newly invented).
- `internal/config/config.go` — `enable_epm` / `epm_policy_sync_interval`, exactly as proposed in §22.3.
- `internal/models/model.go` — `LogCategoryEPM = "EPM_ELEVATION_LOG"` (this assessment's §22.3 suggested `"EPM_ELEVATION"`; the shipped value follows the existing `_LOG` suffix convention every other `LogCategory*` constant in that file uses).
- `internal/service/task/native/epm_policy_sync.go` — registered under slug `epm-policy-sync`, exactly as proposed.
- §22.4's "avoid" list was followed throughout: the legitimate `WTSQueryUserToken`→`CreateProcessAsUser` flow was used (never a UAC bypass technique), no token or password is ever persisted to disk, and the Named Pipe server independently re-derives the caller's identity from the OS rather than trusting the client — this document's warning about accepting pipe requests "without impersonation" was addressed differently than literally suggested (impersonating the client was not needed once `GetNamedPipeClientProcessId`→`ProcessIdToSessionId`→`WTSQueryUserToken` gives an independently-verified identity).

**Windows (§17.1's "missing" table, §4.1's API list) — every item now implemented:**
`WTSGetActiveConsoleSessionId`, `WTSEnumerateSessions`, `WTSQueryUserToken` (`session_windows.go`); `DuplicateTokenEx`, `CreateEnvironmentBlock` (`token_windows.go`); `CreateProcessAsUser` (`launcher_windows.go`); Named Pipe IPC with ACL (`pipe_windows.go`) — `ImpersonateNamedPipeClient` specifically was *not* needed, superseded by the session-derivation approach above; `WinVerifyTrust`/`CryptQueryObject`-equivalent Authenticode verification (`codesign_windows.go`, using `WinVerifyTrustEx` — all of it available directly via `golang.org/x/sys/windows`, no cgo or raw `NewLazyDLL` binding needed except for the one function that package doesn't wrap, `CryptMsgClose`, loaded via `windows.NewLazySystemDLL` exactly as this codebase already does for `wevtapi.dll`).

**Linux (§17.2, §4.2) — implemented with one deliberate deviation from what this assessment proposed:**
`polkit`/D-Bus authorization and `fork`+`setresuid`+`execve` privilege-*dropping* were assessed as the needed mechanism. Once actually building it, that framing turned out to be backwards for EPM's purpose: the daemon already holds root, and the goal is extending that privilege to one approved app on the user's desktop, not dropping to the user's level (which is that the user's own unprivileged shell can already do without any of this). The shipped `launcher_linux.go` keeps the daemon's root privilege and attaches the launched process to the user's GUI session by recovering `DISPLAY`/`XAUTHORITY`/`WAYLAND_DISPLAY`/`DBUS_SESSION_BUS_ADDRESS` from a live process's `/proc/<pid>/environ` — no `polkit`/`pkexec` (which would show a redundant re-authentication prompt after policy already said yes) and no PAM binding. Session discovery uses `loginctl`, not raw `utmp` parsing (struct layout portability risk this assessment didn't flag but was judged not worth taking on). Package-manager integrity (`dpkg -V`/`rpm -V`) substitutes for the GPG verification originally proposed — see the Operator Guide's Limitations section for what that gives up.

**macOS (§17.3, §4.3) — implemented via a materially simpler path than §22.1 proposed:**
This assessment (and its Phase-ordering recommendation) anticipated needing `SMJobBless`, a separate privileged helper tool, and XPC Services IPC — the heaviest lift of the three platforms by its own estimate. None of that was actually necessary: the agent *is already* the privileged (root launchd) daemon SMJobBless exists to install, so there is no separate helper to bless. Console-user detection uses `/dev/console` ownership (a plain `stat(2)`, no `SCDynamicStoreCopyConsoleUser`/CoreFoundation binding), elevated launch uses `launchctl asuser <uid> <path>` (not `AuthorizationExecuteWithPrivileges`, not XPC), and IPC is a plain Unix Domain Socket authenticated via `LOCAL_PEERCRED` (not XPC Services). This turned macOS from the assessed hardest platform into architecturally the simplest of the three shipped enforcement layers.

### What is still genuinely outstanding (do not treat as done)

- **Real-hardware end-to-end validation on all three platforms.** Every enforcement layer has cross-compilation, `go vet`, and unit/integration test coverage (including a real Named Pipe client/server integration test on Windows with the OS-privileged calls stubbed), but the actual elevate-and-launch path against a real interactive session has only been exercised that way — with the privileged primitives stubbed — never against a real WTS session, a real `launchctl asuser` call, or a real `/proc` GUI session on live hardware. Budget a pilot rollout per platform before trusting this in production.
- **Linux GPG signature verification** was descoped in favor of package-manager integrity checking (see above) — a real gap if publisher-based policy rules matter to your deployment on Linux specifically.
- **Phase 4's remaining hardening**: this reconciliation pass ran `go vet`, `golangci-lint run ./...` (zero findings), a manual handle/leak review (which caught and fixed one real Windows `CertContext` leak in `codesign_windows.go`), and confirmed no `import "C"` anywhere in the module. It did not include a third-party penetration test or fuzz-testing the IPC wire parsers.
