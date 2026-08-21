<#
.SYNOPSIS
    SentinelGo Windows service startup diagnostic (Phase C-F validation blocker).

.DESCRIPTION
    Collects evidence about why the SentinelGo service fails to reach RUNNING
    within the SCM's 30-second timeout (SCM events 7000 / 7009).

    READ-ONLY, with exactly one mutating action: a single `sc.exe start`.

    This script does NOT:
      - modify config.json or any configuration value
      - reset, delete, vacuum, or even OPEN any SQLite database (metadata only)
      - replace, move, or rebuild the binary
      - change ServicesPipeTimeout or any registry value
      - retry the start attempt
      - commit or push anything

    Secrets are never written to artifacts: config values are emitted through a
    strict allowlist, and secret-bearing fields are reported as presence/length
    only, so the bundle can be shared safely.

.PARAMETER MaxWaitSeconds
    Upper bound on the start observation window. Must exceed the 30s SCM
    timeout so the failure itself is captured. Default 90.

.PARAMETER SkipStabilityWatch
    Skip the post-RUNNING stability observation (read-only polling only).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\diagnose-windows-start.ps1
#>
[CmdletBinding()]
param(
    [string] $ServiceName      = 'SentinelGo',
    [string] $AgentDir         = 'C:\SentinelGo',
    [int]    $MaxWaitSeconds   = 90,
    [int]    $StabilitySeconds = 60,
    [switch] $SkipStabilityWatch,
    [string] $OutDir
)

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $OutDir) { $OutDir = Join-Path $env:TEMP "sentinelgo-diag-$stamp" }

# ---------------------------------------------------------------- helpers ---

function Write-Section {
    param([string] $Title)
    $line = '=' * 78
    Write-Host ''
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Save-Artifact {
    param([string] $Name, [object] $Content)
    $path = Join-Path $OutDir $Name
    try {
        $Content | Out-String -Width 500 | Set-Content -Path $path -Encoding UTF8
        Write-Host "  [saved] $Name"
    } catch {
        Write-Host "  [WARN] could not save $Name : $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Get-Ts { (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff') }

# Directory inventory: metadata ONLY. Never opens file contents, so SQLite
# databases, -wal and -shm files are measured without being touched.
function Get-DirInventory {
    param([string] $Path, [string] $Label)
    $result = New-Object System.Collections.ArrayList
    if (-not (Test-Path -LiteralPath $Path)) {
        [void]$result.Add("[$Label] NOT PRESENT: $Path")
        return $result
    }
    [void]$result.Add("[$Label] $Path")
    try {
        $items = Get-ChildItem -LiteralPath $Path -Force -Recurse -File -ErrorAction Stop
        if (-not $items) { [void]$result.Add('  (no files)') }
        foreach ($f in ($items | Sort-Object FullName)) {
            [void]$result.Add(('  {0,14:N0}  {1:yyyy-MM-dd HH:mm:ss.fff}  {2}' -f $f.Length, $f.LastWriteTime, $f.FullName))
        }
        if ($items) {
            $total = ($items | Measure-Object -Property Length -Sum).Sum
            [void]$result.Add(('  TOTAL: {0:N0} bytes across {1} files' -f $total, @($items).Count))
        }
    } catch {
        [void]$result.Add("  [ERROR] $($_.Exception.Message)")
    }
    return $result
}

# Config summary via a strict ALLOWLIST. Secrets are never emitted, only
# presence/length, so the artifact bundle can be shared without leaking creds.
function Get-SafeConfigSummary {
    param([string] $ConfigPath)
    $out = New-Object System.Collections.ArrayList
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        [void]$out.Add("config.json NOT PRESENT at $ConfigPath")
        return $out
    }
    try {
        $raw = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
        $cfg = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        [void]$out.Add("[ERROR] could not read/parse config.json: $($_.Exception.Message)")
        return $out
    }

    $safeKeys = @(
        'telemetry_enabled', 'telemetry_collect_interval', 'telemetry_queue_max_rows',
        'telemetry_queue_max_bytes', 'telemetry_queue_max_age',
        'audit_logs_enabled', 'log_storage_enabled', 'log_flush_interval',
        'software_sync_enabled', 'services_sync_enabled', 'services_update_interval',
        'enable_task_polling', 'task_polling_interval',
        'auto_update', 'auto_update_interval', 'agent_info_update_interval',
        'update_interval', 'current_version',
        'processes_collect_cmdline', 'include_builtin_scheduled_tasks', 'collect_routing_table'
    )
    $secretKeys = @('supabase_key', 'agent_secret', 'access_token', 'refresh_token', 'api_key')

    [void]$out.Add('--- non-secret config values (allowlisted) ---')
    foreach ($k in $safeKeys) {
        if ($cfg.PSObject.Properties.Name -contains $k) {
            [void]$out.Add(('  {0,-32} = {1}' -f $k, $cfg.$k))
        }
    }

    [void]$out.Add('')
    [void]$out.Add('--- secret-bearing fields (presence only, values redacted) ---')
    foreach ($k in $secretKeys) {
        if ($cfg.PSObject.Properties.Name -contains $k) {
            $v = [string]$cfg.$k
            if ([string]::IsNullOrEmpty($v)) { $state = 'EMPTY' } else { $state = "PRESENT (len=$($v.Length))" }
            [void]$out.Add(('  {0,-32} = {1}' -f $k, $state))
        } else {
            [void]$out.Add(('  {0,-32} = ABSENT' -f $k))
        }
    }

    if ($cfg.PSObject.Properties.Name -contains 'supabase_url') {
        try {
            [void]$out.Add(('  {0,-32} = host:{1}' -f 'supabase_url', ([Uri]$cfg.supabase_url).Host))
        } catch {
            [void]$out.Add(('  {0,-32} = (unparseable)' -f 'supabase_url'))
        }
    }
    foreach ($k in @('device_id', 'agent_id')) {
        if ($cfg.PSObject.Properties.Name -contains $k) {
            $v = [string]$cfg.$k
            if ($v.Length -gt 4) { $mask = ('*' * ($v.Length - 4)) + $v.Substring($v.Length - 4) } else { $mask = '****' }
            [void]$out.Add(('  {0,-32} = {1}' -f $k, $mask))
        }
    }

    [void]$out.Add('')
    [void]$out.Add('--- all keys present (names only, no values) ---')
    [void]$out.Add('  ' + (($cfg.PSObject.Properties.Name | Sort-Object) -join ', '))
    return $out
}

function Get-ScmEvents {
    param([datetime] $Since)
    try {
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $Since } -ErrorAction Stop |
            Where-Object { $_.Message -match 'SentinelGo' -or $_.ProviderName -match 'SentinelGo' } |
            Sort-Object TimeCreated |
            Select-Object @{ n = 'Time'; e = { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff') } },
                          ProviderName, Id, LevelDisplayName, Message
    } catch {
        "no matching System events since $Since ($($_.Exception.Message))"
    }
}

function Get-AgentEvents {
    param([datetime] $Since)
    try {
        Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $Since } -ErrorAction Stop |
            Where-Object { $_.ProviderName -match 'Sentinel' -or $_.Message -match 'SentinelGo' } |
            Sort-Object TimeCreated |
            Select-Object @{ n = 'Time'; e = { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff') } },
                          ProviderName, Id, LevelDisplayName, Message
    } catch {
        "no matching Application events since $Since ($($_.Exception.Message))"
    }
}

function Get-AgentProcessSnapshot {
    $snap = New-Object System.Collections.ArrayList
    $procs = @(Get-Process -Name 'sentinelgo' -ErrorAction SilentlyContinue)
    if ($procs.Count -eq 0) {
        [void]$snap.Add('  sentinelgo.exe: NOT RUNNING')
        return $snap
    }
    foreach ($p in $procs) {
        try { $startedAt = $p.StartTime.ToString('HH:mm:ss.fff') } catch { $startedAt = 'n/a' }
        try { $cpu = '{0:N3}' -f $p.CPU } catch { $cpu = 'n/a' }
        [void]$snap.Add(('  PID={0} started={1} cpu={2}s threads={3} handles={4} ws={5:N0}' -f `
                    $p.Id, $startedAt, $cpu, $p.Threads.Count, $p.HandleCount, $p.WorkingSet64))
        try {
            $conns = @(Get-NetTCPConnection -OwningProcess $p.Id -ErrorAction Stop)
            foreach ($c in $conns) {
                [void]$snap.Add(('    tcp {0}:{1} -> {2}:{3} [{4}]' -f `
                            $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.State))
            }
            if ($conns.Count -eq 0) { [void]$snap.Add('    tcp: (no connections)') }
        } catch {
            [void]$snap.Add('    tcp: (unavailable)')
        }
    }
    return $snap
}

# Parse `sc.exe query` into state / checkpoint / wait-hint. Checkpoint
# progression is what distinguishes "dispatcher never connected" from
# "Execute callback is slow".
function Get-ScQueryState {
    param([string] $Name)
    $raw = & sc.exe query $Name 2>&1 | Out-String
    $state = 'UNKNOWN'; $cp = ''; $wh = ''
    if ($raw -match 'STATE\s+:\s+\d+\s+(\S+)') { $state = $Matches[1] }
    if ($raw -match 'CHECKPOINT\s+:\s+(\S+)') { $cp = $Matches[1] }
    if ($raw -match 'WAIT_HINT\s+:\s+(\S+)') { $wh = $Matches[1] }
    [pscustomobject]@{ State = $state; Checkpoint = $cp; WaitHint = $wh; Raw = $raw }
}

# ============================================================ STEP 0: ELEV ===

Write-Section '0. ELEVATION CHECK'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$prin = New-Object Security.Principal.WindowsPrincipal($id)
$isAdmin = $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "  Identity : $($id.Name)"
Write-Host "  Elevated : $isAdmin"
if (-not $isAdmin) {
    Write-Host ''
    Write-Host 'ABORT: this script must run in an ELEVATED PowerShell session.' -ForegroundColor Red
    Write-Host 'Right-click PowerShell -> "Run as administrator", then re-run.' -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
Write-Host "  Output   : $OutDir"

try { Start-Transcript -Path (Join-Path $OutDir 'transcript.txt') -Force | Out-Null } catch { }

$stateDir = Join-Path $AgentDir '.sentinelgo'
$configPath = Join-Path $stateDir 'config.json'
# LocalSystem's profile: where lockfile.NewLockFile() actually places the lock
# when the agent runs as a service, because it derives from os.UserHomeDir().
$systemProfileState = 'C:\Windows\System32\config\systemprofile\.sentinelgo'

$osInfo = Get-CimInstance Win32_OperatingSystem
Save-Artifact '00-environment.txt' @(
    "collected_at   : $(Get-Ts)"
    "identity       : $($id.Name)"
    "elevated       : $isAdmin"
    "computer       : $env:COMPUTERNAME"
    "os             : $($osInfo.Caption) $($osInfo.Version)"
    "ps_version     : $($PSVersionTable.PSVersion)"
    "service_name   : $ServiceName"
    "agent_dir      : $AgentDir"
    "state_dir      : $stateDir"
    "systemprofile  : $systemProfileState"
    "max_wait_sec   : $MaxWaitSeconds"
)

# ================================================= STEP 1: SERVICE CONFIG ====

Write-Section '1. SERVICE CONFIGURATION + BINARY HASH'

$svcCfg = @()
$svcCfg += '--- sc.exe qc ---'; $svcCfg += (& sc.exe qc $ServiceName 2>&1 | Out-String)
$svcCfg += '--- sc.exe query ---'; $svcCfg += (& sc.exe query $ServiceName 2>&1 | Out-String)
$svcCfg += '--- sc.exe qfailure ---'; $svcCfg += (& sc.exe qfailure $ServiceName 2>&1 | Out-String)
try {
    $w = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    $svcCfg += '--- Win32_Service ---'
    $svcCfg += ($w | Select-Object Name, DisplayName, State, Status, StartMode, StartName,
        PathName, ProcessId, ExitCode, ServiceSpecificExitCode | Format-List | Out-String)
} catch {
    $svcCfg += "[WARN] Win32_Service query failed: $($_.Exception.Message)"
}
Save-Artifact '01-service-config.txt' $svcCfg
& sc.exe qc $ServiceName 2>&1 | Write-Host

$binInfo = @()
$binPath = Join-Path $AgentDir 'sentinelgo.exe'
foreach ($f in @(Get-ChildItem -LiteralPath $AgentDir -Filter '*.exe*' -Force -File -ErrorAction SilentlyContinue)) {
    try { $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $h = 'HASH-FAILED' }
    $binInfo += ('{0,14:N0}  {1:yyyy-MM-dd HH:mm:ss}  {2}  {3}' -f $f.Length, $f.LastWriteTime, $h, $f.FullName)
}
try {
    $vi = (Get-Item -LiteralPath $binPath).VersionInfo
    $binInfo += ''
    $binInfo += "FileVersion    : $($vi.FileVersion)"
    $binInfo += "ProductVersion : $($vi.ProductVersion)"
} catch { }
$binInfo += ''
$binInfo += '--- sentinelgo.exe -version (fast path, does not load config) ---'
try { $binInfo += (& $binPath -version 2>&1 | Out-String) } catch { $binInfo += "[WARN] $($_.Exception.Message)" }
Save-Artifact '02-binary-hash.txt' $binInfo
$binInfo | Write-Host

# ============================================ STEP 2: STATE DIR (PRE-START) ==

Write-Section '2. STATE DIRECTORY INVENTORY (PRE-START, metadata only)'
$preInv = @()
$preInv += "captured_at: $(Get-Ts)"
$preInv += ''
$preInv += (Get-DirInventory -Path $stateDir -Label 'AGENT STATE DIR')
$preInv += ''
$preInv += (Get-DirInventory -Path $systemProfileState -Label 'LOCALSYSTEM PROFILE STATE DIR (lockfile lives here)')
Save-Artifact '03-state-inventory-PRE.txt' $preInv
$preInv | Write-Host

Write-Section '2b. CONFIG SUMMARY (secrets redacted)'
$cfgSummary = Get-SafeConfigSummary -ConfigPath $configPath
Save-Artifact '04-config-summary-redacted.txt' $cfgSummary
$cfgSummary | Write-Host

# ============================================== STEP 3: EVENT LOGS (PRE) =====

Write-Section '3. EVENT LOGS (HISTORICAL, PRE-START)'
$histSince = (Get-Date).AddDays(-3)
Save-Artifact '05-events-scm-PRE.txt' (Get-ScmEvents -Since $histSince | Format-List | Out-String)
Save-Artifact '06-events-agent-PRE.txt' (Get-AgentEvents -Since $histSince | Format-List | Out-String)
try {
    $appErr = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Error'; StartTime = $histSince } -ErrorAction Stop |
        Where-Object { $_.Message -match 'sentinelgo' } |
        Select-Object @{ n = 'Time'; e = { $_.TimeCreated } }, Id, Message
    Save-Artifact '07-events-appcrash-PRE.txt' ($appErr | Format-List | Out-String)
} catch {
    Save-Artifact '07-events-appcrash-PRE.txt' 'no Application Error events referencing sentinelgo'
}
Write-Host '  (historical SCM / agent / crash events captured)'

# =================================================== STEP 4: START + TIME ====

Write-Section '4. SERVICE START + TIMING'

$preState = Get-ScQueryState -Name $ServiceName
Write-Host "  Pre-start state: $($preState.State)"
if ($preState.State -ne 'STOPPED') {
    Write-Host "  [WARN] service is not STOPPED (it is $($preState.State))." -ForegroundColor Yellow
    Write-Host '  Not stopping it automatically. Aborting so nothing is disturbed.' -ForegroundColor Yellow
    Save-Artifact '08-start-ABORTED.txt' "service was $($preState.State) at $(Get-Ts); start not attempted"
    try { Stop-Transcript | Out-Null } catch { }
    exit 2
}

$markerTime = Get-Date
Write-Host "  Start marker : $($markerTime.ToString('yyyy-MM-dd HH:mm:ss.fff'))"
Write-Host "  Issuing: sc.exe start $ServiceName"

$timeline = New-Object System.Collections.ArrayList
[void]$timeline.Add("marker            : $($markerTime.ToString('yyyy-MM-dd HH:mm:ss.fff'))")

$sw = [Diagnostics.Stopwatch]::StartNew()
$startOutput = & sc.exe start $ServiceName 2>&1 | Out-String
$issueMs = $sw.ElapsedMilliseconds
[void]$timeline.Add("sc.exe start returned after $issueMs ms")
[void]$timeline.Add('sc.exe start output:')
[void]$timeline.Add($startOutput)

$lastKey = ''
$firstProcSeen = $null
$outcome = 'UNKNOWN'
$reachedMs = $null
$nextProcSample = 0

while ($sw.Elapsed.TotalSeconds -lt $MaxWaitSeconds) {
    $q = Get-ScQueryState -Name $ServiceName
    $key = "$($q.State)|$($q.Checkpoint)|$($q.WaitHint)"
    if ($key -ne $lastKey) {
        [void]$timeline.Add(('{0,8} ms  STATE={1,-14} CHECKPOINT={2,-6} WAIT_HINT={3}' -f `
                    $sw.ElapsedMilliseconds, $q.State, $q.Checkpoint, $q.WaitHint))
        $lastKey = $key
    }

    $p = @(Get-Process -Name 'sentinelgo' -ErrorAction SilentlyContinue)
    if ($p.Count -gt 0 -and $null -eq $firstProcSeen) {
        $firstProcSeen = $sw.ElapsedMilliseconds
        [void]$timeline.Add(('{0,8} ms  PROCESS APPEARED pid={1}' -f $sw.ElapsedMilliseconds, $p[0].Id))
    }

    # Sample resource usage every ~2s while pending. Flat CPU means the process
    # is blocked on I/O or a syscall rather than spinning in user code.
    if ($p.Count -gt 0 -and $sw.ElapsedMilliseconds -ge $nextProcSample) {
        $nextProcSample = $sw.ElapsedMilliseconds + 2000
        try { $cpu = '{0:N3}' -f $p[0].CPU } catch { $cpu = 'n/a' }
        [void]$timeline.Add(('{0,8} ms  sample pid={1} cpu={2}s threads={3} handles={4} ws={5:N0}' -f `
                    $sw.ElapsedMilliseconds, $p[0].Id, $cpu, $p[0].Threads.Count, $p[0].HandleCount, $p[0].WorkingSet64))
    }

    if ($q.State -eq 'RUNNING') {
        $reachedMs = $sw.ElapsedMilliseconds
        $outcome = 'RUNNING'
        [void]$timeline.Add(('{0,8} ms  *** REACHED RUNNING ***' -f $reachedMs))
        break
    }
    if ($q.State -eq 'STOPPED' -and $sw.ElapsedMilliseconds -gt 1500) {
        $reachedMs = $sw.ElapsedMilliseconds
        $outcome = 'FAILED-STOPPED'
        [void]$timeline.Add(('{0,8} ms  *** FELL BACK TO STOPPED (start failed) ***' -f $reachedMs))
        break
    }
    Start-Sleep -Milliseconds 250
}
$sw.Stop()
if ($outcome -eq 'UNKNOWN') { $outcome = 'TIMED-OUT-OBSERVING' }

if ($null -ne $reachedMs) { $reachedTxt = $reachedMs } else { $reachedTxt = 'n/a' }
if ($null -ne $firstProcSeen) { $procTxt = "$firstProcSeen ms" } else { $procTxt = 'NEVER SEEN' }
if ($outcome -eq 'RUNNING' -and $reachedMs -lt 30000) { $withinLimit = 'YES' } else { $withinLimit = 'NO' }

[void]$timeline.Add('')
[void]$timeline.Add("OUTCOME              : $outcome")
[void]$timeline.Add("elapsed_total_ms     : $($sw.ElapsedMilliseconds)")
[void]$timeline.Add("time_to_running_ms   : $reachedTxt")
[void]$timeline.Add("process_first_seen   : $procTxt")
[void]$timeline.Add("under_30s_scm_limit  : $withinLimit")

Save-Artifact '08-start-timeline.txt' $timeline
$timeline | Write-Host

Write-Host ''
if ($outcome -eq 'RUNNING') {
    Write-Host "  OUTCOME: $outcome" -ForegroundColor Green
} else {
    Write-Host "  OUTCOME: $outcome" -ForegroundColor Red
}

# ============================================ STEP 5: POST-ATTEMPT CAPTURE ===

Write-Section '5. POST-ATTEMPT CAPTURE'

Write-Host '  Waiting 5s so SCM has flushed its event records...'
Start-Sleep -Seconds 5

Save-Artifact '09-events-scm-POST.txt' (Get-ScmEvents -Since $markerTime | Format-List | Out-String)
Save-Artifact '10-events-agent-POST.txt' (Get-AgentEvents -Since $markerTime | Format-List | Out-String)

$postState = @()
$postState += "captured_at: $(Get-Ts)"
$postState += '--- sc.exe query ---'
$postState += (& sc.exe query $ServiceName 2>&1 | Out-String)
try {
    $w2 = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    $postState += '--- Win32_Service ---'
    $postState += ($w2 | Select-Object Name, State, Status, StartName, ProcessId, ExitCode,
        ServiceSpecificExitCode | Format-List | Out-String)
} catch { }
$postState += '--- process presence ---'
$postState += (Get-AgentProcessSnapshot)
Save-Artifact '11-service-state-POST.txt' $postState
$postState | Write-Host

Write-Section '5b. STATE DIRECTORY INVENTORY (POST-ATTEMPT)'
$postInv = @()
$postInv += "captured_at: $(Get-Ts)"
$postInv += ''
$postInv += (Get-DirInventory -Path $stateDir -Label 'AGENT STATE DIR')
$postInv += ''
$postInv += (Get-DirInventory -Path $systemProfileState -Label 'LOCALSYSTEM PROFILE STATE DIR')
Save-Artifact '12-state-inventory-POST.txt' $postInv
$postInv | Write-Host

# ================================================ STEP 6: STABILITY WATCH ====

if ($outcome -eq 'RUNNING' -and -not $SkipStabilityWatch) {
    Write-Section "6. STABILITY WATCH ($StabilitySeconds s, read-only polling)"
    $stab = New-Object System.Collections.ArrayList
    $deadline = (Get-Date).AddSeconds($StabilitySeconds)
    while ((Get-Date) -lt $deadline) {
        $q = Get-ScQueryState -Name $ServiceName
        $p = @(Get-Process -Name 'sentinelgo' -ErrorAction SilentlyContinue)
        if ($p.Count -gt 0) { $pidTxt = $p[0].Id } else { $pidTxt = 'none' }
        if ($p.Count -gt 0) { try { $cpuTxt = '{0:N2}' -f $p[0].CPU } catch { $cpuTxt = 'n/a' } } else { $cpuTxt = 'n/a' }
        [void]$stab.Add(('{0}  STATE={1,-12} pid={2} cpu={3}s' -f (Get-Ts), $q.State, $pidTxt, $cpuTxt))
        if ($q.State -ne 'RUNNING') {
            [void]$stab.Add("*** SERVICE LEFT RUNNING STATE at $(Get-Ts) ***")
            break
        }
        Start-Sleep -Seconds 5
    }
    Save-Artifact '13-stability-watch.txt' $stab
    $stab | Write-Host

    Save-Artifact '14-events-agent-STABILITY.txt' (Get-AgentEvents -Since $markerTime | Format-List | Out-String)
}

# ========================================================== STEP 7: PACK =====

Write-Section '7. SUMMARY'

$summary = @(
    "collected_at        : $(Get-Ts)"
    "service             : $ServiceName"
    "outcome             : $outcome"
    "time_to_running_ms  : $reachedTxt"
    "process_first_seen  : $procTxt"
    "scm_30s_limit_met   : $withinLimit"
    ''
    'NOTE: no config, SQLite, binary, or registry value was modified by this script.'
    'NOTE: no automatic retry was performed.'
)
Save-Artifact '99-SUMMARY.txt' $summary
$summary | Write-Host

try { Stop-Transcript | Out-Null } catch { }

$zip = Join-Path $env:TEMP "sentinelgo-diag-$stamp.zip"
try {
    Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath $zip -Force -ErrorAction Stop
    Write-Host ''
    Write-Host "  Artifacts folder : $OutDir" -ForegroundColor Green
    Write-Host "  Zipped bundle    : $zip" -ForegroundColor Green
} catch {
    Write-Host ''
    Write-Host "  Artifacts folder : $OutDir" -ForegroundColor Green
    Write-Host "  [WARN] zip failed: $($_.Exception.Message)" -ForegroundColor Yellow
}
Write-Host ''
Write-Host '  Send the folder (or zip) back for analysis.' -ForegroundColor Green
