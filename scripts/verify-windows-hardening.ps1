<#
.SYNOPSIS
    Verifies that a SentinelGo installation is not exploitable via the local
    privilege escalation reported as CyberStation PT-2026-001 finding #1.

.DESCRIPTION
    Read-only. Nothing is created, modified or deleted, so it is safe to run
    against a production host.

    Run it against an UNPATCHED machine first. A verification script that cannot
    detect the bug proves nothing, and the expected output there is a failure
    naming "Authenticated Users" on C:\SentinelGo.

    The four properties checked on every path are independent:
      * no non-privileged principal holds write-equivalent access
      * the owner is privileged (an owner keeps implicit WRITE_DAC and can
        rewrite any DACL at will, so a clean DACL under the wrong owner is
        worthless)
      * the DACL is protected, i.e. inheritance from the parent is severed --
        C:\ propagates an inherit-only Authenticated Users:Modify ACE to every
        child, which is the whole origin of the finding
      * the path is not a reparse point, so the name checked and the bytes
        executed are the same object

.PARAMETER Detailed
    Print the full SDDL of each path.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\verify-windows-hardening.ps1
#>
[CmdletBinding()]
param(
    [switch]$Detailed
)

$ErrorActionPreference = 'Stop'

$ServiceName = 'SentinelGo'
$InstallDir  = Join-Path $env:ProgramFiles 'SentinelGo'
$DataDir     = Join-Path $env:ProgramData  'SentinelGo'
$LegacyDir   = 'C:\SentinelGo'

# SIDs, not names: group names are localised and would not match on a non-English
# system. These three may legitimately hold full control over agent files.
$PrivilegedSids = @(
    'S-1-5-18',                                                                  # NT AUTHORITY\SYSTEM
    'S-1-5-32-544',                                                              # BUILTIN\Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'             # NT SERVICE\TrustedInstaller
)

# Rights that let a principal alter an object, or grant itself the ability to.
# WRITE_DAC and WRITE_OWNER matter as much as Write: a principal holding either
# can award itself everything else.
$DangerousRights = @(
    'WriteData', 'CreateFiles', 'AppendData', 'CreateDirectories',
    'WriteExtendedAttributes', 'WriteAttributes', 'Delete', 'DeleteSubdirectoriesAndFiles',
    'ChangePermissions', 'TakeOwnership', 'Write', 'Modify', 'FullControl'
)

$script:Failures = 0
$script:Checks   = 0

function Write-Result {
    param([string]$Name, [bool]$Ok, [string]$Detail)

    $script:Checks++
    if ($Ok) {
        Write-Host ("  [PASS] {0}" -f $Name) -ForegroundColor Green
    } else {
        $script:Failures++
        Write-Host ("  [FAIL] {0}" -f $Name) -ForegroundColor Red
        if ($Detail) {
            foreach ($line in ($Detail -split "`n")) {
                Write-Host ("         {0}" -f $line) -ForegroundColor Red
            }
        }
    }
}

function Test-PathSecurity {
    param([string]$Path, [switch]$MustExist)

    Write-Host ""
    Write-Host ("Path: {0}" -f $Path) -ForegroundColor Cyan

    if (-not (Test-Path -LiteralPath $Path)) {
        if ($MustExist) {
            Write-Result -Name "exists" -Ok $false -Detail "not found"
        } else {
            Write-Host "  [SKIP] not present" -ForegroundColor DarkGray
        }
        return
    }

    $item = Get-Item -LiteralPath $Path -Force
    $isReparse = [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
    Write-Result -Name "not a reparse point" -Ok (-not $isReparse) `
        -Detail "a junction or symlink here can redirect privileged writes elsewhere"

    $acl = Get-Acl -LiteralPath $Path
    if ($Detailed) {
        Write-Host ("  SDDL: {0}" -f $acl.Sddl) -ForegroundColor DarkGray
    }

    # Owner
    try {
        $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    } catch {
        $ownerSid = '<unresolvable>'
    }
    Write-Result -Name ("owner is privileged ({0})" -f $acl.Owner) `
        -Ok ($PrivilegedSids -contains $ownerSid) `
        -Detail "an owner holds implicit WRITE_DAC and can rewrite this DACL"

    # Inheritance must be severed.
    Write-Result -Name "DACL is protected (inheritance severed)" `
        -Ok $acl.AreAccessRulesProtected `
        -Detail "C:\ propagates Authenticated Users:(OI)(CI)(IO)(M) to every child"

    # Write-equivalent access for anyone unprivileged.
    $offenders = @()
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }

        try {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            $sid = $rule.IdentityReference.Value
        }
        if ($PrivilegedSids -contains $sid) { continue }

        $rights = $rule.FileSystemRights.ToString()
        if ($DangerousRights | Where-Object { $rights -match $_ }) {
            $offenders += ("{0} ({1}) : {2}" -f $rule.IdentityReference, $sid, $rights)
        }
    }
    Write-Result -Name "no write access for unprivileged principals" `
        -Ok ($offenders.Count -eq 0) -Detail ($offenders -join "`n")
}

Write-Host "SentinelGo Windows hardening verification" -ForegroundColor White
Write-Host "=========================================" -ForegroundColor White

Test-PathSecurity -Path $InstallDir -MustExist
Test-PathSecurity -Path (Join-Path $InstallDir 'sentinelgo.exe') -MustExist
Test-PathSecurity -Path (Join-Path $InstallDir '.staging')
Test-PathSecurity -Path $DataDir -MustExist
Test-PathSecurity -Path (Join-Path $DataDir 'config.json') -MustExist

# The legacy tree may still exist after a migration. It must have been hardened
# on the way out, or it remains a staging ground for the original attack.
Test-PathSecurity -Path $LegacyDir

# ---------------------------------------------------------------- service
Write-Host ""
Write-Host "Service: $ServiceName" -ForegroundColor Cyan

$svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Result -Name "service is registered" -Ok $false -Detail "not found"
} else {
    # An unquoted path containing a space lets C:\Program.exe be executed first.
    $pathName = $svc.PathName.Trim()
    Write-Result -Name "binary path is quoted" -Ok ($pathName.StartsWith('"')) `
        -Detail $pathName

    Write-Result -Name "runs as LocalSystem" `
        -Ok ($svc.StartName -eq 'LocalSystem') -Detail $svc.StartName

    $sidType = (& sc.exe qsidtype $ServiceName 2>&1 | Out-String)
    Write-Result -Name "service SID type is UNRESTRICTED" `
        -Ok ($sidType -match 'UNRESTRICTED') -Detail $sidType.Trim()

    # Recovery actions are a hard prerequisite for self-update: the agent swaps
    # its binary then exits non-zero, relying on the SCM to restart it.
    $failure = (& sc.exe qfailure $ServiceName 2>&1 | Out-String)
    Write-Result -Name "restart-on-failure configured" `
        -Ok ($failure -match 'RESTART') `
        -Detail "without this, an update exits and the service stays stopped"
}

# ---------------------------------------------------------------- summary
Write-Host ""
Write-Host "=========================================" -ForegroundColor White
if ($script:Failures -eq 0) {
    Write-Host ("All {0} checks passed." -f $script:Checks) -ForegroundColor Green
    Write-Host ""
    Write-Host "Confirm the exploit is dead by running these AS A STANDARD USER:" -ForegroundColor White
    Write-Host "  Set-Content '$InstallDir\sentinelgo.exe' 'x'   # expect UnauthorizedAccessException"
    Write-Host "  Get-Content '$DataDir\config.json'             # expect access denied"
    Write-Host "  Rename-Item '$InstallDir\sentinelgo.exe' 'x'   # expect access denied"
    exit 0
} else {
    Write-Host ("{0} of {1} checks FAILED." -f $script:Failures, $script:Checks) -ForegroundColor Red
    exit 1
}
