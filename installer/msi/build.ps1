<#
.SYNOPSIS
  Builds the generic SentinelGo MSI (#358) and checks the built package.

.DESCRIPTION
  Run from the repository root on Windows, with Go and WiX 4 (`wix`, with
  WixToolset.Util.wixext added) available:

    pwsh installer/msi/build.ps1 -Tag v4.1.0 -AgentExe dist/sentinelgo-windows-amd64.exe -Out dist/sentinelgo-windows-amd64.msi
    pwsh installer/msi/build.ps1 -Tag v4.1.0 -Flavor readonly -AgentExe dist/sentinelgo-readonly-windows-amd64.exe -Out dist/sentinelgo-readonly-windows-amd64.msi

  CI builds both on every pull request; release.yml builds the released ones.
  The exe must be the -Flavor build: its `-version` says which it is. The
  other checks read the built MSI's tables, so they hold for what ships, not
  for what the .wxs was meant to produce:
    - ProductCode, UpgradeCode, ProductVersion and ProductName are
      scripts/msi's for the flavor;
    - the enrollment properties are hidden from logs and secure;
    - Installed apps offers no Uninstall (ARPNOREMOVE);
    - enrollment runs deferred, elevated, without logging its command line,
      after InstallFiles and before StartServices;
    - the uninstall check (#566) runs the same way, right after
      InstallInitialize and before StopServices, only on a full removal
      that isn't a major upgrade.
#>
param(
  [Parameter(Mandatory)] [string] $Tag,
  [Parameter(Mandatory)] [string] $AgentExe,
  [Parameter(Mandatory)] [string] $Out,
  [ValidateSet("full", "readonly")] [string] $Flavor = "full",
  [string] $Wix = "wix",
  [string] $Source = "installer/msi/sentinelgo.wxs"
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# The exe must be the build the MSI is named for.
$exeVersion = & (Resolve-Path $AgentExe).Path -version
if ($LASTEXITCODE -ne 0) { throw "$AgentExe -version failed" }
if (-not ($exeVersion -contains "Build flavor: $Flavor")) {
  throw "$AgentExe is not the $Flavor build:`n$($exeVersion -join "`n")"
}

$vars = @{}
foreach ($line in (go run ./scripts/msi -version $Tag -flavor $Flavor -vars)) {
  if ($LASTEXITCODE -ne 0) { throw "scripts/msi failed" }
  $k, $v = $line -split "=", 2
  $vars[$k] = $v
}
if ($LASTEXITCODE -ne 0) { throw "scripts/msi failed" }

& $Wix build $Source -arch x64 -ext WixToolset.Util.wixext `
  -d "Version=$($vars.MSI_VERSION)" -d "ProductCode=$($vars.PRODUCT_CODE)" -d "UpgradeCode=$($vars.UPGRADE_CODE)" `
  -d "ProductName=$($vars.PRODUCT_NAME)" -d "AgentExe=$AgentExe" -o $Out
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }
Remove-Item -ErrorAction SilentlyContinue ([IO.Path]::ChangeExtension($Out, ".wixpdb"))

# Read the built MSI through the Windows Installer automation interface.
$installer = New-Object -ComObject WindowsInstaller.Installer
function Invoke-Com($obj, [string] $name, [string] $kind, [object[]] $argv) {
  $obj.GetType().InvokeMember($name, $kind, $null, $obj, $argv)
}
$db = Invoke-Com $installer "OpenDatabase" "InvokeMethod" @((Resolve-Path $Out).Path, 0)
function Get-Rows([string] $sql, [int] $columns) {
  $view = Invoke-Com $db "OpenView" "InvokeMethod" @($sql)
  [void](Invoke-Com $view "Execute" "InvokeMethod" @())
  $rows = @()
  while ($null -ne ($rec = Invoke-Com $view "Fetch" "InvokeMethod" @())) {
    $rows += , @(1..$columns | ForEach-Object { Invoke-Com $rec "StringData" "GetProperty" @([int] $_) })
  }
  [void](Invoke-Com $view "Close" "InvokeMethod" @())
  , $rows
}
function Get-Prop([string] $name) {
  $r = Get-Rows "SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$name'" 1
  if ($r.Count -eq 1) { $r[0][0] } else { "" }
}

$failed = @()
foreach ($p in @(@("ProductCode", $vars.PRODUCT_CODE), @("UpgradeCode", $vars.UPGRADE_CODE), @("ProductVersion", $vars.MSI_VERSION), @("ProductName", $vars.PRODUCT_NAME))) {
  $got = Get-Prop $p[0]
  if ($got -ne $p[1]) { $failed += "$($p[0]) is '$got', want '$($p[1])'" }
}
if ((Get-Prop "ARPNOREMOVE") -ne "1") { $failed += "ARPNOREMOVE isn't set: Installed apps would offer Uninstall" }
$hidden = (Get-Prop "MsiHiddenProperties") -split ";"
$secure = (Get-Prop "SecureCustomProperties") -split ";"
foreach ($p in "SERVER_URL", "ANON_KEY", "ENROLLMENT_TOKEN", "UNINSTALL_TOKEN") {
  if ($hidden -notcontains $p) { $failed += "$p isn't in MsiHiddenProperties" }
  if ($secure -notcontains $p) { $failed += "$p isn't in SecureCustomProperties" }
}
foreach ($p in "EnrollAgent", "UninstallCheck") {
  if ($hidden -notcontains $p) { $failed += "the command line of $p isn't hidden" }
  $ca = Get-Rows "SELECT ``Type``, ``Target`` FROM ``CustomAction`` WHERE ``Action`` = '$p'" 2
  # 0x400 deferred, 0x800 no impersonation (SYSTEM), 0x2000 HideTarget.
  if ($ca.Count -ne 1 -or $ca[0][1] -ne "WixSilentExec64" -or (([int] $ca[0][0]) -band 0x2C00) -ne 0x2C00) {
    $failed += "$p must be a deferred, no-impersonate, HideTarget WixSilentExec64 action: $($ca | ForEach-Object { $_ -join ' ' })"
  }
}
# The other build's MSI of the same version (same UpgradeCode, another
# ProductCode) must be removed, not installed beside this one: the upgrade
# row's VersionMax is this version, inclusive (msidbUpgradeAttributesVersionMaxInclusive 0x200).
$up = Get-Rows "SELECT ``Attributes``, ``VersionMax`` FROM ``Upgrade`` WHERE ``ActionProperty`` = 'WIX_UPGRADE_DETECTED'" 2
if ($up.Count -ne 1 -or $up[0][1] -ne $vars.MSI_VERSION -or (([int] $up[0][0]) -band 0x200) -ne 0x200) {
  $failed += "the major upgrade must include this version (AllowSameVersionUpgrades): $($up | ForEach-Object { $_ -join ' ' })"
}
$seq = @{}
$cond = @{}
foreach ($r in (Get-Rows "SELECT ``Action``, ``Sequence``, ``Condition`` FROM ``InstallExecuteSequence``" 3)) { $seq[$r[0]] = [int] $r[1]; $cond[$r[0]] = $r[2] }
# Removing the old product inside the transaction lets a failed install roll
# it back, instead of leaving the device with no agent.
if (-not ($seq.ContainsKey("RemoveExistingProducts") -and $seq.InstallInitialize -lt $seq.RemoveExistingProducts -and $seq.RemoveExistingProducts -lt $seq.InstallFiles)) {
  $failed += "RemoveExistingProducts must run after InstallInitialize and before InstallFiles"
}
if (-not ($seq.ContainsKey("EnrollAgent") -and $seq.InstallFiles -lt $seq.EnrollAgent -and $seq.EnrollAgent -lt $seq.StartServices)) {
  $failed += "EnrollAgent must run after InstallFiles and before StartServices"
}
# The uninstall check runs before anything is stopped or removed, and never
# on a major upgrade (UPGRADINGPRODUCTCODE), which must not need the token.
if (-not ($seq.ContainsKey("UninstallCheck") -and $seq.InstallInitialize -lt $seq.UninstallCheck -and $seq.UninstallCheck -lt $seq.StopServices -and $seq.UninstallCheck -lt $seq.RemoveFiles)) {
  $failed += "UninstallCheck must run after InstallInitialize and before StopServices and RemoveFiles"
}
if ($cond.UninstallCheck -ne 'REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE') {
  $failed += "UninstallCheck's condition is '$($cond.UninstallCheck)', want 'REMOVE~=`"ALL`" AND NOT UPGRADINGPRODUCTCODE'"
}

if ($failed.Count -gt 0) {
  $failed | ForEach-Object { Write-Host "::error::$Out`: $_" }
  exit 1
}
Write-Host "Built $Out ($Flavor build, version $($vars.MSI_VERSION), ProductCode $($vars.PRODUCT_CODE)); checks passed."
