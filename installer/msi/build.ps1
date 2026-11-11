<#
.SYNOPSIS
  Builds the generic SentinelGo MSI (#358) and checks the built package.

.DESCRIPTION
  Run from the repository root on Windows, with Go and WiX 4 (`wix`, with
  WixToolset.Util.wixext added) available:

    pwsh installer/msi/build.ps1 -Tag v4.1.0 -AgentExe dist/sentinelgo-windows-amd64.exe -Out dist/sentinelgo-windows-amd64.msi

  CI builds it on every pull request; release.yml builds the released one.
  The checks read the built MSI's tables, so they hold for what ships, not
  for what the .wxs was meant to produce:
    - ProductCode, UpgradeCode and ProductVersion are scripts/msi's;
    - the enrollment properties are hidden from logs and secure;
    - Installed apps offers no Uninstall (ARPNOREMOVE);
    - enrollment runs deferred, elevated, without logging its command line,
      after InstallFiles and before StartServices.
#>
param(
  [Parameter(Mandatory)] [string] $Tag,
  [Parameter(Mandatory)] [string] $AgentExe,
  [Parameter(Mandatory)] [string] $Out,
  [string] $Wix = "wix",
  [string] $Source = "installer/msi/sentinelgo.wxs"
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$vars = @{}
foreach ($line in (go run ./scripts/msi -version $Tag -vars)) {
  if ($LASTEXITCODE -ne 0) { throw "scripts/msi failed" }
  $k, $v = $line -split "=", 2
  $vars[$k] = $v
}
if ($LASTEXITCODE -ne 0) { throw "scripts/msi failed" }

& $Wix build $Source -arch x64 -ext WixToolset.Util.wixext `
  -d "Version=$($vars.MSI_VERSION)" -d "ProductCode=$($vars.PRODUCT_CODE)" -d "UpgradeCode=$($vars.UPGRADE_CODE)" `
  -d "AgentExe=$AgentExe" -o $Out
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
foreach ($p in @(@("ProductCode", $vars.PRODUCT_CODE), @("UpgradeCode", $vars.UPGRADE_CODE), @("ProductVersion", $vars.MSI_VERSION))) {
  $got = Get-Prop $p[0]
  if ($got -ne $p[1]) { $failed += "$($p[0]) is '$got', want '$($p[1])'" }
}
if ((Get-Prop "ARPNOREMOVE") -ne "1") { $failed += "ARPNOREMOVE isn't set: Installed apps would offer Uninstall" }
$hidden = (Get-Prop "MsiHiddenProperties") -split ";"
$secure = (Get-Prop "SecureCustomProperties") -split ";"
foreach ($p in "SERVER_URL", "ANON_KEY", "ENROLLMENT_TOKEN") {
  if ($hidden -notcontains $p) { $failed += "$p isn't in MsiHiddenProperties" }
  if ($secure -notcontains $p) { $failed += "$p isn't in SecureCustomProperties" }
}
if ($hidden -notcontains "EnrollAgent") { $failed += "the enrollment command line (EnrollAgent) isn't hidden" }

$ca = Get-Rows "SELECT ``Type``, ``Target`` FROM ``CustomAction`` WHERE ``Action`` = 'EnrollAgent'" 2
# 0x400 deferred, 0x800 no impersonation (SYSTEM), 0x2000 HideTarget.
if ($ca.Count -ne 1 -or $ca[0][1] -ne "WixSilentExec64" -or (([int] $ca[0][0]) -band 0x2C00) -ne 0x2C00) {
  $failed += "EnrollAgent must be a deferred, no-impersonate, HideTarget WixSilentExec64 action: $($ca | ForEach-Object { $_ -join ' ' })"
}
$seq = @{}
foreach ($r in (Get-Rows "SELECT ``Action``, ``Sequence`` FROM ``InstallExecuteSequence``" 2)) { $seq[$r[0]] = [int] $r[1] }
if (-not ($seq.ContainsKey("EnrollAgent") -and $seq.InstallFiles -lt $seq.EnrollAgent -and $seq.EnrollAgent -lt $seq.StartServices)) {
  $failed += "EnrollAgent must run after InstallFiles and before StartServices"
}

if ($failed.Count -gt 0) {
  $failed | ForEach-Object { Write-Host "::error::$Out`: $_" }
  exit 1
}
Write-Host "Built $Out (version $($vars.MSI_VERSION), ProductCode $($vars.PRODUCT_CODE)); checks passed."
