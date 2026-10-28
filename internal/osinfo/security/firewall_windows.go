package security

import (
	"log"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// winFirewallScript reads the inbound firewall policy in force from the
// ActiveStore (local rules merged with Group Policy) in one PowerShell start:
// the enabled inbound rules with their port, program, address, service,
// interface and interface-type filters, each profile's state, default
// inbound action and whether it ignores allow rules ("block all incoming
// connections", AllowInboundRules False), the category and adapter media of
// each connected network, and which process hosts each running service. Filters are fetched in bulk (-All) and
// joined to the rules here, which is far faster than piping each rule to its
// filter.
var winFirewallScript = strings.Join([]string{
	`$ErrorActionPreference = 'Stop'`,
	`$ids = @{}`,
	`$rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True | ForEach-Object { $ids[$_.InstanceID] = $true; @{ id = $_.InstanceID; action = [string]$_.Action; profile = [int]$_.Profile } })`,
	`$ports = @(Get-NetFirewallPortFilter -PolicyStore ActiveStore -All | Where-Object { $ids.ContainsKey($_.InstanceID) } | ForEach-Object { @{ id = $_.InstanceID; protocol = [string]$_.Protocol; local_port = (@($_.LocalPort) -join ',') } })`,
	`$apps = @(Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -All | Where-Object { $ids.ContainsKey($_.InstanceID) } | ForEach-Object { @{ id = $_.InstanceID; program = [string]$_.Program } })`,
	`$addrs = @(Get-NetFirewallAddressFilter -PolicyStore ActiveStore -All | Where-Object { $ids.ContainsKey($_.InstanceID) } | ForEach-Object { @{ id = $_.InstanceID; local_address = (@($_.LocalAddress) -join ','); remote_address = (@($_.RemoteAddress) -join ',') } })`,
	`$svcs = @(Get-NetFirewallServiceFilter -PolicyStore ActiveStore -All | Where-Object { $ids.ContainsKey($_.InstanceID) } | ForEach-Object { @{ id = $_.InstanceID; service = [string]$_.Service } })`,
	`$ifaces = @(Get-NetFirewallInterfaceFilter -PolicyStore ActiveStore -All | Where-Object { $ids.ContainsKey($_.InstanceID) } | ForEach-Object { @{ id = $_.InstanceID; interface = (@($_.InterfaceAlias) -join ',') } })`,
	`$iftypes = @(Get-NetFirewallInterfaceTypeFilter -PolicyStore ActiveStore -All | Where-Object { $ids.ContainsKey($_.InstanceID) } | ForEach-Object { @{ id = $_.InstanceID; interface_type = [string]$_.InterfaceType } })`,
	`$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { @{ name = [string]$_.Name; enabled = ([string]$_.Enabled -ne 'False'); default_inbound = [string]$_.DefaultInboundAction; block_all_inbound = ([string]$_.AllowInboundRules -eq 'False') } })`,
	`$media = @{}; Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | ForEach-Object { $media[[int]$_.ifIndex] = [string]$_.PhysicalMediaType }`,
	`$networks = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { @{ interface = [string]$_.InterfaceAlias; index = [int]$_.InterfaceIndex; category = [string]$_.NetworkCategory; media = [string]$media[[int]$_.InterfaceIndex] } })`,
	`$hosted = @(Get-CimInstance Win32_Service -Filter 'ProcessId > 0' -ErrorAction SilentlyContinue | ForEach-Object { @{ name = [string]$_.Name; pid = [int]$_.ProcessId } })`,
	`@{ rules = $rules; ports = $ports; apps = $apps; addrs = $addrs; services = $svcs; ifaces = $ifaces; iface_types = $iftypes; profiles = $profiles; networks = $networks; hosted = $hosted } | ConvertTo-Json -Compress -Depth 4`,
}, "; ")

// collectWindowsFirewall reads the inbound firewall policy. ok is false when
// it can't be read (e.g. the agent isn't running elevated), and every risky
// service then gets the verdict "unknown".
func collectWindowsFirewall() (winFirewall, bool) {
	out, err := shared.RunPowerShell(winFirewallScript)
	if err != nil {
		log.Printf("security: firewall rules: %v", err)
		return winFirewall{}, false
	}
	fw, ok := parseWinFirewall(out)
	if !ok {
		log.Printf("security: firewall rules: unexpected probe output")
	}
	return fw, ok
}
