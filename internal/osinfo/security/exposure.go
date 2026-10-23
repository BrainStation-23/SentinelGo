package security

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// Bind scopes of a listening socket (#221).
const (
	scopeLoopback  = "loopback"  // 127.0.0.0/8, ::1, localhost: only this device can connect
	scopeAll       = "all"       // 0.0.0.0, ::, *: every interface
	scopeInterface = "interface" // one interface's address, link-local included
	scopeUnknown   = "unknown"   // not an address we can parse; treated as reachable
)

// bindScope classifies a listening socket's local address. Only loopback is
// unreachable from the network; anything unparseable counts as reachable.
func bindScope(addr string) string {
	a := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(addr), "["), "]")
	switch strings.ToLower(a) {
	case "localhost":
		return scopeLoopback
	case "*":
		return scopeAll
	}
	ip, err := netip.ParseAddr(a)
	if err != nil {
		return scopeUnknown
	}
	ip = ip.Unmap() // ::ffff:127.0.0.1 is loopback
	switch {
	case ip.IsLoopback():
		return scopeLoopback
	case ip.IsUnspecified():
		return scopeAll
	default:
		return scopeInterface
	}
}

// riskyPorts is a range of ports a commonly attacked service listens on.
type riskyPorts struct {
	name     string
	protocol string // "tcp" or "udp"
	from, to uint16
}

// riskyServiceCatalogue lists the services that make a device's network
// exposure High when reachable. It matches the console's risky-service
// catalogue (sentinel-ops#296), so the agent and console agree.
var riskyServiceCatalogue = []riskyPorts{
	{"FTP", "tcp", 21, 21},
	{"SSH", "tcp", 22, 22},
	{"Telnet", "tcp", 23, 23},
	{"NetBIOS", "udp", 137, 138},
	{"SMB", "tcp", 139, 139},
	{"SNMP", "udp", 161, 161},
	{"SMB", "tcp", 445, 445},
	{"MSSQL", "tcp", 1433, 1433},
	{"Docker API", "tcp", 2375, 2376},
	{"MySQL", "tcp", 3306, 3306},
	{"RDP", "tcp", 3389, 3389},
	{"RDP", "udp", 3389, 3389},
	{"PostgreSQL", "tcp", 5432, 5432},
	{"VNC", "tcp", 5900, 5906},
	{"WinRM", "tcp", 5985, 5986},
	{"Redis", "tcp", 6379, 6379},
	{"Elasticsearch", "tcp", 9200, 9200},
	{"Kubelet", "tcp", 10250, 10250},
	{"MongoDB", "tcp", 27017, 27017},
}

// riskyServiceName returns the catalogue name of the service p listens as,
// whatever address it's bound to.
func riskyServiceName(p shared.ListeningPort) (string, bool) {
	proto := strings.ToLower(p.Protocol)
	for _, r := range riskyServiceCatalogue {
		if r.protocol == proto && p.Port >= r.from && p.Port <= r.to {
			return r.name, true
		}
	}
	return "", false
}

// Verdicts on whether the host firewall lets a risky service be reached.
const (
	firewallAllowed  = "allowed"  // an inbound rule or the default policy lets connections in
	firewallBlocked  = "blocked"  // the host firewall drops inbound connections to it
	firewallDisabled = "disabled" // no host firewall is filtering inbound connections
	firewallUnknown  = "unknown"  // the agent couldn't tell
)

// firewallCheck returns whether the host firewall lets inbound connections
// reach p and, on Windows, which active firewall profiles let them in.
type firewallCheck func(p shared.ListeningPort) (verdict string, profiles []string)

// constantCheck gives every risky service the same verdict.
func constantCheck(verdict string) firewallCheck {
	return func(shared.ListeningPort) (string, []string) { return verdict, nil }
}

// remoteAccessProcessKeywords are process-name substrings that indicate a
// remote-access tool (case-insensitive match against the process name).
var remoteAccessProcessKeywords = []string{
	"ssh", "rdp", "vnc", "anydesk", "teamviewer", "remote", "pcanywhere",
}

// isRemoteAccessPort reports whether p looks like a remote-access service,
// either by its process name or by listening on a well-known remote-access port.
func isRemoteAccessPort(p shared.ListeningPort) bool {
	procLower := strings.ToLower(p.ProcessName)
	for _, kw := range remoteAccessProcessKeywords {
		if strings.Contains(procLower, kw) {
			return true
		}
	}
	return p.Port == 22 || p.Port == 3389 || (p.Port >= 5900 && p.Port <= 5906)
}

// analyzeNetworkExposure summarizes the listening sockets. Sockets bound to
// loopback count only toward TotalListeningPorts and ActiveNetworkServices:
// nothing on the network can reach them. check may be nil, which gives every
// risky service the verdict "unknown".
func analyzeNetworkExposure(ports []shared.ListeningPort, check firewallCheck) shared.NetworkExposureAccessInfo {
	var info shared.NetworkExposureAccessInfo
	info.TotalListeningPorts = len(ports)

	activeServicesMap := make(map[string]bool)
	remoteAccessMap := make(map[string]bool)
	for _, p := range ports {
		if p.ProcessName != "" {
			activeServicesMap[p.ProcessName] = true
		}
		if bindScope(p.Address) == scopeLoopback {
			continue
		}
		info.PubliclyBoundPorts++
		if isRemoteAccessPort(p) {
			name := p.ProcessName
			if name == "" {
				name = fmt.Sprintf("Unknown service on port %d", p.Port)
			}
			remoteAccessMap[name] = true
		}
	}
	info.ActiveNetworkServices = sortedKeys(activeServicesMap)
	info.RemoteAccessServices = sortedKeys(remoteAccessMap)

	info.RiskyServices = findRiskyServices(ports, check)
	info.OpenAdministrativePorts = []uint16{}
	for _, s := range info.RiskyServices {
		info.OpenAdministrativePorts = append(info.OpenAdministrativePorts, s.Port)
	}
	slices.Sort(info.OpenAdministrativePorts)
	info.OpenAdministrativePorts = slices.Compact(info.OpenAdministrativePorts)
	return info
}

// findRiskyServices returns the risky services listening on a non-loopback
// address, one per socket, with their firewall verdicts, sorted by port,
// protocol and address.
func findRiskyServices(ports []shared.ListeningPort, check firewallCheck) []shared.RiskyService {
	if check == nil {
		check = constantCheck(firewallUnknown)
	}
	risky := []shared.RiskyService{}
	seen := make(map[string]bool)
	for _, p := range ports {
		scope := bindScope(p.Address)
		name, ok := riskyServiceName(p)
		key := fmt.Sprintf("%s/%d/%s", strings.ToLower(p.Protocol), p.Port, p.Address)
		if scope == scopeLoopback || !ok || seen[key] {
			continue
		}
		seen[key] = true
		verdict, profiles := check(p)
		risky = append(risky, shared.RiskyService{
			Name:              name,
			Port:              p.Port,
			Protocol:          strings.ToLower(p.Protocol),
			Address:           p.Address,
			Scope:             scope,
			ProcessName:       p.ProcessName,
			Firewall:          verdict,
			ReachableProfiles: profiles,
		})
	}
	slices.SortFunc(risky, func(a, b shared.RiskyService) int {
		return cmp.Or(cmp.Compare(a.Port, b.Port), cmp.Compare(a.Protocol, b.Protocol), cmp.Compare(a.Address, b.Address))
	})
	return risky
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// summarizeNetworkExposureLevel rates exposure by the risky services on the
// network, not by how many sockets are bound: High when one can be reached
// (or the firewall verdict is unknown), Medium when all of them are blocked
// by the host firewall, Low when there are none.
func summarizeNetworkExposureLevel(net shared.NetworkExposureAccessInfo) (level string, recommendations []string) {
	var exposed, blocked []string
	for _, s := range net.RiskyServices {
		label := fmt.Sprintf("%s (%d/%s)", s.Name, s.Port, s.Protocol)
		if s.Firewall == firewallBlocked {
			blocked = appendUnique(blocked, label)
		} else {
			exposed = appendUnique(exposed, label)
		}
	}
	var stillBlocked []string
	for _, b := range blocked {
		if !slices.Contains(exposed, b) {
			stillBlocked = append(stillBlocked, b)
		}
	}

	switch {
	case len(exposed) > 0:
		return "High", []string{"Close or firewall " + strings.Join(exposed, ", ") + ": reachable from the network."}
	case len(stillBlocked) > 0:
		return "Medium", []string{"Turn off " + strings.Join(stillBlocked, ", ") + " if unused: listening on the network, though the host firewall blocks inbound connections."}
	default:
		return "Low", nil
	}
}

func appendUnique(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}
