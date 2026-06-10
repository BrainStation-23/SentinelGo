package security

import (
	"log"
	"math"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"sentinelgo/internal/osinfo/shared"
)

const maxListeningPorts = 200

// Collect returns a SecurityInfo populated by platform-specific probes.
// Individual probe failures are swallowed; fields default to zero/unknown.
func Collect() shared.SecurityInfo {
	return collectSecurity()
}

// collectListeningPorts enumerates listening TCP ports and bound UDP ports
// using gopsutil, which works cross-platform without exec calls.
func collectListeningPorts() []shared.ListeningPort {
	conns, err := gnet.Connections("all")
	if err != nil {
		log.Printf("security: listening ports: %v", err)
		return nil
	}

	var ports []shared.ListeningPort
	for _, conn := range conns {
		// TCP: must be in LISTEN state. UDP (SOCK_DGRAM=2): any socket with a bound port.
		isTCPListen := conn.Status == "LISTEN"
		isUDPBound := conn.Type == 2 && conn.Laddr.Port > 0
		if !isTCPListen && !isUDPBound {
			continue
		}
		if conn.Laddr.Port > math.MaxUint16 {
			continue
		}

		proto := "tcp"
		if conn.Type == 2 {
			proto = "udp"
		}

		lp := shared.ListeningPort{
			Protocol:  proto,
			Port:      uint16(conn.Laddr.Port),
			Address:   conn.Laddr.IP,
			ProcessID: conn.Pid,
		}
		if conn.Pid > 0 {
			if p, perr := process.NewProcess(conn.Pid); perr == nil {
				if name, nerr := p.Name(); nerr == nil {
					lp.ProcessName = name
				}
			}
		}

		ports = append(ports, lp)
		if len(ports) >= maxListeningPorts {
			log.Printf("security: listening ports truncated at %d", maxListeningPorts)
			break
		}
	}
	return ports
}
