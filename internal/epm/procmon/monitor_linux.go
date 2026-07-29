//go:build linux

package procmon

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"sentinelgo/internal/epm"
)

// DefaultLinuxPollInterval is used only by the gopsutil fallback path (see
// New's doc comment) — matches the plan's stated Linux fallback cadence.
const DefaultLinuxPollInterval = 250 * time.Millisecond

const linuxEventBufferSize = 1024

// New returns the Linux process monitor: the netlink proc connector
// (AF_NETLINK/NETLINK_CONNECTOR) when it can be opened — needs
// CAP_NET_ADMIN, which the agent has as root — falling back to the same
// gopsutil poll-and-diff backend macOS uses when it cannot (missing
// capability, kernel built without CONFIG_PROC_EVENTS, etc.). See
// parse_linux.go's doc comment for this backend's verification status: the
// wire parsing is unit-tested against buffer fixtures, but the live socket
// path has not been exercised against a real kernel in this development
// environment.
func New() Monitor {
	m := &linuxMonitor{bus: newEventBus(linuxEventBufferSize)}
	return m
}

type linuxMonitor struct {
	bus  *eventBus
	fd   int
	done chan struct{}
	stop chan struct{}

	fallback Monitor
}

func (m *linuxMonitor) Start() error {
	fd, err := openProcConnector()
	if err != nil {
		log.Printf("epm: procmon: netlink proc connector unavailable (%v), falling back to polling", err)
		m.fallback = newPollingMonitor(gopsutilSnapshot, DefaultLinuxPollInterval, "poll", linuxEventBufferSize)
		return m.fallback.Start()
	}

	m.fd = fd
	m.stop = make(chan struct{})
	m.done = make(chan struct{})
	go m.loop()
	return nil
}

// openProcConnector opens, binds, and subscribes a netlink connector socket
// to process events. Returns an error (never panics) on any failure, so
// Start can fall back to polling cleanly.
func openProcConnector() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_CONNECTOR)
	if err != nil {
		return -1, err
	}

	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0, Groups: cnIdxProc}
	if err := unix.Bind(fd, addr); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}

	msg := buildSubscribeMessage(uint32(os.Getpid()))
	if _, err := unix.Write(fd, msg); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}

	return fd, nil
}

func (m *linuxMonitor) loop() {
	defer close(m.done)
	buf := make([]byte, 4096)

	for {
		select {
		case <-m.stop:
			return
		default:
		}

		n, _, err := unix.Recvfrom(m.fd, buf, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return // socket closed or otherwise unusable; stop the loop
		}

		for _, raw := range parseProcConnectorBuffer(buf[:n]) {
			if ev, ok := m.toProcessEvent(raw); ok {
				m.bus.send(ev)
			}
		}
	}
}

func (m *linuxMonitor) toProcessEvent(raw rawProcEvent) (ProcessEvent, bool) {
	now := time.Now().UTC()
	switch raw.what {
	case procEventExec:
		ev := ProcessEvent{Kind: EventStart, ObservedAt: now, PID: int(raw.pid), Source: "netlink", Have: HavePID, Elevated: epm.TriUnknown}
		enrichFromProc(int(raw.pid), &ev)
		return ev, true
	case procEventExit:
		ev := ProcessEvent{
			Kind: EventExit, ObservedAt: now, PID: int(raw.pid), ExitCode: int(raw.exitCode),
			Source: "netlink", Have: HavePID | HaveExitCode, Elevated: epm.TriUnknown,
		}
		return ev, true
	default:
		return ProcessEvent{}, false
	}
}

// enrichFromProc fills ImagePath/CommandLine/ParentPID from /proc/<pid>.
// The proc connector's EXEC event carries only a bare PID — the kernel
// message contains no image path or argv — so this is the only source for
// those fields. A short-lived process can exit before this read runs; each
// lookup is independent and tolerates ENOENT by simply leaving that field's
// Have bit unset rather than erroring the whole event out.
func enrichFromProc(pid int, ev *ProcessEvent) {
	pidStr := strconv.Itoa(pid)

	if exe, err := os.Readlink("/proc/" + pidStr + "/exe"); err == nil {
		ev.ImagePath = exe
		ev.Have |= HaveImagePath
	}

	if raw, err := os.ReadFile("/proc/" + pidStr + "/cmdline"); err == nil && len(raw) > 0 {
		// /proc/<pid>/cmdline is NUL-separated argv with a trailing NUL;
		// render it as a space-joined string, the same convention
		// CommandLine carries elsewhere in this codebase (see EPM's
		// ElevationRequest.CommandLine, a single string field).
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		ev.CommandLine = strings.Join(args, " ")
		if ev.CommandLine != "" {
			ev.Have |= HaveCommandLine
		}
	}

	if ppid, uid, ok := parseProcStatus("/proc/" + pidStr + "/status"); ok {
		ev.ParentPID = ppid
		ev.Have |= HaveParentPID
		ev.UserID = uid
		ev.Have |= HaveUserID
	}
}

// parseProcStatus reads PPid and the real UID (first field of the Uid: line)
// from /proc/<pid>/status.
func parseProcStatus(path string) (ppid int, uid string, ok bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, "", false
	}
	return parseProcStatusContent(string(raw))
}

func (m *linuxMonitor) Events() <-chan ProcessEvent {
	if m.fallback != nil {
		return m.fallback.Events()
	}
	return m.bus.Events()
}

func (m *linuxMonitor) Dropped() uint64 {
	if m.fallback != nil {
		return m.fallback.Dropped()
	}
	return m.bus.Dropped()
}

func (m *linuxMonitor) Stop() {
	if m.fallback != nil {
		m.fallback.Stop()
		return
	}
	if m.stop == nil {
		return
	}
	close(m.stop)
	_ = unix.Close(m.fd) // unblocks the Recvfrom in loop()
	<-m.done
	m.bus.close()
}
