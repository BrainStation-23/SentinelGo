//go:build linux

package procmon

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// Netlink proc connector wire format — include/uapi/linux/connector.h and
// include/uapi/linux/cn_proc.h. This is a long-stable kernel ABI (introduced
// in Linux 2.6.15 and unchanged since), reconstructed here from that public
// header documentation.
//
// IMPORTANT VERIFICATION NOTE: this parsing logic is exercised by
// buffer-fixture unit tests (parse_linux_test.go) built from
// buildSubscribeMessage/an encoder of the same shape, which proves the
// decoder correctly inverts a buffer laid out to this documented struct
// layout. It has NOT been exercised against a live kernel socket — this
// development environment has no Linux runtime available. monitor_linux.go
// wires an automatic fallback to the gopsutil polling backend (shared with
// macOS, see poll.go/snapshot_gopsutil.go) if the netlink socket fails to
// open, so a wrong assumption here degrades to a working, if
// higher-latency, backend rather than silently collecting nothing — but the
// live netlink path itself should be validated on real hardware before
// being relied on for anything latency-sensitive (e.g. Phase 6b's
// terminate-on-violation).
const (
	nlmsgHdrLen     = 16 // nlmsghdr: len(4) + type(2) + flags(2) + seq(4) + pid(4)
	cnMsgHdrLen     = 20 // cn_msg: id{idx(4),val(4)} + seq(4) + ack(4) + len(2) + flags(2)
	procEventHdrLen = 16 // proc_event: what(4) + cpu(4) + timestamp_ns(8)

	nlmsgDone = 0x3

	cnIdxProc = 0x1
	cnValProc = 0x1

	procCNMcastListen = 1

	procEventExec = 0x00000002
	procEventExit = 0x80000000
)

// rawProcEvent is the decoded shape of the one proc_event union variant this
// package cares about — EXEC or EXIT. FORK is intentionally never decoded:
// at fork time the child is still running the parent's image (copy-on-write,
// pre-exec), so reporting it as a process "start" would attribute the wrong
// ImagePath/CommandLine once /proc enrichment runs. EXEC is the point a new
// image is actually in place, which is what EPM's process telemetry cares
// about.
type rawProcEvent struct {
	what       uint32
	pid        int32
	tgid       int32
	exitCode   int32
	exitSignal int32
}

// buildSubscribeMessage constructs the netlink connector "start listening to
// process events" control message: nlmsghdr + cn_msg header + a single
// __u32 PROC_CN_MCAST_LISTEN payload. selfPID is this process's PID, used as
// nlmsg_pid per netlink convention (reference implementations universally
// set this to getpid(), though the kernel does not require it).
func buildSubscribeMessage(selfPID uint32) []byte {
	const totalLen = nlmsgHdrLen + cnMsgHdrLen + 4
	buf := make([]byte, totalLen)

	binary.LittleEndian.PutUint32(buf[0:4], uint32(totalLen)) // nlmsg_len
	binary.LittleEndian.PutUint16(buf[4:6], nlmsgDone)        // nlmsg_type
	binary.LittleEndian.PutUint16(buf[6:8], 0)                // nlmsg_flags
	binary.LittleEndian.PutUint32(buf[8:12], 0)               // nlmsg_seq
	binary.LittleEndian.PutUint32(buf[12:16], selfPID)        // nlmsg_pid

	binary.LittleEndian.PutUint32(buf[16:20], cnIdxProc) // cn_msg.id.idx
	binary.LittleEndian.PutUint32(buf[20:24], cnValProc) // cn_msg.id.val
	binary.LittleEndian.PutUint32(buf[24:28], 0)         // cn_msg.seq
	binary.LittleEndian.PutUint32(buf[28:32], 0)         // cn_msg.ack
	binary.LittleEndian.PutUint16(buf[32:34], 4)         // cn_msg.len
	binary.LittleEndian.PutUint16(buf[34:36], 0)         // cn_msg.flags

	binary.LittleEndian.PutUint32(buf[36:40], procCNMcastListen) // payload

	return buf
}

// parseProcConnectorBuffer parses zero or more netlink-framed proc connector
// messages out of a single recvfrom() buffer — the kernel can and does batch
// multiple messages into one datagram — and returns the EXEC/EXIT events
// found. Any other proc_event kind (FORK, UID, COMM, ...) and any
// malformed/truncated trailing message is silently skipped: a reader loop
// that panics or wedges on one odd message would lose every subsequent
// event on the socket, which is worse than missing one.
func parseProcConnectorBuffer(buf []byte) []rawProcEvent {
	var events []rawProcEvent
	for len(buf) >= nlmsgHdrLen {
		msgLen := int(binary.LittleEndian.Uint32(buf[0:4]))
		if msgLen < nlmsgHdrLen || msgLen > len(buf) {
			break
		}

		if ev, ok := parseCnMsgBody(buf[nlmsgHdrLen:msgLen]); ok {
			events = append(events, ev)
		}

		// nlmsghdr framing pads each message to a 4-byte (NLMSG_ALIGNTO)
		// boundary before the next one starts.
		aligned := (msgLen + 3) &^ 3
		if aligned <= 0 || aligned > len(buf) {
			break
		}
		buf = buf[aligned:]
	}
	return events
}

func parseCnMsgBody(body []byte) (rawProcEvent, bool) {
	if len(body) < cnMsgHdrLen {
		return rawProcEvent{}, false
	}
	idx := binary.LittleEndian.Uint32(body[0:4])
	val := binary.LittleEndian.Uint32(body[4:8])
	if idx != cnIdxProc || val != cnValProc {
		return rawProcEvent{}, false
	}

	payload := body[cnMsgHdrLen:]
	if len(payload) < procEventHdrLen {
		return rawProcEvent{}, false
	}

	what := binary.LittleEndian.Uint32(payload[0:4])
	// payload[4:8] = cpu, payload[8:16] = timestamp_ns — not needed today.
	union := payload[procEventHdrLen:]

	switch what {
	case procEventExec:
		if len(union) < 8 {
			return rawProcEvent{}, false
		}
		return rawProcEvent{
			what: what,
			pid:  int32(binary.LittleEndian.Uint32(union[0:4])),
			tgid: int32(binary.LittleEndian.Uint32(union[4:8])),
		}, true
	case procEventExit:
		if len(union) < 16 {
			return rawProcEvent{}, false
		}
		return rawProcEvent{
			what:       what,
			pid:        int32(binary.LittleEndian.Uint32(union[0:4])),
			tgid:       int32(binary.LittleEndian.Uint32(union[4:8])),
			exitCode:   int32(binary.LittleEndian.Uint32(union[8:12])),
			exitSignal: int32(binary.LittleEndian.Uint32(union[12:16])),
		}, true
	default:
		return rawProcEvent{}, false
	}
}

// parseProcStatusContent extracts PPid and the real UID (first field of the
// Uid: line, which lists real/effective/saved/filesystem in that order) from
// the text content of /proc/<pid>/status. Split from monitor_linux.go's
// parseProcStatus (which does the actual file read) so the line-parsing
// logic is testable without a real /proc filesystem.
func parseProcStatusContent(content string) (ppid int, uid string, ok bool) {
	var havePPid, haveUID bool
	for _, line := range strings.Split(content, "\n") {
		switch {
		case strings.HasPrefix(line, "PPid:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if v, err := strconv.Atoi(fields[1]); err == nil {
					ppid = v
					havePPid = true
				}
			}
		case strings.HasPrefix(line, "Uid:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid = fields[1]
				haveUID = true
			}
		}
	}
	return ppid, uid, havePPid || haveUID
}
