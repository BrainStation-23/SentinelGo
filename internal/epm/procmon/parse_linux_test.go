//go:build linux

package procmon

import (
	"encoding/binary"
	"testing"
)

// buildProcEventMessage constructs one complete nlmsghdr-framed proc
// connector message (nlmsghdr + cn_msg header + proc_event) for a given
// EXEC or EXIT variant — the inverse of buildSubscribeMessage/
// parseProcConnectorBuffer, used here purely as a test fixture builder so
// the decoder can be exercised against a buffer laid out exactly to the
// documented kernel struct layout (see parse_linux.go's doc comment).
func buildProcEventMessage(what uint32, pid, tgid, exitCode, exitSignal int32) []byte {
	const procEventUnionLen = 16 // large enough for the exit variant (4 fields)
	total := nlmsgHdrLen + cnMsgHdrLen + procEventHdrLen + procEventUnionLen
	buf := make([]byte, total)

	binary.LittleEndian.PutUint32(buf[0:4], uint32(total))
	binary.LittleEndian.PutUint16(buf[4:6], nlmsgDone)
	binary.LittleEndian.PutUint32(buf[8:12], 0)
	binary.LittleEndian.PutUint32(buf[12:16], 1234)

	binary.LittleEndian.PutUint32(buf[16:20], cnIdxProc)
	binary.LittleEndian.PutUint32(buf[20:24], cnValProc)
	binary.LittleEndian.PutUint16(buf[32:34], uint16(procEventHdrLen+procEventUnionLen))

	pe := buf[nlmsgHdrLen+cnMsgHdrLen:]
	binary.LittleEndian.PutUint32(pe[0:4], what)
	// pe[4:8] = cpu, pe[8:16] = timestamp_ns — left zero, not read by the decoder.

	union := pe[procEventHdrLen:]
	binary.LittleEndian.PutUint32(union[0:4], uint32(pid))
	binary.LittleEndian.PutUint32(union[4:8], uint32(tgid))
	binary.LittleEndian.PutUint32(union[8:12], uint32(exitCode))
	binary.LittleEndian.PutUint32(union[12:16], uint32(exitSignal))

	return buf
}

func TestParseProcConnectorBuffer_Exec(t *testing.T) {
	buf := buildProcEventMessage(procEventExec, 4242, 4242, 0, 0)
	events := parseProcConnectorBuffer(buf)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	ev := events[0]
	if ev.what != procEventExec || ev.pid != 4242 || ev.tgid != 4242 {
		t.Errorf("unexpected event: %+v", ev)
	}
}

func TestParseProcConnectorBuffer_Exit(t *testing.T) {
	buf := buildProcEventMessage(procEventExit, 4242, 4242, 7, 0)
	events := parseProcConnectorBuffer(buf)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	ev := events[0]
	if ev.what != procEventExit || ev.pid != 4242 || ev.exitCode != 7 {
		t.Errorf("unexpected event: %+v", ev)
	}
}

func TestParseProcConnectorBuffer_UnknownWhatIgnored(t *testing.T) {
	const procEventFork = 0x00000001
	buf := buildProcEventMessage(procEventFork, 1, 1, 0, 0)
	if events := parseProcConnectorBuffer(buf); len(events) != 0 {
		t.Errorf("got %d events for a FORK message, want 0 (FORK is intentionally ignored)", len(events))
	}
}

func TestParseProcConnectorBuffer_MultipleMessagesInOneBuffer(t *testing.T) {
	a := buildProcEventMessage(procEventExec, 100, 100, 0, 0)
	b := buildProcEventMessage(procEventExit, 100, 100, 0, 0)
	buf := append(a, b...)

	events := parseProcConnectorBuffer(buf)
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].what != procEventExec || events[1].what != procEventExit {
		t.Errorf("events out of order or wrong kind: %+v", events)
	}
}

func TestParseProcConnectorBuffer_TruncatedBufferStopsCleanly(t *testing.T) {
	buf := buildProcEventMessage(procEventExec, 1, 1, 0, 0)
	truncated := buf[:len(buf)-10]
	// Must not panic; the truncated trailing message is simply dropped.
	// The nlmsg_len field still claims the full original length, which is
	// now greater than len(truncated), so the length check rejects it.
	events := parseProcConnectorBuffer(truncated)
	if len(events) != 0 {
		t.Errorf("got %d events from a truncated buffer, want 0", len(events))
	}
}

func TestParseProcConnectorBuffer_WrongConnectorIDIgnored(t *testing.T) {
	buf := buildProcEventMessage(procEventExec, 1, 1, 0, 0)
	// Corrupt cn_msg.id.val so it no longer matches CN_VAL_PROC.
	binary.LittleEndian.PutUint32(buf[20:24], 0xdead)
	if events := parseProcConnectorBuffer(buf); len(events) != 0 {
		t.Errorf("got %d events for a non-proc-connector message, want 0", len(events))
	}
}

func TestBuildSubscribeMessage_Shape(t *testing.T) {
	msg := buildSubscribeMessage(999)
	if len(msg) != 40 {
		t.Fatalf("len(msg) = %d, want 40", len(msg))
	}
	if got := binary.LittleEndian.Uint32(msg[0:4]); int(got) != len(msg) {
		t.Errorf("nlmsg_len = %d, want %d", got, len(msg))
	}
	if got := binary.LittleEndian.Uint16(msg[4:6]); got != nlmsgDone {
		t.Errorf("nlmsg_type = %d, want NLMSG_DONE (%d)", got, nlmsgDone)
	}
	if got := binary.LittleEndian.Uint32(msg[12:16]); got != 999 {
		t.Errorf("nlmsg_pid = %d, want 999", got)
	}
	if got := binary.LittleEndian.Uint32(msg[16:20]); got != cnIdxProc {
		t.Errorf("cn_msg.id.idx = %#x, want CN_IDX_PROC", got)
	}
	if got := binary.LittleEndian.Uint32(msg[20:24]); got != cnValProc {
		t.Errorf("cn_msg.id.val = %#x, want CN_VAL_PROC", got)
	}
	if got := binary.LittleEndian.Uint32(msg[36:40]); got != procCNMcastListen {
		t.Errorf("mcast op payload = %d, want PROC_CN_MCAST_LISTEN (%d)", got, procCNMcastListen)
	}
}

func TestParseProcStatusContent(t *testing.T) {
	const content = "Name:\tbash\n" +
		"State:\tS (sleeping)\n" +
		"Tgid:\t4242\n" +
		"PPid:\t100\n" +
		"Uid:\t1000\t1000\t1000\t1000\n" +
		"Gid:\t1000\t1000\t1000\t1000\n"

	ppid, uid, ok := parseProcStatusContent(content)
	if !ok {
		t.Fatal("parseProcStatusContent returned ok=false")
	}
	if ppid != 100 {
		t.Errorf("ppid = %d, want 100", ppid)
	}
	if uid != "1000" {
		t.Errorf("uid = %q, want \"1000\"", uid)
	}
}

func TestParseProcStatusContent_Empty(t *testing.T) {
	if _, _, ok := parseProcStatusContent(""); ok {
		t.Error("expected ok=false for empty content")
	}
}
