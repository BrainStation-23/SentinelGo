package watch

// Parsing fanotify's event buffer (Linux, read(2) on the group). Kept free
// of build tags so it is tested and fuzzed on every platform: the buffer
// comes from the kernel, but a parser bug must never panic the service.

import (
	"bytes"
	"encoding/binary"
)

// Layout of struct fanotify_event_metadata and the info records that
// follow it in a FAN_REPORT_DFID_NAME group (linux/fanotify.h).
const (
	fanMetaLen         = 24 // sizeof(struct fanotify_event_metadata)
	fanInfoHdrLen      = 4  // struct fanotify_event_info_header
	fanFIDHdrLen       = fanInfoHdrLen + 8 + 8
	fanInfoDFIDName    = 2 // FAN_EVENT_INFO_TYPE_DFID_NAME
	fanQOverflow       = 0x4000
	fanMaxHandleBytes  = 128 // MAX_HANDLE_SZ
	fanMaxEventNameLen = 4096
)

// fanEvent is one event: a descriptor (FAN_CLASS_NOTIF groups without
// FID reporting), or the parent folder's handle plus the entry's name
// (FAN_REPORT_DFID_NAME groups, where fd is FAN_NOFD).
type fanEvent struct {
	mask uint64
	fd   int32
	pid  int32

	hasName    bool
	fsid       [2]int32
	handleType int32
	handle     []byte
	name       string
}

// overflow reports a FAN_Q_OVERFLOW event: the kernel dropped events.
func (e fanEvent) overflow() bool { return e.mask&fanQOverflow != 0 }

// parseFanEvents calls fn for each well-formed event in buf and stops at the
// first malformed one. handle aliases buf.
func parseFanEvents(buf []byte, fn func(fanEvent)) {
	for off := 0; off+fanMetaLen <= len(buf); {
		evLen := int(binary.NativeEndian.Uint32(buf[off:]))
		metaLen := int(binary.NativeEndian.Uint16(buf[off+6:]))
		if evLen < fanMetaLen || off+evLen > len(buf) || metaLen < fanMetaLen || metaLen > evLen {
			return
		}
		ev := fanEvent{
			mask: binary.NativeEndian.Uint64(buf[off+8:]),
			fd:   int32(binary.NativeEndian.Uint32(buf[off+16:])), // #nosec G115 -- the kernel's signed fd
			pid:  int32(binary.NativeEndian.Uint32(buf[off+20:])), // #nosec G115 -- the kernel's signed pid
		}
		parseFanInfo(buf[off+metaLen:off+evLen], &ev)
		fn(ev)
		off += evLen
	}
}

// parseFanInfo reads the info records after the metadata and keeps the
// first DFID_NAME record whose handle and name are well formed.
func parseFanInfo(b []byte, ev *fanEvent) {
	for len(b) >= fanInfoHdrLen {
		typ := b[0]
		recLen := int(binary.NativeEndian.Uint16(b[2:]))
		if recLen < fanInfoHdrLen || recLen > len(b) {
			return
		}
		rec := b[:recLen]
		b = b[recLen:]
		if typ != fanInfoDFIDName || ev.hasName || len(rec) < fanFIDHdrLen {
			continue
		}
		n := int(binary.NativeEndian.Uint32(rec[12:]))
		if n <= 0 || n > fanMaxHandleBytes || fanFIDHdrLen+n > len(rec) {
			continue
		}
		rest := rec[fanFIDHdrLen+n:]
		end := bytes.IndexByte(rest, 0)
		if end <= 0 || end > fanMaxEventNameLen {
			continue
		}
		name := string(rest[:end])
		if name == "." || name == ".." || bytes.IndexByte(rest[:end], '/') >= 0 {
			continue
		}
		ev.hasName = true
		ev.fsid = [2]int32{
			int32(binary.NativeEndian.Uint32(rec[4:])), // #nosec G115 -- __kernel_fsid_t is two ints
			int32(binary.NativeEndian.Uint32(rec[8:])), // #nosec G115 -- __kernel_fsid_t is two ints
		}
		ev.handleType = int32(binary.NativeEndian.Uint32(rec[16:])) // #nosec G115 -- file_handle.handle_type is an int
		ev.handle = rec[fanFIDHdrLen : fanFIDHdrLen+n]
		ev.name = name
	}
}
