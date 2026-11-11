package watch

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// fdEvent builds a descriptor event.
func fdEvent(mask uint64, fd, pid int32) []byte {
	b := make([]byte, fanMetaLen)
	binary.NativeEndian.PutUint32(b[0:], fanMetaLen)
	b[4] = 3 // FANOTIFY_METADATA_VERSION
	binary.NativeEndian.PutUint16(b[6:], fanMetaLen)
	binary.NativeEndian.PutUint64(b[8:], mask)
	binary.NativeEndian.PutUint32(b[16:], uint32(fd)) // #nosec G115 -- test data
	binary.NativeEndian.PutUint32(b[20:], uint32(pid))
	return b
}

// nameEvent builds a FAN_REPORT_DFID_NAME event (fd FAN_NOFD).
func nameEvent(mask uint64, pid int32, fsid [2]int32, handleType int32, handle []byte, name string) []byte {
	rec := make([]byte, fanFIDHdrLen, 64)
	rec[0] = fanInfoDFIDName
	binary.NativeEndian.PutUint32(rec[4:], uint32(fsid[0])) // #nosec G115 -- test data
	binary.NativeEndian.PutUint32(rec[8:], uint32(fsid[1]))
	binary.NativeEndian.PutUint32(rec[12:], uint32(len(handle)))
	binary.NativeEndian.PutUint32(rec[16:], uint32(handleType))
	rec = append(rec, handle...)
	rec = append(rec, name...)
	rec = append(rec, 0)
	for len(rec)%4 != 0 {
		rec = append(rec, 0)
	}
	binary.NativeEndian.PutUint16(rec[2:], uint16(len(rec)))
	ev := fdEvent(mask, -1, pid)
	ev = append(ev, rec...)
	binary.NativeEndian.PutUint32(ev[0:], uint32(len(ev)))
	return ev
}

func TestParseFanEvents(t *testing.T) {
	handle := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	buf := append(fdEvent(0x08, 7, 100), nameEvent(0x80, 200, [2]int32{11, -12}, 1, handle, "drop.exe")...)
	buf = append(buf, fdEvent(fanQOverflow, -1, 0)...)
	var got []fanEvent
	parseFanEvents(buf, func(e fanEvent) {
		e.handle = bytes.Clone(e.handle)
		got = append(got, e)
	})
	if len(got) != 3 {
		t.Fatalf("parsed %d events, want 3", len(got))
	}
	if e := got[0]; e.mask != 0x08 || e.fd != 7 || e.pid != 100 || e.hasName || e.overflow() {
		t.Errorf("write event %+v", e)
	}
	if e := got[1]; !e.hasName || e.fd != -1 || e.pid != 200 || e.fsid != [2]int32{11, -12} || e.handleType != 1 ||
		!bytes.Equal(e.handle, handle) || e.name != "drop.exe" {
		t.Errorf("move event %+v", e)
	}
	if !got[2].overflow() {
		t.Error("overflow not reported")
	}
}

func TestParseFanEvents_Malformed(t *testing.T) {
	good := nameEvent(0x80, 1, [2]int32{1, 2}, 1, []byte{9, 9, 9, 9}, "x")
	cases := map[string][]byte{
		"short":            good[:10],
		"length past end":  func() []byte { b := bytes.Clone(good); binary.NativeEndian.PutUint32(b, 4096); return b }(),
		"length too small": func() []byte { b := bytes.Clone(good); binary.NativeEndian.PutUint32(b, 8); return b }(),
		"metadata_len big": func() []byte { b := bytes.Clone(good); binary.NativeEndian.PutUint16(b[6:], 500); return b }(),
	}
	for name, b := range cases {
		n := 0
		parseFanEvents(b, func(fanEvent) { n++ })
		if n != 0 {
			t.Errorf("%s: parsed %d events", name, n)
		}
	}
	// A bad info record leaves the event without a name, but the event is
	// still reported.
	for name, mutate := range map[string]func(b []byte){
		"handle too long": func(b []byte) { binary.NativeEndian.PutUint32(b[fanMetaLen+12:], 1000) },
		"record past end": func(b []byte) { binary.NativeEndian.PutUint16(b[fanMetaLen+2:], 4000) },
		"no NUL":          func(b []byte) { b[len(b)-4] = 'y'; b[len(b)-3] = 'y'; b[len(b)-2] = 'y'; b[len(b)-1] = 'y' },
	} {
		b := bytes.Clone(good)
		mutate(b)
		var got []fanEvent
		parseFanEvents(b, func(e fanEvent) { got = append(got, e) })
		if len(got) != 1 || got[0].hasName {
			t.Errorf("%s: %+v", name, got)
		}
	}
	for _, bad := range []string{".", "..", "a/b"} {
		var got fanEvent
		parseFanEvents(nameEvent(0x80, 1, [2]int32{}, 1, []byte{1}, bad), func(e fanEvent) { got = e })
		if got.hasName {
			t.Errorf("name %q accepted", bad)
		}
	}
}

func FuzzParseFanEvents(f *testing.F) {
	f.Add(fdEvent(0x08, 3, 1))
	f.Add(nameEvent(0x80, 1, [2]int32{5, 6}, 1, []byte{1, 2, 3, 4, 5, 6, 7, 8}, "a.bin"))
	f.Add(append(fdEvent(fanQOverflow, -1, 0), nameEvent(0x80, 1, [2]int32{}, 0, []byte{1}, "x")...))
	f.Fuzz(func(t *testing.T, buf []byte) {
		parseFanEvents(buf, func(e fanEvent) {
			if e.hasName {
				if e.name == "" || e.name == "." || e.name == ".." || bytes.ContainsAny([]byte(e.name), "/\x00") {
					t.Fatalf("bad name %q", e.name)
				}
				if len(e.handle) == 0 || len(e.handle) > fanMaxHandleBytes {
					t.Fatalf("handle of %d bytes", len(e.handle))
				}
			}
		})
	})
}
