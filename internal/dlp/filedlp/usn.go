package filedlp

// Parsing the NTFS/ReFS change journal's records (FSCTL_READ_USN_JOURNAL,
// #331 part 2). No OS suffix, so it is tested on any host; usn_windows.go
// reads the journal.

import "encoding/binary"

// USN reasons the classification cares about: a file's data changed, it was
// created or renamed into place, and its last handle closed.
const (
	usnReasonDataOverwrite  = 0x00000001
	usnReasonDataExtend     = 0x00000002
	usnReasonDataTruncation = 0x00000004
	usnReasonFileCreate     = 0x00000100
	usnReasonFileDelete     = 0x00000200
	usnReasonRenameNewName  = 0x00002000
	usnReasonClose          = 0x80000000
)

// fileAttributeDirectory is FILE_ATTRIBUTE_DIRECTORY.
const fileAttributeDirectory = 0x10

// usnChange is a file whose content may have changed: its 128-bit file
// reference (a 64-bit one zero-extended).
type usnChange struct {
	ref [16]byte
}

// parseUSNRecords reads the records after the 8-byte next-USN header of an
// FSCTL_READ_USN_JOURNAL output buffer. It returns the next USN and the
// files (not folders) whose data changed, were created or renamed in, and
// not deleted. V2 records (NTFS) carry 64-bit references and V3 (ReFS, or
// NTFS asked for V3) 128-bit ones; other versions are skipped. A truncated
// or malformed record ends the parse.
func parseUSNRecords(buf []byte) (next int64, out []usnChange) {
	if len(buf) < 8 {
		return 0, nil
	}
	next = int64(binary.LittleEndian.Uint64(buf)) // #nosec G115 -- a USN is a signed 64-bit offset
	for off := 8; off+8 <= len(buf); {
		recLen := int(binary.LittleEndian.Uint32(buf[off:]))
		if recLen < 8 || off+recLen > len(buf) {
			break
		}
		rec := buf[off : off+recLen]
		off += recLen
		if c, ok := usnRecordChange(rec); ok {
			out = append(out, c)
		}
	}
	return next, out
}

// usnRecordChange decodes one record: a file (not a folder) whose data
// changed, or that was created or renamed in, and not deleted.
func usnRecordChange(rec []byte) (usnChange, bool) {
	var c usnChange
	var reason, attrs uint32
	switch binary.LittleEndian.Uint16(rec[4:]) {
	case 2:
		if len(rec) < 60 {
			return c, false
		}
		copy(c.ref[:8], rec[8:16])
		reason = binary.LittleEndian.Uint32(rec[40:])
		attrs = binary.LittleEndian.Uint32(rec[52:])
	case 3:
		if len(rec) < 76 {
			return c, false
		}
		copy(c.ref[:], rec[8:24])
		reason = binary.LittleEndian.Uint32(rec[56:])
		attrs = binary.LittleEndian.Uint32(rec[68:])
	default:
		return c, false // V4 range records and unknown versions
	}
	const written = usnReasonDataOverwrite | usnReasonDataExtend | usnReasonDataTruncation | usnReasonFileCreate | usnReasonRenameNewName
	if attrs&fileAttributeDirectory != 0 || reason&usnReasonFileDelete != 0 || reason&written == 0 {
		return c, false
	}
	return c, true
}
