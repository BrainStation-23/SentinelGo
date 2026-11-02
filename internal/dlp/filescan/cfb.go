package filescan

import (
	"bytes"
	"encoding/binary"
	"io"
	"unicode/utf16"
)

// OLE compound files hold legacy Office documents (.doc, .xls, .ppt, .msg),
// which have no extractor yet, and also encrypted Office Open XML files: a
// password or Rights Management protected .docx/.xlsx/.pptx is a compound
// file with an "EncryptedPackage" stream. Stream names are stored in UTF-16,
// so they are found by searching the file, without parsing the format.

var (
	cfbEncryptedPackage = utf16le("EncryptedPackage")
	cfbDRM              = utf16le("DRMEncrypted") // Rights Management data spaces
)

func utf16le(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

// scanCFB reports a compound file as rights protected, password protected, or
// an unsupported legacy format.
func (st *scanState) scanCFB(ra io.ReaderAt, size int64) docResult {
	enc, drm, err := cfbMarkers(st, ra, size)
	switch {
	case err != nil:
		return docResult{typ: "ole", status: statusFor(st.ctx, err)}
	case enc && drm:
		return docResult{typ: "ooxml.encrypted", status: Unscannable(ReasonRightsProtected)}
	case enc:
		return docResult{typ: "ooxml.encrypted", status: Unscannable(ReasonPasswordProtected)}
	default:
		return docResult{typ: "ole", status: Unscannable(ReasonUnsupportedType)}
	}
}

// cfbMarkers searches ra for the encryption stream names, reading in blocks
// that overlap by the longest marker.
func cfbMarkers(st *scanState, ra io.ReaderAt, size int64) (enc, drm bool, err error) {
	const block = 256 << 10
	overlap := max(len(cfbEncryptedPackage), len(cfbDRM))
	buf := make([]byte, block+overlap)
	for off := int64(0); off < size && (!enc || !drm); off += block {
		if err := st.ctx.Err(); err != nil {
			return false, false, err
		}
		n, rerr := ra.ReadAt(buf[:min(int64(len(buf)), size-off)], off)
		if rerr != nil && rerr != io.EOF {
			return false, false, rerr
		}
		enc = enc || bytes.Contains(buf[:n], cfbEncryptedPackage)
		drm = drm || bytes.Contains(buf[:n], cfbDRM)
	}
	return enc, drm, nil
}
