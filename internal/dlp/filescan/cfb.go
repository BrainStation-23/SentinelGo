package filescan

import (
	"bytes"
	"encoding/binary"
	"io"
	"unicode/utf16"
)

// Encrypted Office Open XML files are OLE compound files with an
// "EncryptedPackage" stream (and "DRMEncrypted…" data spaces for Rights
// Management). When a compound file doesn't parse, these stream names, stored
// in UTF-16, are still found by searching the file.

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
