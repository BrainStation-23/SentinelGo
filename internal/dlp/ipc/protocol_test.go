package ipc

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// A bundle full of characters JSON would HTML-escape still fits.
func TestWrite_NoHTMLEscaping(t *testing.T) {
	var buf bytes.Buffer
	policy := []byte(`"` + strings.Repeat("<", 4<<20) + `"`)
	if err := Write(&buf, Message{Type: TypePolicy, Policy: policy}); err != nil {
		t.Fatal(err)
	}
	m, err := Read(&buf, MaxServiceFrame)
	if err != nil || len(m.Policy) != len(policy) {
		t.Fatalf("read back %d bytes, err %v", len(m.Policy), err)
	}
}

func FuzzRead(f *testing.F) {
	frame := func(s string) []byte {
		b := binary.BigEndian.AppendUint32(nil, uint32(len(s)))
		return append(b, s...)
	}
	f.Add(frame(`{"proto":1,"type":"hello","hello":{"pid":1,"capabilities":{"clipboard":"supported"}}}`))
	f.Add(frame(`{"proto":1,"type":"event","event":{"event_id":"x","findings":[{"detector":"pii.iban","count":1}]}}`))
	f.Add(frame(`{"proto":2,"type":"ping"}`))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Read(bytes.NewReader(data), MaxHelperFrame)
		if err != nil {
			return
		}
		if m.Proto != Proto || m.Type == "" {
			t.Fatalf("Read accepted %+v", m)
		}
		var out bytes.Buffer
		if err := Write(&out, m); err != nil {
			t.Fatalf("re-encode: %v", err)
		}
	})
}
