package ipc

import (
	"bytes"
	"encoding/binary"
	"errors"
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

// A notify frame and its result round-trip; a notify whose frame is over
// the helper's limit is rejected (#301).
func TestNotifyRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	n := &Notify{ID: "n1", Title: "Reboot tonight", Message: "Save your work <before> 22:00 & log off", Level: LevelWarning}
	if err := Write(&buf, Message{Type: TypeNotify, Notify: n}); err != nil {
		t.Fatal(err)
	}
	m, err := Read(&buf, MaxServiceFrame)
	if err != nil || m.Type != TypeNotify || m.Notify == nil || *m.Notify != *n {
		t.Fatalf("read back %+v, err %v", m, err)
	}

	if err := Write(&buf, Message{Type: TypeNotifyResult, NotifyResult: &NotifyResult{ID: "n1", Error: "exit status 1"}}); err != nil {
		t.Fatal(err)
	}
	m, err = Read(&buf, MaxHelperFrame)
	if err != nil || m.NotifyResult == nil || m.NotifyResult.ID != "n1" || m.NotifyResult.Error != "exit status 1" {
		t.Fatalf("read back %+v, err %v", m, err)
	}

	big := &Notify{ID: "n2", Title: "t", Message: strings.Repeat("x", MaxHelperFrame)}
	if err := Write(&buf, Message{Type: TypeNotify, Notify: big}); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(&buf, MaxHelperFrame); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("oversized notify: Read = %v, want ErrFrameTooLarge", err)
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
	f.Add(frame(`{"proto":1,"type":"notify_result","notify_result":{"id":"n1","error":"exit status 1"}}`))
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
