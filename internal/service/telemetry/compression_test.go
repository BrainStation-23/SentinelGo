package telemetry

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Compression is implemented but SHIPPED DISABLED, pending confirmation that
// the SentinelOps backend decompresses request bodies. These tests pin both
// halves of that: that the disabled path is byte-for-byte unchanged, and that
// the enabled path produces something a backend could actually read.

// TestCompressionIsOffByDefault is the shipping-safety test. If the backend
// does not decompress, every telemetry upload becomes a 4xx that the sender
// retains and dead-letters — nothing is lost, but nothing is delivered either.
func TestCompressionIsOffByDefault(t *testing.T) {
	var gotEncoding string
	var gotBody []byte

	svc, _ := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Content-Encoding")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})

	payload := `{"payload":{"items":[` + strings.Repeat(`{"a":"bbbbbbbbbb"},`, 200) + `{"a":"x"}]}}`
	seedSectionState(t, svc, "identity")
	enqueueTestMessage(t, svc, "identity", payload)

	if _, err := svc.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if gotEncoding != "" {
		t.Errorf("Content-Encoding = %q by default, want none — compression must "+
			"stay off until the backend confirms it decompresses request bodies", gotEncoding)
	}
	if string(gotBody) != payload {
		t.Error("the request body differs from the stored payload with compression off; " +
			"the disabled path must be byte-for-byte unchanged")
	}
}

// TestCompressionWhenEnabledIsDecodable proves the enabled path produces a
// valid gzip stream whose contents are exactly the stored payload.
func TestCompressionWhenEnabledIsDecodable(t *testing.T) {
	var gotEncoding string
	var decoded []byte

	svc, _ := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		gotEncoding = r.Header.Get("Content-Encoding")
		raw, _ := io.ReadAll(r.Body)
		if gotEncoding == "gzip" {
			zr, err := gzip.NewReader(bytes.NewReader(raw))
			if err != nil {
				t.Errorf("body is not a valid gzip stream: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			decoded, _ = io.ReadAll(zr)
			_ = zr.Close()
		} else {
			decoded = raw
		}
		w.WriteHeader(http.StatusOK)
	})
	svc.cfg.TelemetryGzipEnabled = true

	payload := `{"payload":{"items":[` + strings.Repeat(`{"a":"bbbbbbbbbb"},`, 200) + `{"a":"x"}]}}`
	seedSectionState(t, svc, "identity")
	enqueueTestMessage(t, svc, "identity", payload)

	if _, err := svc.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if gotEncoding != "gzip" {
		t.Fatalf("Content-Encoding = %q with compression enabled, want gzip", gotEncoding)
	}
	if string(decoded) != payload {
		t.Error("the decompressed body does not match the stored payload")
	}
}

// TestSmallBodiesAreNotCompressed pins the size threshold, which exists because
// of measured behaviour rather than theory: on a real endpoint the small
// sections got LARGER under gzip — virtualization 20 bytes to 44, firmware 59
// to 80 — since the gzip header and trailer cost more than a short JSON object
// can recover.
func TestSmallBodiesAreNotCompressed(t *testing.T) {
	small := []byte(`{"payload":{"is_virtual":false}}`)

	body, encoding := maybeCompress(small, true)
	if encoding != "" {
		t.Errorf("a %d-byte body was compressed; gzip makes bodies that size bigger", len(small))
	}
	if string(body) != string(small) {
		t.Error("a body below the threshold was modified")
	}
}

// TestCompressionNeverInflates pins the belt-and-braces check: even above the
// threshold, an incompressible body is sent as-is rather than padded.
func TestCompressionNeverInflates(t *testing.T) {
	// Random-ish, high-entropy content that gzip cannot shrink.
	var buf bytes.Buffer
	for i := 0; i < gzipMinBytes*2; i++ {
		buf.WriteByte(byte((i*2654435761 + i*i*40503) >> 7))
	}
	incompressible := buf.Bytes()

	body, encoding := maybeCompress(incompressible, true)
	if len(body) > len(incompressible) {
		t.Errorf("compression grew the body from %d to %d bytes and sent it anyway",
			len(incompressible), len(body))
	}
	if encoding == "gzip" && len(body) >= len(incompressible) {
		t.Error("Content-Encoding: gzip was set for a body that did not shrink")
	}
}

// TestCompressionDisabledLeavesLargeBodiesAlone pins that the flag, not the
// size, is what gates compression.
func TestCompressionDisabledLeavesLargeBodiesAlone(t *testing.T) {
	large := []byte(strings.Repeat("a", gzipMinBytes*4))

	body, encoding := maybeCompress(large, false)
	if encoding != "" {
		t.Errorf("Content-Encoding = %q with compression disabled", encoding)
	}
	if len(body) != len(large) {
		t.Errorf("body length = %d with compression disabled, want %d", len(body), len(large))
	}
}

// TestStoredPayloadIsNeverCompressed pins that compression applies to the wire
// body only. If the queue held gzip bytes, turning the flag off would leave
// undeliverable messages behind it.
func TestStoredPayloadIsNeverCompressed(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	svc.cfg.TelemetryGzipEnabled = true

	payload := `{"payload":{"items":[` + strings.Repeat(`{"a":"bbbbbbbbbb"},`, 200) + `{"a":"x"}]}}`
	seedSectionState(t, svc, "identity")
	enqueueTestMessage(t, svc, "identity", payload)

	// Short deadline so the retry policy gives up quickly rather than backing
	// off for the full RPC timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_, _ = svc.Flush(ctx)

	pending, err := svc.queueStore.GetPending(10)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("queue depth = %d, want 1", len(pending))
	}
	if pending[0].Payload != payload {
		t.Error("the queued payload was replaced by its compressed form; turning " +
			"the flag off would then leave undeliverable messages in the queue")
	}
}
