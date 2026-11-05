package scanworker

// The service <-> worker protocol, the same on every OS: frames of a 4-byte
// big-endian length and a JSON message. How a file reaches the worker
// differs: a descriptor alongside the frame (SCM_RIGHTS) on Linux, a handle
// duplicated into the worker (Message.Handle) on Windows.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
)

// Message types.
const (
	typeReady  = "ready"  // worker -> service, once sandboxed
	typePolicy = "policy" // service -> worker: the bundle to scan with
	typeScan   = "scan"   // service -> worker, with the file
	typeResult = "result" // worker -> service
)

// message is one frame of the protocol.
type message struct {
	Type    string           `json:"type"`
	ID      uint64           `json:"id,omitempty"`
	Bundle  json.RawMessage  `json:"bundle,omitempty"`  // policy
	Size    int64            `json:"size,omitempty"`    // scan
	Handle  uint64           `json:"handle,omitempty"`  // scan, Windows: the file's handle in the worker
	Result  *filescan.Result `json:"result,omitempty"`  // result
	Sandbox string           `json:"sandbox,omitempty"` // ready: what the sandbox applies
	Error   string           `json:"error,omitempty"`
}

// Frame limits: a bundle is at most 8 MB; results are capped below.
const (
	maxFrameToWorker   = 9 << 20
	maxFrameFromWorker = 8 << 20
	maxFrame           = maxFrameToWorker // the larger of the two: no frame is sent bigger
	// maxOffsets caps match offsets per finding in a result (the count is
	// kept), so a file full of e-mail addresses can't make a huge reply.
	maxOffsets = 10000
)

// frameConn is one end of the service <-> worker channel.
type frameConn interface {
	// writeMsg sends m, with the descriptor fd when fd >= 0 (Linux).
	writeMsg(m message, fd int) error
	// readMsg reads one frame of at most limit bytes and the file that came
	// with it (nil if none).
	readMsg(limit int) (message, *os.File, error)
	// setReadDeadline bounds readMsg; a read past it fails with an error
	// os.IsTimeout recognizes. The zero time removes the bound.
	setReadDeadline(t time.Time) error
	close() error
}

// encodeFrame marshals m with its length prefix.
func encodeFrame(m message) ([]byte, error) {
	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	// The receiver refuses frames over its limit anyway; refusing them here
	// too bounds this allocation and the length prefix.
	if len(body) > maxFrame {
		return nil, fmt.Errorf("scanworker: frame of %d bytes over the %d-byte limit", len(body), maxFrame)
	}
	frame := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body))) // #nosec G115 -- at most maxFrame, far below 4 GB
	return append(frame, body...), nil
}

// decodeFrame reads a frame's body after its length prefix hdr.
func decodeFrame(r io.Reader, hdr []byte, limit int) (message, error) {
	var m message
	size := binary.BigEndian.Uint32(hdr)
	if size > uint32(limit) { // #nosec G115 -- limit is a small positive constant
		return m, fmt.Errorf("scanworker: frame of %d bytes over the %d-byte limit", size, limit)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return m, err
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return m, fmt.Errorf("scanworker: bad frame: %w", err)
	}
	return m, nil
}

// capOffsets trims each finding's offsets to maxOffsets.
func capOffsets(r *filescan.Result) {
	for i := range r.Findings {
		if len(r.Findings[i].Offsets) > maxOffsets {
			r.Findings[i].Offsets = r.Findings[i].Offsets[:maxOffsets]
		}
	}
	for e := range r.Entries {
		for i := range r.Entries[e].Findings {
			if len(r.Entries[e].Findings[i].Offsets) > maxOffsets {
				r.Entries[e].Findings[i].Offsets = r.Entries[e].Findings[i].Offsets[:maxOffsets]
			}
		}
	}
}

// serve answers requests on c; sandboxDesc is reported in the ready message.
// It never opens a path: it reads only the files it is handed.
func serve(c frameConn, sandboxDesc string) error {
	defer func() { _ = c.close() }()
	if err := c.writeMsg(message{Type: typeReady, Sandbox: sandboxDesc}, -1); err != nil {
		return err
	}
	var scanner *filescan.Scanner
	for {
		m, f, err := c.readMsg(maxFrameToWorker)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch m.Type {
		case typePolicy:
			if f != nil {
				_ = f.Close()
			}
			scanner = nil
			if b, err := policy.Decode(m.Bundle); err == nil {
				eng, _ := policy.Compile(b).FilesEngine()
				scanner = filescan.New(eng, filescan.LimitsFrom(b.Modules.Files), "")
			}
		case typeScan:
			res := scanOne(scanner, f, m.Size)
			if err := c.writeMsg(message{Type: typeResult, ID: m.ID, Result: &res}, -1); err != nil {
				return err
			}
		default:
			if f != nil {
				_ = f.Close()
			}
		}
	}
}

func scanOne(s *filescan.Scanner, f *os.File, size int64) filescan.Result {
	if f == nil || s == nil {
		if f != nil {
			_ = f.Close()
		}
		return filescan.Result{Status: filescan.Unscannable(ReasonWorkerFailed), Size: size}
	}
	defer func() { _ = f.Close() }()
	res := s.Scan(context.Background(), filescan.Source{Size: size}, f)
	capOffsets(&res)
	return res
}
