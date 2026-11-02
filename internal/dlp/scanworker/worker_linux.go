package scanworker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
)

// workerFD is the descriptor the worker's socket arrives on.
const workerFD = 3

// Serve is `sentinelgo dlp-scan`: it sandboxes the process, then serves scan
// requests on fd 3 until the service closes the socket. It never opens a path.
func Serve() error {
	desc, err := sandbox()
	if err != nil {
		return fmt.Errorf("sandbox: %w", err)
	}
	c, _, err := fileConn(os.NewFile(workerFD, "scan-socket"))
	if err != nil {
		return fmt.Errorf("fd %d: %w", workerFD, err)
	}
	return serve(c, desc)
}

// serve answers requests on c; sandboxDesc is reported in the ready message.
func serve(c conn, sandboxDesc string) error {
	defer func() { _ = c.c.Close() }()
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
