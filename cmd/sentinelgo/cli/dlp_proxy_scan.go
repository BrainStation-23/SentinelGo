package cli

import (
	"context"
	"os"
	"time"

	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
)

// inProcessScanner scans in the calling process. Only for this manual test
// command; the service always uses the sandboxed workers.
func inProcessScanner(c *policy.Compiled, spill string) filedlp.Scanner {
	eng, _ := c.FilesEngine()
	return localScanner{filescan.New(eng, filescan.LimitsFrom(c.Modules.Files), spill)}
}

type localScanner struct{ s *filescan.Scanner }

func (l localScanner) Scan(ctx context.Context, f *os.File, size int64, _ time.Duration) filescan.Result {
	return l.s.Scan(ctx, filescan.Source{Size: size}, f)
}
