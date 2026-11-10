package collector

// OS-agnostic (no build tag) like collector_parse.go, so it's tested on every
// host. The Linux and macOS file collectors use it.

import (
	"bufio"
	"bytes"
	"io"
	"time"
)

// firstRunTailBytes bounds how far back a first run looks into a log file.
// Older content is past any retention window on a normal host, and reading
// gigabytes to find the window's start isn't worth it.
const firstRunTailBytes = 32 << 20

// firstRunOffset returns where a first run (no checkpoint for the file) should
// start reading so only lines newer than cutoff are collected (#437): the
// offset of the first line, within the last firstRunTailBytes, whose timestamp
// is at or after cutoff. Lines whose timestamp can't be parsed (parseTS returns
// the zero time) don't decide the start. When no line qualifies, it returns
// size, so only lines written from now on are read.
func firstRunOffset(r io.ReadSeeker, size int64, cutoff time.Time, parseTS func(string) time.Time) (int64, error) {
	start := max(size-firstRunTailBytes, 0)
	if _, err := r.Seek(start, io.SeekStart); err != nil {
		return 0, err
	}
	br := bufio.NewReaderSize(r, 64<<10)
	pos := start
	if start > 0 {
		// Mid-line: skip to the start of the next full line.
		skipped, err := br.ReadSlice('\n')
		for err == bufio.ErrBufferFull {
			pos += int64(len(skipped))
			skipped, err = br.ReadSlice('\n')
		}
		pos += int64(len(skipped))
		if err != nil {
			return size, nil
		}
	}
	for pos < size {
		line, err := br.ReadBytes('\n')
		if len(line) == 0 && err != nil {
			break
		}
		ts := parseTS(string(bytes.TrimRight(line, "\r\n")))
		if !ts.IsZero() && !ts.Before(cutoff) {
			return pos, nil
		}
		pos += int64(len(line))
		if err != nil {
			break
		}
	}
	return size, nil
}
