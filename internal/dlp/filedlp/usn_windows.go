package filedlp

// The NTFS/ReFS change journal (USN journal) for at-rest classification
// (#331 part 2): after a full pass, only the files the journal says
// changed are classified again. It is cheap (a few records per changed
// file), survives reboots, and needs no watch kept open. Reading it needs
// administrator rights (the service is SYSTEM).

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/yara/walk"
)

const (
	fsctlQueryUSNJournal = 0x000900F4
	fsctlReadUSNJournal  = 0x000900BB

	fileIDType         = 0 // FILE_ID_TYPE: a 64-bit file id
	extendedFileIDType = 2 // a 128-bit file id

	// usnReasonMask asks for the records classification cares about.
	usnReasonMask = usnReasonDataOverwrite | usnReasonDataExtend | usnReasonDataTruncation |
		usnReasonFileCreate | usnReasonFileDelete | usnReasonRenameNewName | usnReasonClose
)

// maxJournalChanges: more changed files than this in one read means walk
// again instead. A var for tests.
var maxJournalChanges = 20_000

// usnJournalData is USN_JOURNAL_DATA_V0.
type usnJournalData struct {
	UsnJournalID    uint64
	FirstUsn        int64
	NextUsn         int64
	LowestValidUsn  int64
	MaxUsn          int64
	MaximumSize     uint64
	AllocationDelta uint64
}

// readUSNJournalData is READ_USN_JOURNAL_DATA_V1.
type readUSNJournalData struct {
	StartUsn          int64
	ReasonMask        uint32
	ReturnOnlyOnClose uint32
	Timeout           uint64
	BytesToWaitFor    uint64
	UsnJournalID      uint64
	MinMajorVersion   uint16
	MaxMajorVersion   uint16
}

// fileIDDescriptor is FILE_ID_DESCRIPTOR.
type fileIDDescriptor struct {
	Size uint32
	Type uint32
	ID   [16]byte
}

var procOpenFileByID = windows.NewLazySystemDLL("kernel32.dll").NewProc("OpenFileById")

// usnJournal reads the journals of the volumes the folders are on. Volume
// handles are opened on demand and closed by Close; it can be used again
// afterwards.
type usnJournal struct {
	mu      sync.Mutex
	handles map[string]windows.Handle // "C:" → volume handle
	states  map[string]string
}

func newUSNJournal() *usnJournal {
	return &usnJournal{handles: map[string]windows.Handle{}, states: map[string]string{}}
}

// volumesOf returns the drive letters ("C:") the roots are on. Roots on
// network paths have no journal the agent can read.
func volumesOf(roots []string) (vols []string, network bool) {
	seen := map[string]bool{}
	for _, r := range roots {
		v := strings.ToUpper(filepath.VolumeName(r))
		if len(v) != 2 || v[1] != ':' {
			network = true
			continue
		}
		if !seen[v] {
			seen[v] = true
			vols = append(vols, v)
		}
	}
	return vols, network
}

func (j *usnJournal) handle(vol string) (windows.Handle, error) {
	if h, ok := j.handles[vol]; ok {
		return h, nil
	}
	p, err := windows.UTF16PtrFromString(`\\.\` + vol)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return 0, err
	}
	j.handles[vol] = h
	return h, nil
}

// query returns a volume's journal, or why there is none to read.
func (j *usnJournal) query(vol string) (windows.Handle, usnJournalData, string) {
	h, err := j.handle(vol)
	if err != nil {
		return 0, usnJournalData{}, journalReason(err)
	}
	var d usnJournalData
	var n uint32
	if err := windows.DeviceIoControl(h, fsctlQueryUSNJournal, nil, 0, (*byte)(unsafe.Pointer(&d)), uint32(unsafe.Sizeof(d)), &n, nil); err != nil { // #nosec G103 -- fixed-size struct for the API
		return 0, usnJournalData{}, journalReason(err)
	}
	return h, d, ""
}

func journalReason(err error) string {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return "not_permitted"
	case errors.Is(err, windows.ERROR_JOURNAL_NOT_ACTIVE), errors.Is(err, windows.ERROR_JOURNAL_DELETE_IN_PROGRESS):
		return "journal_inactive"
	case errors.Is(err, windows.ERROR_INVALID_FUNCTION), errors.Is(err, windows.ERROR_NOT_SUPPORTED):
		return "no_journal" // FAT, exFAT
	default:
		return "journal_error"
	}
}

func (j *usnJournal) setState(vol, reason string) {
	if reason == "" {
		j.states[vol] = "active"
	} else {
		j.states[vol] = "unsupported:" + reason
	}
}

func (j *usnJournal) Mark(roots []string, _ map[string]JournalCursor) map[string]JournalCursor {
	j.mu.Lock()
	defer j.mu.Unlock()
	vols, network := volumesOf(roots)
	clear(j.states)
	if network {
		j.states["network"] = "unsupported:network_path"
	}
	out := map[string]JournalCursor{}
	for _, v := range vols {
		_, d, reason := j.query(v)
		j.setState(v, reason)
		if reason == "" {
			out[v] = JournalCursor{Journal: d.UsnJournalID, Next: d.NextUsn}
		}
	}
	return out
}

func (j *usnJournal) Changes(ctx context.Context, roots []string, cursors map[string]JournalCursor) ([]string, map[string]JournalCursor, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	vols, _ := volumesOf(roots)
	next := map[string]JournalCursor{}
	var paths []string
	lost := false
	for _, v := range vols {
		h, d, reason := j.query(v)
		j.setState(v, reason)
		if reason != "" {
			continue // no journal: this volume is covered by the rescans only
		}
		refs, cur, ok := volumeChanges(ctx, h, d, cursors[v])
		next[v] = cur
		if !ok {
			lost = true
			continue
		}
		paths = append(paths, pathsUnder(h, refs, roots)...)
	}
	return paths, next, lost
}

// volumeChanges reads one volume's changed files from its cursor. ok is
// false when the journal can't say (a volume not walked yet, a new
// journal, records overwritten, too many changes); the cursor then moves
// to the journal's end.
func volumeChanges(ctx context.Context, h windows.Handle, d usnJournalData, cur JournalCursor) (map[[16]byte]bool, JournalCursor, bool) {
	end := JournalCursor{Journal: d.UsnJournalID, Next: d.NextUsn}
	if cur.Journal != d.UsnJournalID || cur.Next < d.LowestValidUsn || cur.Next > d.NextUsn {
		return nil, end, false
	}
	refs, pos, gone := readJournal(ctx, h, d, cur.Next)
	if gone || len(refs) > maxJournalChanges {
		return nil, end, false
	}
	return refs, JournalCursor{Journal: d.UsnJournalID, Next: pos}, true
}

// pathsUnder maps file references to paths, keeping those under roots.
func pathsUnder(h windows.Handle, refs map[[16]byte]bool, roots []string) []string {
	var out []string
	for ref := range refs {
		p, ok := pathByID(h, ref)
		if !ok {
			continue
		}
		if _, in := walk.Under(p, roots, "windows"); in {
			out = append(out, p)
		}
	}
	return out
}

// readJournal reads a volume's records from start up to the journal's end
// when it was queried. gone is true when the records from start were
// already overwritten. It stops early, past maxJournalChanges files.
func readJournal(ctx context.Context, h windows.Handle, d usnJournalData, start int64) (refs map[[16]byte]bool, pos int64, gone bool) {
	refs = map[[16]byte]bool{}
	buf := make([]byte, 64<<10)
	pos = start
	for pos < d.NextUsn && len(refs) <= maxJournalChanges && ctx.Err() == nil {
		in := readUSNJournalData{StartUsn: pos, ReasonMask: usnReasonMask, ReturnOnlyOnClose: 1,
			UsnJournalID: d.UsnJournalID, MinMajorVersion: 2, MaxMajorVersion: 3}
		var n uint32
		err := windows.DeviceIoControl(h, fsctlReadUSNJournal, (*byte)(unsafe.Pointer(&in)), uint32(unsafe.Sizeof(in)), &buf[0], uint32(len(buf)), &n, nil) // #nosec G103 -- fixed-size struct for the API
		if err != nil {
			return refs, pos, true
		}
		nextUSN, changes := parseUSNRecords(buf[:n])
		for _, c := range changes {
			refs[c.ref] = true
		}
		if nextUSN <= pos {
			break // nothing more
		}
		pos = nextUSN
	}
	return refs, pos, false
}

// pathByID opens a file by its reference on the volume and returns its
// path (C:\…), without following links.
func pathByID(vol windows.Handle, ref [16]byte) (string, bool) {
	desc := fileIDDescriptor{Type: extendedFileIDType, ID: ref}
	if [8]byte(ref[8:]) == [8]byte{} {
		desc.Type = fileIDType // a 64-bit reference: NTFS
	}
	desc.Size = uint32(unsafe.Sizeof(desc))
	r, _, _ := procOpenFileByID.Call(uintptr(vol), uintptr(unsafe.Pointer(&desc)), windows.FILE_READ_ATTRIBUTES, // #nosec G103 -- fixed-size struct for the API
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, 0,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT)
	h := windows.Handle(r)
	if h == windows.InvalidHandle || h == 0 {
		return "", false // deleted since, or not ours to open
	}
	defer func() { _ = windows.CloseHandle(h) }()
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), volumeNameDOS)
	if err != nil || n == 0 || int(n) >= len(buf) {
		return "", false
	}
	p := windows.UTF16ToString(buf[:n])
	p = strings.TrimPrefix(p, `\\?\`)
	if strings.HasPrefix(p, `UNC\`) || len(p) < 3 || p[1] != ':' {
		return "", false
	}
	return p, true
}

func (j *usnJournal) States() map[string]string {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make(map[string]string, len(j.states))
	for k, v := range j.states {
		out[k] = v
	}
	return out
}

func (j *usnJournal) Close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	for v, h := range j.handles {
		_ = windows.CloseHandle(h)
		delete(j.handles, v)
	}
}
