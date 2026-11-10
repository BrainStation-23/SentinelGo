package report

// Privacy (#415, hard rule): threat hunting never logs, stores or sends
// matched bytes, excerpts or file content. Two checks:
//   - TestPrivacy_MarkerNeverLeaves scans (simulated: the engine comes with
//     #410) a file holding a unique marker and follows the result through
//     events, the upload, the status, the on-disk queue and the logs,
//     emergency log included. The marker must appear nowhere.
//   - TestNoFileReads parses this package's sources: it must not open or
//     read files (owner lookups only stat them).

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"sentinelgo/internal/emergencylog"
	"sentinelgo/internal/store"
	"sentinelgo/internal/supabase"
	"sentinelgo/internal/yara"
)

func TestPrivacy_MarkerNeverLeaves(t *testing.T) {
	var nonce [12]byte
	_, _ = rand.Read(nonce[:])
	marker := "SGMARKER" + hex.EncodeToString(nonce[:])

	// The scanned file: the marker is its content, never its name.
	dir := t.TempDir()
	file := filepath.Join(dir, "sample.bin")
	content := []byte("MZ header ... " + marker + " ... payload tail")
	if err := os.WriteFile(file, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)

	// Capture the standard log and the emergency log.
	var logBuf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(old) })
	emDir := filepath.Join(dir, "emergency")
	if err := emergencylog.Init(emDir); err != nil {
		t.Fatal(err)
	}

	// What a worker reports for that file: rule identity, string
	// identifiers, the hash and the size. Nothing else crosses over.
	res := FileResult{Path: file, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(content)), Hits: []Hit{{
		RulesetID: "6f1c2a40-1111-4c3b-9a55-0123456789ab", RulesetRevision: 1,
		Rule: "Marker_Test", Namespace: "default", Tags: []string{"test"},
		Meta:      map[string]any{"author": "qa", "description": "finds the privacy marker"},
		StringIDs: []string{"$marker"},
	}}}

	q, err := store.NewYARAEventStore(filepath.Join(dir, store.YARAEventsDBName))
	if err != nil {
		t.Fatal(err)
	}
	var sent [][]byte
	for _, trigger := range []string{yara.TriggerOnDemand, yara.TriggerScheduled} {
		for _, mode := range []string{yara.PathModeFull, yara.PathModeHashed} {
			s := NewScan("", trigger, yara.PresetCustom, yara.Evidence{PathMode: mode}, q)
			evs, err := s.Matches(res)
			if err != nil {
				t.Fatal(err)
			}
			evs = append(evs, s.Summary(yara.ScanCompleted, 1, 0, 0))
			if err := q.Add(evs); err != nil {
				t.Fatal(err)
			}
			st := yara.Status{State: yara.StateOK, LastScan: s.SummaryBody(yara.ScanCompleted, 1, 0, 0)}
			data, err := st.Encode()
			if err != nil {
				t.Fatal(err)
			}
			sent = append(sent, data)
			for _, ev := range evs {
				data, _ := json.Marshal(ev)
				sent = append(sent, data)
			}
		}
	}
	// Upload: the first batch is refused (logs ids), the rest go through.
	rpc := &fakeRPC{errs: []error{&supabase.APIError{Status: 400, Code: yara.SQLStateInvalid, Message: "invalid event"}}}
	_ = q.Add([]yara.Event{summary(1)})
	if _, err := NewEventSync(q, NewClient(func() RPC { return rpc }), nil).Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	emergencylog.Record("yara", "test record after a scan of %s", file)
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	check := func(where string, data []byte) {
		t.Helper()
		if bytes.Contains(data, []byte(marker)) {
			t.Errorf("file content leaked into %s", where)
		}
	}
	for i, data := range sent {
		check("event/status "+strconv.Itoa(i), data)
	}
	for i, data := range rpc.raw {
		check("upload "+strconv.Itoa(i), data)
	}
	check("log", logBuf.Bytes())
	for _, pattern := range []string{filepath.Join(dir, "sentinelgo_yara.db*"), filepath.Join(emDir, "*")} {
		files, _ := filepath.Glob(pattern)
		if strings.HasSuffix(pattern, "db*") && len(files) == 0 {
			t.Fatal("queue database not found")
		}
		for _, f := range files {
			data, err := os.ReadFile(f) // #nosec G304 -- test temp files
			if err != nil {
				t.Fatal(err)
			}
			check(filepath.Base(f), data)
		}
	}
	// Sanity: the evidence that should be there is.
	all := bytes.Join(sent, nil)
	for _, want := range []string{"Marker_Test", "$marker", res.SHA256} {
		if !bytes.Contains(all, []byte(want)) {
			t.Errorf("events lack %q", want)
		}
	}
}

// TestNoFileReads: this package builds and sends events; reading files is
// the sandboxed worker's job. Its sources may not open or read files, nor
// print.
func TestNoFileReads(t *testing.T) {
	forbidden := map[string]map[string]bool{
		"os": {"Open": true, "OpenFile": true, "ReadFile": true, "Create": true, "WriteFile": true,
			"Stdout": true, "Stderr": true},
		"io":  {"ReadAll": true, "Copy": true, "CopyN": true, "ReadFull": true},
		"fmt": {"Print": true, "Printf": true, "Println": true, "Fprint": true, "Fprintf": true, "Fprintln": true},
	}
	forbiddenImports := map[string]bool{"bufio": true, "io/ioutil": true, "os/exec": true, "net/http": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var offenders []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		imported := map[string]string{}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if forbiddenImports[p] {
				offenders = append(offenders, fset.Position(imp.Pos()).String()+": imports "+p)
			}
			local := filepath.Base(p)
			if imp.Name != nil {
				local = imp.Name.Name
			}
			imported[local] = p
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && forbidden[imported[id.Name]][sel.Sel.Name] {
				offenders = append(offenders, fset.Position(sel.Pos()).String()+": uses "+imported[id.Name]+"."+sel.Sel.Name)
			}
			return true
		})
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Fatalf("yara/report must not read files or print (#415):\n  %s", strings.Join(offenders, "\n  "))
	}
}
