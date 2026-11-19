//go:build readonly

package scanworker

import (
	"os"
	"testing"
	"time"
)

// recordConn keeps what serveYARA writes.
type recordConn struct{ sent []message }

func (r *recordConn) writeMsg(m message, _ int) error        { r.sent = append(r.sent, m); return nil }
func (r *recordConn) readMsg(int) (message, *os.File, error) { return message{}, nil, os.ErrClosed }
func (r *recordConn) setReadDeadline(time.Time) error        { return nil }
func (r *recordConn) close() error                           { return nil }

// The read-only build holds no YARA rules (#547): it compiles nothing and
// answers every scan with no rules, so the service never waits on it.
func TestReadOnly_WorkerHasNoYARA(t *testing.T) {
	c := &recordConn{}
	ys := &yaraState{}
	for _, m := range []message{
		{Type: typeYARARuleset},
		{Type: typeYARACompile, ID: 1},
		{Type: typeYARAScan, ID: 2, Size: 10},
	} {
		if err := serveYARA(c, ys, m, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.sent) != 2 || c.sent[0].Type != typeYARACompiled || len(c.sent[0].Compiled) != 0 ||
		c.sent[1].YARA == nil || c.sent[1].YARA.Status != YARANoRules || c.sent[1].YARA.Size != 10 {
		t.Fatalf("sent %+v", c.sent)
	}
}
