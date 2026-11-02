package uploadproxy

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"time"

	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/policy"
)

// maxParts bounds the multipart parts inspected in one request.
const maxParts = 1000

// Inspector decides uploads with the file policies (channel file.upload).
// Request bodies go to spill files in a root-only directory, deleted after
// the request; the scan workers read them by descriptor. The proxy itself
// only splits multipart bodies into their parts, never parses file contents.
type Inspector struct {
	decider  *filedlp.Decider
	spillDir string
	now      func() time.Time
}

// NewInspector returns an Inspector. spillDir must be readable by the service
// only. Bodies are read up to the policy's max_file_bytes.
func NewInspector(d *filedlp.Decider, spillDir string) *Inspector {
	return &Inspector{decider: d, spillDir: spillDir, now: time.Now}
}

// Inspect reads r's body, decides it, and returns the verdict and a body to
// forward in its place: the same bytes, the inspected part from the spill
// file and any rest still streaming from the client. The caller closes it.
func (in *Inspector) Inspect(ctx context.Context, r *http.Request, host string) (filedlp.Verdict, io.ReadCloser, error) {
	// The same limit the scanner applies, so a body cut here is reported as
	// too large rather than scanned as if it were complete.
	limit := max(in.decider.Files().MaxFileBytes, 1)
	spill, err := os.CreateTemp(in.spillDir, "upload-*")
	if err != nil {
		return filedlp.Verdict{}, nil, err
	}
	n, err := io.Copy(spill, io.LimitReader(r.Body, limit+1))
	if err != nil {
		closeSpill(spill)
		return filedlp.Verdict{}, nil, err
	}
	body := &spillBody{spill: spill, n: n, rest: r.Body}
	if _, err := spill.Seek(0, io.SeekStart); err != nil {
		_ = body.Close()
		return filedlp.Verdict{}, nil, err
	}

	dest := filedlp.Destination{Channel: policy.ChannelFileUpload, Type: filedlp.TypeUpload, Host: host}
	var v filedlp.Verdict
	decide := func(f *os.File, name string) {
		if got := in.decideFile(ctx, f, name, dest); got.Block && !v.Block {
			v = got
		}
	}
	switch {
	case n > limit:
		// Over max_file_bytes: decided as too large (on_unscannable); the
		// rest is forwarded unread.
		decide(spill, "")
	case isMultipart(r):
		if err := in.parts(ctx, spill, n, r, decide); err != nil {
			decide(spill, "") // not parseable as multipart: the whole body
		}
	default:
		decide(spill, "")
	}
	if _, err := spill.Seek(0, io.SeekStart); err != nil {
		_ = body.Close()
		return filedlp.Verdict{}, nil, err
	}
	return v, body, nil
}

func isMultipart(r *http.Request) bool {
	mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "multipart/form-data" && params["boundary"] != ""
}

// parts decides each file in a multipart body on its own, and the plain form
// fields together.
func (in *Inspector) parts(ctx context.Context, spill *os.File, n int64, r *http.Request, decide func(*os.File, string)) error {
	_, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	mr := multipart.NewReader(io.NewSectionReader(spill, 0, n), params["boundary"])
	fields, err := os.CreateTemp(in.spillDir, "upload-fields-*")
	if err != nil {
		return err
	}
	defer closeSpill(fields)
	for i := 0; i < maxParts; i++ {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if part.FileName() == "" {
			_, err = io.Copy(fields, part)
			_, _ = fields.WriteString("\n")
			if err != nil {
				return err
			}
			continue
		}
		f, err := os.CreateTemp(in.spillDir, "upload-part-*")
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, part); err != nil {
			closeSpill(f)
			return err
		}
		decide(f, part.FileName())
		closeSpill(f)
	}
	decide(fields, "")
	return nil
}

// decideFile decides one uploaded file.
func (in *Inspector) decideFile(ctx context.Context, f *os.File, name string, dest filedlp.Destination) filedlp.Verdict {
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return filedlp.Verdict{}
	}
	return in.decider.Decide(ctx, filedlp.Request{
		File: f, Path: name, Dest: dest, At: in.now(), NoCache: true,
		Ident: filedlp.Identity{Size: fi.Size()},
	}, true)
}

// spillBody is the forwarded body: the spilled bytes, then the rest.
type spillBody struct {
	spill *os.File
	n     int64
	rest  io.ReadCloser
	r     io.Reader
}

func (b *spillBody) Read(p []byte) (int, error) {
	if b.r == nil {
		b.r = io.MultiReader(io.LimitReader(b.spill, b.n), b.rest)
	}
	return b.r.Read(p)
}

func (b *spillBody) Close() error {
	closeSpill(b.spill)
	return b.rest.Close()
}

// closeSpill closes and deletes a spill file.
func closeSpill(f *os.File) {
	_ = f.Close()
	_ = os.Remove(f.Name())
}
