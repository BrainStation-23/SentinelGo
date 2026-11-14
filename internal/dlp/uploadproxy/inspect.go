package uploadproxy

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
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
	name := dispositionName(r.Header)
	switch {
	case n > limit:
		// Over max_file_bytes: decided as too large (on_unscannable); the
		// rest is forwarded unread.
		decide(spill, name)
	case isMultipart(r):
		if err := in.parts(spill, n, r, decide); err != nil {
			decide(spill, name) // not parseable as multipart: the whole body
		}
	default:
		decide(spill, name)
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

// parts decides each file in a multipart body on its own. Plain form fields
// are what the user typed or the page filled in, not files, so the file
// policies don't decide them.
func (in *Inspector) parts(spill *os.File, n int64, r *http.Request, decide func(*os.File, string)) error {
	_, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	mr := multipart.NewReader(io.NewSectionReader(spill, 0, n), params["boundary"])
	for i := 0; i < maxParts; i++ {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if part.FileName() == "" {
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
	return nil
}

// CarriesFile reports whether r's body may be a file being uploaded, as
// opposed to a web app's API call (a chat message, telemetry, a form post).
// Only those are decided by the file.upload policies: an API body is full of
// IDs and timestamps that look like personal data, and the text in it is
// typed, not a file. A multipart body is inspected for its file parts.
//
// A file is recognized by how sites send one: multipart/form-data, an
// object-store or resumable upload (Azure Blob, S3, Google, tus) or a
// Content-Disposition naming a file, whatever their Content-Type; otherwise
// any body that isn't an API, form or text type, including one with no type.
// A file sent inside a JSON API body (base64) isn't seen.
func CarriesFile(r *http.Request) bool {
	if isMultipart(r) || hasUploadSignal(r) {
		return true
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return true
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return true // can't tell: inspect
	}
	return !apiType(mt)
}

// uploadHeaders mark a request as a file upload whatever its Content-Type
// (a browser sends a file's own type, application/json for a .json file).
var uploadHeaders = []string{
	"X-Ms-Blob-Type",        // Azure Blob Put Blob (ChatGPT, Copilot)
	"X-Goog-Upload-Command", // Google resumable uploads (Gemini, Drive)
	"X-Goog-Upload-Protocol",
	"X-Upload-Content-Type", // Google APIs resumable uploads
	"Tus-Resumable",         // tus.io resumable uploads
	"Upload-Offset",
	"X-Amz-Decoded-Content-Length", // S3 streaming uploads
}

// uploadQuery marks a presigned object-store URL: a PUT to it stores a file.
var uploadQuery = []string{"X-Amz-Signature", "X-Goog-Signature"}

func hasUploadSignal(r *http.Request) bool {
	for _, h := range uploadHeaders {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	if dispositionName(r.Header) != "" {
		return true
	}
	q := r.URL.Query()
	for _, k := range uploadQuery {
		if q.Get(k) != "" {
			return true
		}
	}
	return false
}

// dispositionName is the file name a Content-Disposition header gives, if any.
func dispositionName(h http.Header) string {
	cd := h.Get("Content-Disposition")
	if cd == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(cd)
	if err != nil {
		return ""
	}
	return params["filename"]
}

// apiType reports whether a media type is what web apps use for API calls,
// form posts and beacons rather than for a file.
func apiType(mt string) bool {
	switch mt {
	case "application/json", "application/x-www-form-urlencoded", "text/plain",
		"application/x-ndjson", "application/graphql", "application/grpc",
		"application/grpc-web", "application/grpc-web+proto", "application/grpc-web-text",
		"application/x-protobuf", "application/protobuf", "application/x-protobuffer",
		"application/csp-report", "application/reports+json", "application/x-amz-json-1.1":
		return true
	}
	return strings.HasSuffix(mt, "+json") || strings.HasPrefix(mt, "application/grpc")
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
