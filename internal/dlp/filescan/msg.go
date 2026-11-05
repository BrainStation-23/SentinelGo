package filescan

// Outlook messages (.msg, MS-OXMSG): an OLE compound file whose properties
// are streams named __substg1.0_<tag><type>, with recipients and attachments
// in child storages. The text read is the subject, the sender and recipient
// names and addresses, and the body (plain text, else the HTML body without
// its markup, else the compressed RTF body decompressed and read as RTF). Each attachment is scanned as an entry, as zip entries are,
// and an attached message is read the same way, one level deeper. An S/MIME
// encrypted message is unscannable:encrypted.

import (
	"bytes"
	"errors"
	"html"
	"io"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	msgProp        = "__substg1.0_"
	msgRecipPrefix = "__recip_version1.0_#"
	msgAttachPref  = "__attach_version1.0_#"
	msgTypeUnicode = "001F"
	msgTypeString8 = "001E"
	msgTypeBinary  = "0102"
)

// Property tags read as text, in this order: subject, sender name, sent
// representing name, display to/cc/bcc, plain body.
var msgTextTags = []string{"0037", "0C1A", "0042", "0E04", "0E03", "0E02", "1000"}

// Recipient properties: display name, SMTP address, email address.
var msgRecipTags = []string{"3001", "39FE", "3003"}

const (
	msgTagClass     = "001A"
	msgTagHTMLBody  = "1013"
	msgTagRTFBody   = "1009"
	msgAttachData   = msgProp + "3701" + msgTypeBinary
	msgAttachMsg    = msgProp + "3701000D" // an attached message, as a storage
	msgTagLongName  = "3707"
	msgTagShortName = "3704"
)

// isMSG reports whether a compound file's root holds a message.
func isMSG(top map[string]cfbEntry) bool {
	if _, ok := top["__properties_version1.0"]; !ok {
		return false
	}
	for name := range top {
		if strings.HasPrefix(name, msgProp) {
			return true
		}
	}
	return false
}

// msgString reads a string property of storage m, Unicode or 8-bit; ok is
// false when it isn't there.
func (f *cfbFile) msgString(m map[string]int, tag string) (string, bool, error) {
	if i, ok := m[msgProp+tag+msgTypeUnicode]; ok {
		b, err := f.read(f.entries[i])
		if err != nil {
			return "", true, err
		}
		return strings.TrimRight(decodeUTF16LE(b), "\x00"), true, nil
	}
	if i, ok := m[msgProp+tag+msgTypeString8]; ok {
		b, err := f.read(f.entries[i])
		if err != nil {
			return "", true, err
		}
		return strings.TrimRight(decodeCP1252(b), "\x00"), true, nil
	}
	return "", false, nil
}

var (
	htmlDropRe = regexp.MustCompile(`(?is)<(script|style|head)\b.*?</(script|style|head)\s*>`)
	htmlBreak  = regexp.MustCompile(`(?i)<\s*(br|/p|/div|/tr|/li|/h[1-6])\b[^>]*>`)
	htmlTagRe  = regexp.MustCompile(`(?s)<[^>]*>`)
)

// htmlText is an HTML body's text: no scripts, styles or tags, entities
// decoded, block ends as line breaks.
func htmlText(b []byte) string {
	s := string(b)
	if !utf8.ValidString(s) {
		s = decodeCP1252(b)
	}
	s = htmlDropRe.ReplaceAllString(s, " ")
	s = htmlBreak.ReplaceAllString(s, "\n")
	s = htmlTagRe.ReplaceAllString(s, " ")
	return html.UnescapeString(s)
}

// scanMSG scans the message in storage idx (0: the file's root).
func (st *scanState) scanMSG(f *cfbFile, idx, depth int, name string) docResult {
	const typ = "ole.msg"
	m := f.childMap(idx)
	if class, _, _ := f.msgString(m, msgTagClass); strings.HasPrefix(class, "IPM.Note.SMIME") && !strings.Contains(class, "MultipartSigned") {
		return docResult{typ: typ, status: Unscannable(ReasonEncrypted)}
	}
	sink := newSink(st)
	partial, err := st.msgText(f, m, sink)
	d := st.finishDoc(typ, sink, err)
	if partial {
		d.status = worse(d.status, StatusTruncated)
	}
	if err == nil {
		st.msgAttachments(f, m, depth, name)
	}
	return d
}

// msgText writes the message's text; partial is true when its only body is
// compressed RTF that can't be decompressed.
func (st *scanState) msgText(f *cfbFile, m map[string]int, sink *textSink) (partial bool, err error) {
	write := func(s string) error {
		if s = strings.TrimSpace(s); s == "" {
			return nil
		}
		return sink.WriteString(s + "\n")
	}
	hasBody := false
	for _, tag := range msgTextTags {
		s, ok, err := f.msgString(m, tag)
		if err != nil {
			return false, err
		}
		hasBody = hasBody || (ok && tag == "1000" && strings.TrimSpace(s) != "")
		if err := write(s); err != nil {
			return false, err
		}
	}
	if !hasBody {
		if i, ok := m[msgProp+msgTagHTMLBody+msgTypeBinary]; ok {
			b, err := f.read(f.entries[i])
			if err != nil {
				return false, err
			}
			hasBody = true
			if err := write(htmlText(b)); err != nil {
				return false, err
			}
		}
	}
	if i, ok := m[msgProp+msgTagRTFBody+msgTypeBinary]; ok && !hasBody {
		if partial, err = st.msgRTFBody(f, i, sink); err != nil {
			return partial, err
		}
	}
	for name, i := range m {
		if !strings.HasPrefix(name, msgRecipPrefix) {
			continue
		}
		rm := f.childMap(i)
		for _, tag := range msgRecipTags {
			s, _, err := f.msgString(rm, tag)
			if err != nil {
				return partial, err
			}
			if err := write(s); err != nil {
				return partial, err
			}
		}
	}
	return partial, nil
}

// msgRTFBody writes the text of a compressed RTF body; partial is true when
// it is corrupt (whatever decoded before the damage is still scanned).
func (st *scanState) msgRTFBody(f *cfbFile, i int, sink *textSink) (partial bool, err error) {
	b, err := f.read(f.entries[i])
	if err != nil {
		return false, err
	}
	r, err := newLZFuReader(b)
	if err != nil {
		return true, nil
	}
	err = extractRTF(r, sink)
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, errCorrupt) {
		return true, nil
	}
	if err == nil {
		err = sink.WriteString("\n")
	}
	return false, err
}

// msgAttachments scans each attachment as an entry: its data as a file, or
// an attached message as a message.
func (st *scanState) msgAttachments(f *cfbFile, m map[string]int, depth int, name string) {
	if depth+1 >= st.s.limits.MaxDepth {
		return
	}
	for aname, i := range m {
		if !strings.HasPrefix(aname, msgAttachPref) {
			continue
		}
		if st.ctx.Err() != nil || st.entriesLeft <= 0 || st.textLeft <= 0 {
			return
		}
		st.entriesLeft--
		am := f.childMap(i)
		label, _, _ := f.msgString(am, msgTagLongName)
		if label == "" {
			label, _, _ = f.msgString(am, msgTagShortName)
		}
		if label == "" {
			label = aname
		}
		e := Entry{Name: path.Join(name, path.Base(strings.ReplaceAll(label, `\`, "/")))} // #nosec G305 -- a label for results, never a path anything is written to
		var doc docResult
		switch {
		case hasIndex(am, msgAttachMsg) && f.entries[am[msgAttachMsg]].typ == cfbTypeStorage:
			doc = st.scanMSG(f, am[msgAttachMsg], depth+1, e.Name)
		case hasIndex(am, msgAttachData):
			b, err := f.read(f.entries[am[msgAttachData]])
			if err != nil {
				e.Status = st.entryStatus(err)
				st.entries = append(st.entries, e)
				continue
			}
			doc = st.scanDoc(bytes.NewReader(b), int64(len(b)), depth+1, e.Name)
		default:
			continue // a link or an OLE object without data
		}
		e.DetectedType, e.Status, e.Findings, e.Labels = doc.typ, doc.status, doc.findings, doc.labels
		protected := e.Status == Unscannable(ReasonPasswordProtected) || e.Status == Unscannable(ReasonRightsProtected) ||
			e.Status == Unscannable(ReasonEncrypted)
		if len(e.Findings) > 0 || protected {
			st.entries = append(st.entries, e)
		}
	}
}

func hasIndex(m map[string]int, name string) bool { _, ok := m[name]; return ok }
