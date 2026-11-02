package filescan

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

// xmlBreaks maps element local names to the text written when one ends, so
// paragraphs, cells and rows don't run together ("4111" in one cell and
// "1111…" in the next must not read as one number). Elements not listed join
// directly: Word splits one word over several runs.
var xmlBreaks = map[string]string{
	// OOXML (WordprocessingML, SpreadsheetML, DrawingML)
	"p": "\n", "tc": "\t", "tr": "\n", "si": "\n", "c": "\t", "row": "\n",
	// ODF
	"h": "\n", "table-cell": "\t", "table-row": "\n", "list-item": "\n",
}

// xmlInline maps empty elements that stand for a character.
var xmlInline = map[string]string{
	"br": "\n", "cr": "\n", "tab": "\t", "line-break": "\n", "s": " ",
}

// xmlSkip are elements whose text isn't document content: Word field codes
// and spreadsheet formulas (a cell's value is in <v>, which is kept).
var xmlSkip = map[string]bool{"instrText": true, "f": true}

// errXML is a malformed document part.
var errXML = errors.New("malformed XML")

// extractXMLText writes the character data of an XML document part to sink.
// encoding/xml expands no custom entities, so entity bombs don't apply.
func extractXMLText(r io.Reader, sink *textSink) error {
	d := xml.NewDecoder(r)
	var sb strings.Builder
	skip := 0
	flush := func() error {
		if sb.Len() == 0 {
			return nil
		}
		err := sink.WriteString(sb.String())
		sb.Reset()
		return err
	}
	for {
		tok, err := d.RawToken()
		if err != nil {
			if ferr := flush(); ferr != nil {
				return ferr
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return errXML
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if xmlSkip[t.Name.Local] || skip > 0 {
				skip++
			} else if s, ok := xmlInline[t.Name.Local]; ok {
				sb.WriteString(s)
			}
		case xml.EndElement:
			if skip > 0 {
				skip--
			} else if s := xmlBreaks[t.Name.Local]; s != "" {
				sb.WriteString(s)
			}
		case xml.CharData:
			if skip == 0 {
				sb.Write(t)
			}
		}
		if sb.Len() >= textReadBytes {
			if err := flush(); err != nil {
				return err
			}
		}
	}
}

// labelNames reads Microsoft sensitivity label names from docProps/custom.xml:
// properties named MSIP_Label_<id>_Name.
func labelNames(r io.Reader) []string {
	d := xml.NewDecoder(r)
	var labels []string
	inLabel := false
	var sb strings.Builder
	for {
		tok, err := d.RawToken()
		if err != nil {
			return labels
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "property" {
				for _, a := range t.Attr {
					if a.Name.Local == "name" && strings.HasPrefix(a.Value, "MSIP_Label_") && strings.HasSuffix(a.Value, "_Name") {
						inLabel = true
						sb.Reset()
					}
				}
			}
		case xml.CharData:
			if inLabel && sb.Len() < 256 {
				sb.Write(t)
			}
		case xml.EndElement:
			if t.Name.Local == "property" && inLabel {
				inLabel = false
				if name := strings.TrimSpace(sb.String()); name != "" && len(labels) < 16 {
					labels = append(labels, name)
				}
			}
		}
	}
}
