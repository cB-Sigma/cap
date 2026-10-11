// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// EDXL-DE envelopes. Some alerting systems pass CAP messages inside an
// OASIS EDXL Distribution Element: a distribution root (EDXLDistribution
// in 1.0, edxlDistribution in 2.0) with routing facts (distribution ID,
// sender, time sent, status, type or kind) and content objects, each
// holding XML content with the CAP alert embedded (xmlContent in 1.0,
// contentXML in 2.0) or other content, a document given inline in base64
// or by URI (nonXMLContent in 1.0, otherContent in 2.0). ParseEDXLDE
// reads the routing facts and every CAP alert carried; ParseFeed accepts
// such an envelope too. Element names follow the EDXL-DE 1.0 and 2.0
// schemas; no schema or specification text is copied.

// EDXL-DE namespaces.
const (
	EDXLDE10Namespace = "urn:oasis:names:tc:emergency:EDXL:DE:1.0"
	EDXLDE20Namespace = "urn:oasis:names:tc:emergency:EDXL:DE:2.0"
)

// Distribution is an EDXL-DE envelope as far as a CAP reader needs it.
type Distribution struct {
	// Version is "1.0" or "2.0".
	Version  string
	ID       string // distributionID
	SenderID string
	Sent     string // dateTimeSent
	// Expires is dateTimeExpires (2.0, where it is required).
	Expires string
	Status  string // distributionStatus
	Type    string // distributionType
	// Confidentiality is combinedConfidentiality (1.0); WriteEDXLDE writes
	// "UNCLASSIFIED AND NOT SENSITIVE" when it is empty.
	Confidentiality string
	// Entries are the CAP alerts the content objects carry, in document
	// order: embedded or base64 alerts with Alert and Raw set, alerts given
	// by URI with Link set. Each entry's ID is the distribution ID with the
	// content object's position ("ID#1" for the first).
	Entries []Entry
}

// isEDXLRoot tells the root element's name: EDXLDistribution in 1.0,
// edxlDistribution in 2.0 (either is accepted in both namespaces).
func isEDXLRoot(local string) bool {
	return local == "EDXLDistribution" || local == "edxlDistribution"
}

func edxlVersion(space string) (string, bool) {
	switch space {
	case EDXLDE10Namespace:
		return "1.0", true
	case EDXLDE20Namespace:
		return "2.0", true
	}
	return "", false
}

// ParseEDXLDE reads an EDXL-DE 1.0 or 2.0 envelope and the CAP alerts in
// it. Content that is not CAP is skipped.
func ParseEDXLDE(b []byte) (*Distribution, error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	var (
		dist    *Distribution
		depth   int
		objects int
		cur     *Entry // the content object being read
		mime    string
		data    string
	)
	for {
		start := d.InputOffset()
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("the EDXL-DE document is not well-formed XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if dist == nil {
				v, ok := edxlVersion(t.Name.Space)
				if !isEDXLRoot(t.Name.Local) || !ok {
					return nil, fmt.Errorf("not an EDXL-DE envelope (root element must be EDXLDistribution in %s or %s)", EDXLDE10Namespace, EDXLDE20Namespace)
				}
				dist = &Distribution{Version: v}
				continue
			}
			if _, ok := edxlVersion(t.Name.Space); ok {
				switch t.Name.Local {
				case "distributionID":
					if depth == 2 {
						dist.ID = text(d, &t)
						depth--
					}
				case "senderID":
					if depth == 2 {
						dist.SenderID = text(d, &t)
						depth--
					}
				case "dateTimeSent":
					if depth == 2 {
						dist.Sent = text(d, &t)
						depth--
					}
				case "dateTimeExpires":
					if depth == 2 {
						dist.Expires = text(d, &t)
						depth--
					}
				case "distributionStatus", "distributionType", "distributionKind":
					if depth == 2 {
						v := text(d, &t)
						if t.Name.Local == "distributionStatus" {
							dist.Status = v
						} else {
							dist.Type = v
						}
						depth--
					}
				case "combinedConfidentiality":
					if depth == 2 || (depth == 3 && cur == nil) { // 2.0: inside descriptor
						dist.Confidentiality = text(d, &t)
						depth--
					}
				case "contentObject":
					objects++
					cur, mime, data = &Entry{ID: fmt.Sprintf("%s#%d", dist.ID, objects), Updated: dist.Sent}, "", ""
				case "mimeType", "MIMEType":
					if cur != nil {
						mime = text(d, &t)
						depth--
					}
				case "contentData":
					if cur != nil {
						data = text(d, &t)
						depth--
					}
				case "uri", "URI":
					if cur != nil {
						if u := text(d, &t); u != "" && cur.Link == "" {
							cur.Link = u
						}
						depth--
					}
				}
				continue
			}
			if t.Name.Local == "alert" && cur != nil {
				if v, isCAP := Version(t.Name.Space); isCAP {
					var a *Alert
					if v == "1.2" {
						a = &Alert{}
						if err := d.DecodeElement(a, &t); err != nil {
							return nil, fmt.Errorf("an embedded CAP alert cannot be read: %w", err)
						}
						a.Version = v
					} else if err := d.Skip(); err != nil {
						return nil, fmt.Errorf("an embedded CAP alert cannot be read: %w", err)
					}
					depth--
					raw := bytes.TrimSpace(b[start:d.InputOffset()])
					if a == nil {
						var err error
						if a, err = parseEmbedded(raw, t); err != nil {
							return nil, fmt.Errorf("an embedded CAP alert cannot be read: %w", err)
						}
					}
					cur.Alert, cur.Raw, cur.Link = a, raw, ""
				}
			}
		case xml.EndElement:
			depth--
			if t.Name.Local == "contentObject" && cur != nil {
				if cur.Alert == nil && data != "" && strings.Contains(mime, "cap+xml") {
					raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(data), ""))
					if err != nil {
						return nil, fmt.Errorf("content object %d: contentData is not base64: %w", objects, err)
					}
					a, err := Parse(raw)
					if err != nil {
						return nil, fmt.Errorf("content object %d: %w", objects, err)
					}
					cur.Alert, cur.Raw, cur.Link = a, raw, ""
				}
				if cur.Alert != nil || (cur.Link != "" && strings.Contains(mime, "cap+xml")) {
					dist.Entries = append(dist.Entries, *cur)
				}
				cur = nil
			}
		}
	}
	if dist == nil {
		return nil, errors.New("the EDXL-DE document has no root element")
	}
	return dist, nil
}

// WriteEDXLDE writes an EDXL-DE 1.0 envelope with one content object per
// CAP document, embedded as XML. The documents are embedded byte for byte
// (their XML declarations dropped), so signed alerts stay verifiable.
// d's ID, SenderID, Sent, Status and Type are required (Type is Report,
// Update, Cancel and so on, as EDXL-DE 1.0 lists them); Version and
// Entries are ignored.
func WriteEDXLDE(d Distribution, docs ...[]byte) ([]byte, error) {
	for _, f := range []struct{ n, v string }{{"distributionID", d.ID}, {"senderID", d.SenderID}, {"dateTimeSent", d.Sent}, {"distributionStatus", d.Status}, {"distributionType", d.Type}} {
		if strings.TrimSpace(f.v) == "" {
			return nil, fmt.Errorf("EDXL-DE: %s is required", f.n)
		}
	}
	conf := d.Confidentiality
	if conf == "" {
		conf = "UNCLASSIFIED AND NOT SENSITIVE"
	}
	var b bytes.Buffer
	b.WriteString(xml.Header)
	b.WriteString(`<EDXLDistribution xmlns="` + EDXLDE10Namespace + `">` + "\n")
	for _, f := range []struct{ n, v string }{{"distributionID", d.ID}, {"senderID", d.SenderID}, {"dateTimeSent", d.Sent},
		{"distributionStatus", d.Status}, {"distributionType", d.Type}, {"combinedConfidentiality", conf}} {
		b.WriteString("  <" + f.n + ">")
		_ = xml.EscapeText(&b, []byte(f.v))
		b.WriteString("</" + f.n + ">\n")
	}
	for i, doc := range docs {
		doc = bytes.TrimSpace(doc)
		if bytes.HasPrefix(doc, []byte("<?xml")) {
			if j := bytes.Index(doc, []byte("?>")); j >= 0 {
				doc = bytes.TrimSpace(doc[j+2:])
			}
		}
		if _, err := Parse(doc); err != nil {
			return nil, fmt.Errorf("EDXL-DE: document %d: %w", i, err)
		}
		b.WriteString("  <contentObject><xmlContent><embeddedXMLContent>")
		b.Write(doc)
		b.WriteString("</embeddedXMLContent></xmlContent></contentObject>\n")
	}
	b.WriteString("</EDXLDistribution>\n")
	return b.Bytes(), nil
}

// EDXLContent is one content object of an EDXL-DE 2.0 envelope written by
// WriteEDXLDE2: a CAP document embedded as XML (Doc), the same carried in
// base64 (Doc with Base64), or an alert given by its URI (Link, with Size
// and Digest, the SHA-1 of the document, when known).
type EDXLContent struct {
	Doc         []byte
	Base64      bool
	Link        string
	Size        int64
	Digest      []byte
	Description string // contentDescription
	Language    string // contentLanguage
}

// WriteEDXLDE2 writes an EDXL-DE 2.0 envelope: the envelope elements, a
// descriptor when d.Confidentiality is set ("Unclassified" or
// "Classified" in 2.0), and one content object per CAP document or link.
// Embedded documents go in byte for byte (their XML declarations dropped)
// so signed alerts stay verifiable. d's ID, SenderID, Sent, Status and
// Type (written as distributionKind: Report, Update, Cancel and so on) are
// required; Expires, required by 2.0, defaults to the latest expiry of the
// embedded alerts' info blocks. The xlink:type attributes the 2.0 schema
// requires are written.
func WriteEDXLDE2(d Distribution, contents ...EDXLContent) ([]byte, error) {
	for _, f := range []struct{ n, v string }{{"distributionID", d.ID}, {"senderID", d.SenderID}, {"dateTimeSent", d.Sent}, {"distributionStatus", d.Status}, {"distributionKind", d.Type}} {
		if strings.TrimSpace(f.v) == "" {
			return nil, fmt.Errorf("EDXL-DE: %s is required", f.n)
		}
	}
	if len(contents) == 0 {
		return nil, errors.New("EDXL-DE: no content")
	}
	if c := d.Confidentiality; c != "" && c != "Unclassified" && c != "Classified" {
		return nil, fmt.Errorf("EDXL-DE 2.0: combinedConfidentiality %q is not Unclassified or Classified", c)
	}
	type obj struct {
		c   EDXLContent
		doc []byte
	}
	objs := make([]obj, 0, len(contents))
	expires := d.Expires
	var latest time.Time
	var latestText string
	for i, c := range contents {
		if (len(c.Doc) == 0) == (c.Link == "") {
			return nil, fmt.Errorf("EDXL-DE: content %d needs a document or a link, not both", i)
		}
		if c.Link != "" {
			objs = append(objs, obj{c: c})
			continue
		}
		doc := bytes.TrimSpace(c.Doc)
		if bytes.HasPrefix(doc, []byte("<?xml")) {
			if j := bytes.Index(doc, []byte("?>")); j >= 0 {
				doc = bytes.TrimSpace(doc[j+2:])
			}
		}
		a, err := Parse(doc)
		if err != nil {
			return nil, fmt.Errorf("EDXL-DE: content %d: %w", i, err)
		}
		for _, in := range a.Info {
			if t, err := time.Parse(time.RFC3339, in.Expires); err == nil && t.After(latest) {
				latest, latestText = t, in.Expires
			}
		}
		objs = append(objs, obj{c: c, doc: doc})
	}
	if expires == "" {
		expires = latestText
	}
	if expires == "" {
		return nil, errors.New("EDXL-DE 2.0: dateTimeExpires is required (set Expires, or give alerts that expire)")
	}
	var b bytes.Buffer
	esc := func(s string) { _ = xml.EscapeText(&b, []byte(s)) }
	elem := func(indent, name, v string) {
		b.WriteString(indent + "<" + name + ">")
		esc(v)
		b.WriteString("</" + name + ">\n")
	}
	b.WriteString(xml.Header)
	b.WriteString(`<edxlDistribution xmlns="` + EDXLDE20Namespace + `" xmlns:xlink="http://www.w3.org/1999/xlink" xlink:type="extended">` + "\n")
	elem("  ", "distributionID", d.ID)
	elem("  ", "senderID", d.SenderID)
	elem("  ", "dateTimeSent", d.Sent)
	elem("  ", "dateTimeExpires", expires)
	elem("  ", "distributionStatus", d.Status)
	elem("  ", "distributionKind", d.Type)
	if d.Confidentiality != "" {
		b.WriteString(`  <descriptor xlink:type="resource">` + "\n")
		elem("    ", "combinedConfidentiality", d.Confidentiality)
		b.WriteString("  </descriptor>\n")
	}
	b.WriteString(`  <content xlink:type="resource">` + "\n")
	for _, o := range objs {
		b.WriteString(`    <contentObject xlink:type="resource">` + "\n")
		if o.c.Description != "" || o.c.Language != "" {
			b.WriteString("      <contentDescriptor>\n")
			if o.c.Description != "" {
				elem("        ", "contentDescription", o.c.Description)
			}
			if o.c.Language != "" {
				elem("        ", "contentLanguage", o.c.Language)
			}
			b.WriteString("      </contentDescriptor>\n")
		}
		switch {
		case o.c.Link != "":
			b.WriteString("      <otherContent>\n")
			elem("        ", "mimeType", "application/cap+xml")
			if o.c.Size > 0 {
				elem("        ", "size", fmt.Sprint(o.c.Size))
			}
			if len(o.c.Digest) > 0 {
				elem("        ", "digest", base64.StdEncoding.EncodeToString(o.c.Digest))
			}
			elem("        ", "uri", o.c.Link)
			b.WriteString("      </otherContent>\n")
		case o.c.Base64:
			sum := sha1.Sum(o.doc)
			b.WriteString("      <otherContent>\n")
			elem("        ", "mimeType", "application/cap+xml")
			elem("        ", "size", fmt.Sprint(len(o.doc)))
			elem("        ", "digest", base64.StdEncoding.EncodeToString(sum[:]))
			elem("        ", "contentData", base64.StdEncoding.EncodeToString(o.doc))
			b.WriteString("      </otherContent>\n")
		default:
			b.WriteString("      <contentXML><embeddedXMLContent>")
			b.Write(o.doc)
			b.WriteString("</embeddedXMLContent></contentXML>\n")
		}
		b.WriteString("    </contentObject>\n")
	}
	b.WriteString("  </content>\n</edxlDistribution>\n")
	return b.Bytes(), nil
}

// parseEmbedded reads an alert element cut out of a larger document. The
// element usually declares its own namespace; when it inherits it, the
// declaration is added so the element reads on its own.
func parseEmbedded(raw []byte, se xml.StartElement) (*Alert, error) {
	a, err := Parse(raw)
	if err == nil {
		return a, nil
	}
	if bytes.HasPrefix(raw, []byte("<alert")) && !bytes.Contains(raw[:bytes.IndexByte(raw, '>')+1], []byte("xmlns")) {
		fixed := append([]byte(`<alert xmlns="`+se.Name.Space+`"`), raw[len("<alert"):]...)
		if a, err2 := Parse(fixed); err2 == nil {
			return a, nil
		}
	}
	return nil, err
}
