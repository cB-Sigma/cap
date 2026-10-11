package cap

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// AtomNamespace is the Atom (RFC 4287) namespace.
const AtomNamespace = "http://www.w3.org/2005/Atom"

// Entry is one feed entry: an embedded CAP alert, or a link to one.
type Entry struct {
	ID      string
	Updated string
	Title   string
	Link    string // the CAP document's URL when it is not embedded
	Alert   *Alert // embedded alert, if any
	// Raw is the embedded alert element's text (for signature checks); a
	// bare CAP document's Raw is the whole document.
	Raw []byte
}

// Key identifies an entry version: a changed entry is fetched again.
func (e Entry) Key() string { return e.ID + "|" + e.Updated + "|" + e.Link }

// ParseFeed reads an Atom feed, an RSS 2.0 feed or a bare CAP document
// (one entry). Atom entries may embed the alert in their content or link
// to it; RSS items link to it.
func ParseFeed(b []byte) ([]Entry, error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = false
	var (
		out      []Entry
		cur      *Entry
		root     string
		linkRank int
	)
	for {
		start := d.InputOffset()
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("the feed is not well-formed XML: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			if ee, ok := tok.(xml.EndElement); ok && cur != nil && (ee.Name.Local == "entry" || ee.Name.Local == "item") {
				out = append(out, *cur)
				cur = nil
			}
			continue
		}
		if root == "" {
			root = se.Name.Local
			if _, isCAP := Version(se.Name.Space); root == "alert" && (isCAP || se.Name.Space == "") {
				a, err := Parse(b)
				if err != nil {
					return nil, fmt.Errorf("the CAP document cannot be read: %w", err)
				}
				return []Entry{{ID: a.Identifier, Updated: a.Sent, Alert: a, Raw: b}}, nil
			}
			if root != "feed" && root != "rss" && root != "RDF" {
				return nil, fmt.Errorf("the document is neither an Atom or RSS feed nor a CAP alert (root element %q)", root)
			}
			continue
		}
		switch {
		case se.Name.Local == "entry" || se.Name.Local == "item":
			cur, linkRank = &Entry{}, 0
		case cur == nil:
		case se.Name.Local == "alert" && se.Name.Space == Namespace:
			var a Alert
			if err := d.DecodeElement(&a, &se); err != nil {
				return nil, fmt.Errorf("an embedded CAP alert cannot be read: %w", err)
			}
			a.Version = "1.2"
			cur.Alert = &a
			cur.Raw = bytes.TrimSpace(b[start:d.InputOffset()])
		case se.Name.Local == "alert" && isOldCAP(se.Name.Space):
			// CAP 1.1 or 1.0: read on its own, as 1.2 (Parse).
			if err := d.Skip(); err != nil {
				return nil, fmt.Errorf("an embedded CAP alert cannot be read: %w", err)
			}
			raw := bytes.TrimSpace(b[start:d.InputOffset()])
			a, err := Parse(raw)
			if err != nil {
				return nil, fmt.Errorf("an embedded CAP alert cannot be read: %w", err)
			}
			cur.Alert, cur.Raw = a, raw
		case se.Name.Local == "link":
			href, typ, rel := attr(se, "href"), attr(se, "type"), attr(se, "rel")
			if href == "" { // RSS: the URL is the text
				var s string
				_ = d.DecodeElement(&s, &se)
				href = strings.TrimSpace(s)
			}
			rank := 1
			switch {
			case strings.Contains(typ, "cap+xml"):
				rank = 4
			case rel == "" || rel == "alternate":
				rank = 2
				if strings.HasSuffix(strings.ToLower(href), ".xml") {
					rank = 3
				}
			case rel == "related" || rel == "enclosure":
				rank = 2
			}
			if href != "" && rank > linkRank {
				cur.Link, linkRank = href, rank
			}
		case se.Name.Local == "enclosure":
			if href := attr(se, "url"); href != "" && strings.Contains(attr(se, "type"), "xml") && linkRank < 4 {
				cur.Link, linkRank = href, 4
			}
		case se.Name.Local == "id" || se.Name.Local == "guid":
			cur.ID = text(d, &se)
		case se.Name.Local == "updated" || se.Name.Local == "pubDate" || (se.Name.Local == "published" && cur.Updated == ""):
			cur.Updated = text(d, &se)
		case se.Name.Local == "title":
			cur.Title = text(d, &se)
		}
	}
	return out, nil
}

func isOldCAP(space string) bool {
	v, ok := Version(space)
	return ok && v != "1.2"
}

func attr(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func text(d *xml.Decoder, se *xml.StartElement) string {
	var s string
	_ = d.DecodeElement(&s, se)
	return strings.TrimSpace(s)
}

// ---- Atom output -------------------------------------------------------------

type atomFeed struct {
	XMLName xml.Name    `xml:"http://www.w3.org/2005/Atom feed"`
	ID      string      `xml:"id"`
	Title   string      `xml:"title"`
	Updated string      `xml:"updated"`
	Author  atomPerson  `xml:"author"`
	Links   []atomLink  `xml:"link"`
	Entries []atomEntry `xml:"entry"`
}

type atomPerson struct {
	Name string `xml:"name"`
}

type atomLink struct {
	Rel  string `xml:"rel,attr,omitempty"`
	Type string `xml:"type,attr,omitempty"`
	Href string `xml:"href,attr"`
}

type atomEntry struct {
	ID      string      `xml:"id"`
	Title   string      `xml:"title"`
	Updated string      `xml:"updated"`
	Summary string      `xml:"summary,omitempty"`
	Links   []atomLink  `xml:"link"`
	Content atomContent `xml:"content"`
}

type atomContent struct {
	Type  string `xml:"type,attr"`
	Alert *Alert
}

// FeedMeta describes a published Atom feed.
type FeedMeta struct {
	ID, Title, Author, Self string
	// AlertURL gives the URL a CAP message is also served at.
	AlertURL func(identifier string) string
}

// WriteAtom renders alerts (newest first) as an Atom feed whose entries
// embed each CAP message and link to its own document.
func WriteAtom(m FeedMeta, alerts []*Alert, now time.Time) ([]byte, error) {
	f := atomFeed{ID: m.ID, Title: m.Title, Updated: now.UTC().Format(time.RFC3339), Author: atomPerson{m.Author}}
	if m.Self != "" {
		f.Links = append(f.Links, atomLink{Rel: "self", Type: "application/atom+xml", Href: m.Self})
	}
	for _, a := range alerts {
		a.XMLName = xml.Name{Space: Namespace, Local: "alert"}
		upd := a.Sent
		if t, err := ParseTime(a.Sent); err == nil {
			upd = t.UTC().Format(time.RFC3339)
		}
		e := atomEntry{ID: "urn:cap:" + a.Sender + ":" + a.Identifier, Updated: upd, Content: atomContent{Type: MediaType, Alert: a}}
		e.Title = a.MsgType
		if len(a.Info) > 0 {
			in := a.Info[0]
			e.Title = in.Headline
			if e.Title == "" {
				e.Title = in.Event
			}
			e.Summary = in.Description
		}
		if m.AlertURL != nil {
			e.Links = append(e.Links, atomLink{Rel: "alternate", Type: MediaType, Href: m.AlertURL(a.Identifier)})
		}
		f.Entries = append(f.Entries, e)
	}
	b, err := xml.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), b...), nil
}
