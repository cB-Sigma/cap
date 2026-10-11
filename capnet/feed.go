// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package capnet

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/cap"
)

// Format is how a FeedHandler presents its alerts.
type Format int

// Feed formats.
const (
	AtomEmbedded Format = iota // Atom (RFC 4287) entries carrying each alert as content
	AtomLinked                 // Atom entries linking to each alert's document
	RSSLinked                  // RSS 2.0 items linking to each alert's document
	EDXLDE10                   // one EDXL-DE 1.0 envelope, an embedded alert per content object
	EDXLDE20                   // one EDXL-DE 2.0 envelope, an embedded alert per content object
)

// FeedHandler serves a CAP feed of the alerts published to it, newest
// first, with ETag and Last-Modified and 304 answers to conditional GETs,
// and each alert's document at Base+"alerts/<n>.xml". Published documents
// are served byte for byte, so signatures stay verifiable. Expired alerts
// leave the feed (Prune). It is safe for concurrent use.
type FeedHandler struct {
	Format Format
	// ID, Title and Author describe the feed (Atom id and title, RSS title,
	// EDXL-DE senderID).
	ID, Title, Author string
	// Base is the path the handler is mounted at, ending in "/" (default
	// "/"); the feed itself is served at Base and Base+"feed".
	Base string
	// Now gives the time (time.Now when nil).
	Now func() time.Time

	mu       sync.Mutex
	docs     []published
	next     int
	version  int
	modified time.Time
}

type published struct {
	n     int
	alert *cap.Alert
	raw   []byte
}

func (h *FeedHandler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *FeedHandler) base() string {
	if h.Base == "" {
		return "/"
	}
	return h.Base
}

// Publish adds a CAP document (signed or not) to the feed after checking
// that it reads as CAP. An alert with the same sender and identifier as
// one already published replaces it.
func (h *FeedHandler) Publish(doc []byte) error {
	a, err := cap.Parse(doc)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, p := range h.docs {
		if p.alert.Sender == a.Sender && p.alert.Identifier == a.Identifier {
			h.docs = append(h.docs[:i], h.docs[i+1:]...)
			break
		}
	}
	h.docs = append(h.docs, published{n: h.next, alert: a, raw: bytes.TrimSpace(doc)})
	h.next++
	h.changed()
	return nil
}

// Remove takes an alert off the feed by sender and identifier.
func (h *FeedHandler) Remove(sender, identifier string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, p := range h.docs {
		if p.alert.Sender == sender && p.alert.Identifier == identifier {
			h.docs = append(h.docs[:i], h.docs[i+1:]...)
			h.changed()
			return true
		}
	}
	return false
}

// Prune takes off the feed the alerts whose every info block has expired
// at t; an alert without expiry stays.
func (h *FeedHandler) Prune(t time.Time) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	keep := h.docs[:0]
	n := 0
	for _, p := range h.docs {
		if exp := p.alert.Expires(); !exp.IsZero() && exp.Before(t) {
			n++
			continue
		}
		keep = append(keep, p)
	}
	h.docs = keep
	if n > 0 {
		h.changed()
	}
	return n
}

func (h *FeedHandler) changed() {
	h.version++
	m := h.now().UTC().Truncate(time.Second)
	if !m.After(h.modified) {
		m = h.modified.Add(time.Second)
	}
	h.modified = m
}

// ServeHTTP serves the feed and the documents.
func (h *FeedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, h.base())
	if !ok {
		http.NotFound(w, r)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if name, ok := strings.CutPrefix(rest, "alerts/"); ok {
		n, err := strconv.Atoi(strings.TrimSuffix(name, ".xml"))
		for _, p := range h.docs {
			if err == nil && p.n == n {
				w.Header().Set("Content-Type", cap.MediaType)
				_, _ = w.Write(p.raw)
				return
			}
		}
		http.NotFound(w, r)
		return
	}
	if rest != "" && rest != "feed" {
		http.NotFound(w, r)
		return
	}
	if h.modified.IsZero() {
		h.modified = h.now().UTC().Truncate(time.Second)
	}
	etag := fmt.Sprintf(`"cap-%d"`, h.version)
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		if inm == etag || inm == "*" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	} else if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if t, err := http.ParseTime(ims); err == nil && !h.modified.After(t) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	body, ctype, err := h.render(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", h.modified.Format(http.TimeFormat))
	_, _ = w.Write(body)
}

// docURL is a document's absolute URL as the request reached the handler.
func (h *FeedHandler) docURL(r *http.Request, n int) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s%salerts/%d.xml", scheme, r.Host, h.base(), n)
}

func withoutDecl(b []byte) []byte {
	if bytes.HasPrefix(b, []byte("<?xml")) {
		if j := bytes.Index(b, []byte("?>")); j >= 0 {
			return bytes.TrimSpace(b[j+2:])
		}
	}
	return b
}

func esc(b *bytes.Buffer, s string) { _ = xml.EscapeText(b, []byte(s)) }

func (h *FeedHandler) render(r *http.Request) ([]byte, string, error) {
	var b bytes.Buffer
	title := h.Title
	if title == "" {
		title = "CAP alerts"
	}
	id := h.ID
	if id == "" {
		id = "urn:cap-feed"
	}
	switch h.Format {
	case RSSLinked:
		b.WriteString(xml.Header + `<rss version="2.0"><channel><title>`)
		esc(&b, title)
		b.WriteString(`</title><link>`)
		esc(&b, h.base())
		b.WriteString(`</link><description>`)
		esc(&b, title)
		b.WriteString(`</description>`)
		for i := len(h.docs) - 1; i >= 0; i-- {
			p := h.docs[i]
			b.WriteString(`<item><title>`)
			esc(&b, itemTitle(p.alert))
			b.WriteString(`</title><link>`)
			esc(&b, h.docURL(r, p.n))
			b.WriteString(`</link><guid isPermaLink="false">`)
			esc(&b, p.alert.Key())
			b.WriteString(`</guid>`)
			if t, err := cap.ParseTime(p.alert.Sent); err == nil {
				b.WriteString(`<pubDate>` + t.Format(time.RFC1123Z) + `</pubDate>`)
			}
			b.WriteString(`</item>`)
		}
		b.WriteString(`</channel></rss>`)
		return b.Bytes(), "application/rss+xml", nil
	case EDXLDE10, EDXLDE20:
		if len(h.docs) == 0 {
			return nil, "", errors.New("capnet: an EDXL-DE feed needs at least one alert")
		}
		sender := h.Author
		if sender == "" {
			sender = "cap-feed"
		}
		d := cap.Distribution{ID: fmt.Sprintf("%s-%d", id, h.version), SenderID: sender, Sent: cap.FormatTime(h.modified),
			Status: "Actual", Type: "Report"}
		if h.Format == EDXLDE10 {
			docs := make([][]byte, 0, len(h.docs))
			for i := len(h.docs) - 1; i >= 0; i-- {
				docs = append(docs, h.docs[i].raw)
			}
			out, err := cap.WriteEDXLDE(d, docs...)
			return out, "application/xml", err
		}
		cs := make([]cap.EDXLContent, 0, len(h.docs))
		latest := time.Time{}
		for i := len(h.docs) - 1; i >= 0; i-- {
			cs = append(cs, cap.EDXLContent{Doc: h.docs[i].raw})
			if e := h.docs[i].alert.Expires(); e.After(latest) {
				latest = e
			}
		}
		if latest.IsZero() {
			latest = h.modified.Add(24 * time.Hour)
		}
		d.Expires = cap.FormatTime(latest)
		out, err := cap.WriteEDXLDE2(d, cs...)
		return out, "application/xml", err
	default:
		b.WriteString(xml.Header + `<feed xmlns="http://www.w3.org/2005/Atom"><id>`)
		esc(&b, id)
		b.WriteString(`</id><title>`)
		esc(&b, title)
		b.WriteString(`</title><updated>` + h.modified.Format(time.RFC3339) + `</updated>`)
		if h.Author != "" {
			b.WriteString(`<author><name>`)
			esc(&b, h.Author)
			b.WriteString(`</name></author>`)
		}
		for i := len(h.docs) - 1; i >= 0; i-- {
			p := h.docs[i]
			b.WriteString(`<entry><id>`)
			esc(&b, "urn:cap:"+p.alert.Key())
			b.WriteString(`</id><title>`)
			esc(&b, itemTitle(p.alert))
			b.WriteString(`</title><updated>`)
			upd := h.modified.Format(time.RFC3339)
			if t, err := cap.ParseTime(p.alert.Sent); err == nil {
				upd = t.Format(time.RFC3339)
			}
			b.WriteString(upd + `</updated>`)
			if h.Format == AtomLinked {
				b.WriteString(`<link rel="alternate" type="` + cap.MediaType + `" href="`)
				esc(&b, h.docURL(r, p.n))
				b.WriteString(`"/>`)
			} else {
				b.WriteString(`<content type="` + cap.MediaType + `">`)
				b.Write(withoutDecl(p.raw))
				b.WriteString(`</content>`)
			}
			b.WriteString(`</entry>`)
		}
		b.WriteString(`</feed>`)
		return b.Bytes(), "application/atom+xml", nil
	}
}

func itemTitle(a *cap.Alert) string {
	for _, in := range a.Info {
		if in.Headline != "" {
			return in.Headline
		}
		if in.Event != "" {
			return in.Event
		}
	}
	return a.Identifier
}
