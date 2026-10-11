// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package capnet is the network side of CAP: a feed poller for consumers,
// a feed server and a push receiver as http.Handlers for publishers and
// gateways, a push sender, and a client for the TCP alert stream of
// Canada's NAAD System. It uses only the standard library and package cap.
package capnet

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/cap"
)

// Item is an alert a Poller or NAADSStream delivers: the feed entry it
// came from (empty for a stream), the alert and its document as received
// (verify signatures on Raw, never on a re-encoded alert).
type Item struct {
	Entry cap.Entry
	Alert *cap.Alert
	Raw   []byte
}

// Poller reads a CAP feed (Atom, RSS, an EDXL-DE envelope or a bare
// alert, see cap.ParseFeed) with conditional GETs, fetches the CAP
// documents that entries link to, and delivers each alert once (by
// sender, identifier and sent). It is safe for one goroutine at a time.
type Poller struct {
	// URL is the feed's address.
	URL string
	// Client makes the requests (http.DefaultClient when nil).
	Client *http.Client
	// UserAgent is sent with every request; some feeds (the US NWS API)
	// refuse requests without one.
	UserAgent string
	// MaxBytes bounds a feed or document (default 8 MiB).
	MaxBytes int64
	// SkipLinked leaves entries that link to their alert undelivered
	// instead of fetching the document.
	SkipLinked bool
	// History, when set, has every delivered alert added, so that its
	// Missing and Profile see the feed's Update and Cancel chains.
	History *cap.History
	// MaxPages is how many pages of a paged Atom feed (RFC 5005, links
	// rel="next") one poll reads; 0 or 1 reads the first only.
	MaxPages int
	// MaxLinked bounds the documents fetched in one poll (0: no bound);
	// the entries left are fetched by the next polls, which spares feeds
	// that limit request rates.
	MaxLinked int
	// Accept is sent as the Accept header of document fetches (default
	// application/cap+xml, then XML).
	Accept string

	mu           sync.Mutex
	etag, lastMo string
	seen         map[string]time.Time
}

// ErrNotModified is what Poll's second result reports when the feed
// answered 304.
var ErrNotModified = errors.New("capnet: the feed has not changed")

func (p *Poller) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	return http.DefaultClient
}

func (p *Poller) max() int64 {
	if p.MaxBytes > 0 {
		return p.MaxBytes
	}
	return 8 << 20
}

func (p *Poller) get(ctx context.Context, url, accept string, conditional bool) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	if p.UserAgent != "" {
		req.Header.Set("User-Agent", p.UserAgent)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if conditional {
		p.mu.Lock()
		if p.etag != "" {
			req.Header.Set("If-None-Match", p.etag)
		}
		if p.lastMo != "" {
			req.Header.Set("If-Modified-Since", p.lastMo)
		}
		p.mu.Unlock()
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, resp, ErrNotModified
	}
	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, resp, fmt.Errorf("capnet: GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, p.max()+1))
	if err != nil {
		return nil, resp, err
	}
	if int64(len(b)) > p.max() {
		return nil, resp, fmt.Errorf("capnet: GET %s: over %d bytes", url, p.max())
	}
	return b, resp, nil
}

// Poll reads the feed once and returns the alerts not delivered before,
// in feed order. When the feed has not changed it returns no items and
// ErrNotModified. Entries whose linked document cannot be fetched or read
// are reported in the error (errors.Join) while the others are returned.
func (p *Poller) Poll(ctx context.Context) ([]Item, error) {
	b, resp, err := p.get(ctx, p.URL, "", true)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	if v := resp.Header.Get("ETag"); v != "" {
		p.etag = v
	}
	if v := resp.Header.Get("Last-Modified"); v != "" {
		p.lastMo = v
	}
	if p.seen == nil {
		p.seen = map[string]time.Time{}
	}
	p.mu.Unlock()
	entries, err := cap.ParseFeed(b)
	if err != nil {
		return nil, err
	}
	// A paged Atom feed (RFC 5005): follow rel="next" up to MaxPages.
	pageURL := p.URL
	for page := 1; page < p.MaxPages; page++ {
		next := nextLink(b)
		if next == "" {
			break
		}
		pageURL = resolve(pageURL, next)
		if b, _, err = p.get(ctx, pageURL, "", false); err != nil {
			return nil, err
		}
		more, err := cap.ParseFeed(b)
		if err != nil {
			return nil, err
		}
		entries = append(entries, more...)
	}
	accept := p.Accept
	if accept == "" {
		accept = cap.MediaType + ", application/xml;q=0.9, text/xml;q=0.8"
	}
	var out []Item
	var errs []error
	fetched, left := 0, false
	for _, e := range entries {
		a, raw := e.Alert, e.Raw
		if a == nil {
			if e.Link == "" || p.SkipLinked {
				continue
			}
			link := resolve(p.URL, e.Link)
			if p.isSeenLink(link) {
				continue
			}
			if p.MaxLinked > 0 && fetched >= p.MaxLinked {
				left = true
				continue
			}
			fetched++
			doc, _, err := p.get(ctx, link, accept, false)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if a, err = cap.Parse(doc); err != nil {
				errs = append(errs, fmt.Errorf("capnet: %s: %w", link, err))
				continue
			}
			raw = doc
			p.markLink(link)
		}
		p.mu.Lock()
		_, dup := p.seen[a.Key()]
		if !dup {
			p.seen[a.Key()] = a.Expires()
		}
		p.mu.Unlock()
		if dup {
			continue
		}
		if p.History != nil {
			p.History.Add(a)
		}
		out = append(out, Item{Entry: e, Alert: a, Raw: raw})
	}
	if left {
		// Entries wait for the next poll: it must read the feed again.
		p.mu.Lock()
		p.etag, p.lastMo = "", ""
		p.mu.Unlock()
	}
	return out, errors.Join(errs...)
}

func (p *Poller) isSeenLink(link string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.seen["link "+link]
	return ok
}

func (p *Poller) markLink(link string) {
	p.mu.Lock()
	p.seen["link "+link] = time.Time{}
	p.mu.Unlock()
}

// Forget drops what the poller remembers of alerts that expired before t
// (and of every linked document), bounding its memory on a long run; an
// expired alert that reappears is then delivered again.
func (p *Poller) Forget(t time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, exp := range p.seen {
		if strings.HasPrefix(k, "link ") || (!exp.IsZero() && exp.Before(t)) {
			delete(p.seen, k)
		}
	}
}

// Run polls every interval until ctx ends, calling deliver for each new
// item and report (when set) for each error other than ErrNotModified.
func (p *Poller) Run(ctx context.Context, interval time.Duration, deliver func(Item), report func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		items, err := p.Poll(ctx)
		for _, it := range items {
			deliver(it)
		}
		if err != nil && !errors.Is(err, ErrNotModified) && report != nil && ctx.Err() == nil {
			report(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// resolve makes a link relative to the feed absolute.
func resolve(base, link string) string {
	b, err := url.Parse(base)
	if err != nil {
		return link
	}
	l, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return link
	}
	return b.ResolveReference(l).String()
}

var (
	linkTag  = regexp.MustCompile(`<(?:[A-Za-z_][\w.-]*:)?link\b[^>]*>`)
	relNext  = regexp.MustCompile(`\brel\s*=\s*["']next["']`)
	hrefAttr = regexp.MustCompile(`\bhref\s*=\s*["']([^"']*)["']`)
)

// nextLink is the href of a feed's link rel="next", or "".
func nextLink(feed []byte) string {
	for _, tag := range linkTag.FindAll(feed, -1) {
		if relNext.Match(tag) {
			if m := hrefAttr.FindSubmatch(tag); m != nil {
				return html.UnescapeString(string(m[1]))
			}
		}
	}
	return ""
}
