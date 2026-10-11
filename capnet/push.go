// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package capnet

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cB-Sigma/cap"
)

// Receiver is an http.Handler that takes CAP documents by POST (as
// application/cap+xml): it checks the bearer token, the signature (with
// Verifier), the schema (with Schema validators, when set), CAP 1.2 and
// the profiles, then hands the alert to Deliver. Answers: 204 when
// delivered, 400 for a document that is not CAP, 401 for a wrong token,
// 403 for a signature that does not verify, 413 for a body over MaxBytes,
// 415 for another media type, 422 for an alert with errors, and 503 when
// Deliver fails.
type Receiver struct {
	// Token, when set, is the bearer token every request must carry.
	Token string
	// Verifier, when set, checks signatures; the alert delivered is the
	// verified document's.
	Verifier *cap.Verifier
	// Schema validators, when given, run as cap.ValidateSchema's extras
	// (capxsd.Validator for the OASIS schema); nil skips the schema check.
	Schema []cap.SchemaValidator
	// Options are the validation options (profiles, lenient times).
	Options cap.Options
	// MaxBytes bounds a body (default 1 MiB).
	MaxBytes int64
	// Deliver takes each accepted alert with its document as posted; an
	// error answers 503 so the sender retries.
	Deliver func(ctx context.Context, it Item) error
}

// ServeHTTP handles one POST.
func (rc *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if rc.Token != "" {
		got := r.Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(got), []byte("Bearer "+rc.Token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="cap"`)
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if !strings.HasPrefix(ct, cap.MediaType) && !strings.HasPrefix(ct, "application/xml") && !strings.HasPrefix(ct, "text/xml") {
		http.Error(w, "send "+cap.MediaType, http.StatusUnsupportedMediaType)
		return
	}
	max := rc.MaxBytes
	if max <= 0 {
		max = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if int64(len(body)) > max {
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
		return
	}
	doc := body
	if rc.Verifier != nil {
		verified, _, err := rc.Verifier.Verify(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		doc = verified
	}
	if rc.Schema != nil {
		if err := cap.ValidateSchema(doc, rc.Schema...); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}
	a, err := cap.Parse(doc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.Validate(rc.Options); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if rc.Deliver != nil {
		if err := rc.Deliver(r.Context(), Item{Alert: a, Raw: body}); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// Pusher sends CAP documents by HTTP POST as application/cap+xml, with a
// bearer token when set, retrying network errors, 408, 429 and 5xx answers
// with exponential backoff (honouring Retry-After). 4xx answers other than
// those are final.
type Pusher struct {
	// Client makes the requests (http.DefaultClient when nil).
	Client *http.Client
	// Token, when set, is sent as a bearer token.
	Token string
	// Attempts is the number of tries (default 5); Backoff the first wait
	// (default 1 s, doubling, at most 1 min).
	Attempts int
	Backoff  time.Duration
	// UserAgent is sent with every request when set.
	UserAgent string
}

// PushError is a final refusal by the receiver.
type PushError struct {
	Status int
	Body   string
}

func (e *PushError) Error() string {
	return fmt.Sprintf("capnet: the receiver answered %d: %s", e.Status, e.Body)
}

// Push posts doc to url, retrying as Pusher says; it checks first that doc
// reads as CAP.
func (p *Pusher) Push(ctx context.Context, url string, doc []byte) error {
	if _, err := cap.Parse(doc); err != nil {
		return err
	}
	attempts := p.Attempts
	if attempts <= 0 {
		attempts = 5
	}
	wait := p.Backoff
	if wait <= 0 {
		wait = time.Second
	}
	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return errors.Join(ctx.Err(), last)
			case <-time.After(wait):
			}
			wait = min(2*wait, time.Minute)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(doc))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", cap.MediaType)
		if p.Token != "" {
			req.Header.Set("Authorization", "Bearer "+p.Token)
		}
		if p.UserAgent != "" {
			req.Header.Set("User-Agent", p.UserAgent)
		}
		resp, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			return nil
		}
		last = &PushError{Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
		if resp.StatusCode != http.StatusRequestTimeout && resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
			return last
		}
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			var secs int
			if _, err := fmt.Sscanf(ra, "%d", &secs); err == nil && secs > 0 {
				wait = min(time.Duration(secs)*time.Second, 10*time.Minute)
			}
		}
	}
	return last
}
