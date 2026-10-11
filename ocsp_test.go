// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap_test

import (
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
	"golang.org/x/crypto/ocsp"
)

// responder is a test OCSP responder for the PKI's issuing CA.
type responder struct {
	p       *pki
	mu      sync.Mutex
	status  int // ocsp.Good, ocsp.Revoked, ocsp.Unknown; -1 answers 500
	next    time.Time
	queries int
}

func (r *responder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries++
	if r.status < 0 {
		http.Error(w, "down", http.StatusInternalServerError)
		return
	}
	body, _ := io.ReadAll(req.Body)
	q, err := ocsp.ParseRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tmpl := ocsp.Response{Status: r.status, SerialNumber: q.SerialNumber, ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: r.next}
	if r.status == ocsp.Revoked {
		tmpl.RevokedAt = time.Now().Add(-time.Minute)
	}
	der, err := ocsp.CreateResponse(r.p.inter, r.p.inter, tmpl, r.p.intKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(der)
}

func (r *responder) set(status int, next time.Time) {
	r.mu.Lock()
	r.status, r.next = status, next
	r.mu.Unlock()
}

// OCSPCheck asks the responder a signing certificate names: "good"
// passes, "revoked" refuses; an unreachable responder, an "unknown" or a
// stale answer and a certificate without a responder pass unless Strict.
//
// Covers: SIG-IPE-711
func TestCAPVerifyOCSP(t *testing.T) {
	p := newPKI(t)
	r := &responder{p: p}
	srv := httptest.NewServer(r)
	defer srv.Close()
	now := time.Now()
	p.ocsp = []string{srv.URL}
	s, _ := p.signer("ocsp.example.test", true, now.Add(-time.Hour), now.Add(24*time.Hour), 0)
	p.ocsp = nil
	signed := signedRain(t, s)
	s2, _ := p.signer("no-ocsp.example.test", true, now.Add(-time.Hour), now.Add(24*time.Hour), 0)
	noResponder := signedRain(t, s2)

	soft, _ := cap.NewVerifier(cap.VerifySettings{Roots: []string{p.rootPEM}})
	soft.Revoked = cap.OCSPCheck(cap.OCSPOptions{})
	strict, _ := cap.NewVerifier(cap.VerifySettings{Roots: []string{p.rootPEM}})
	strict.Revoked = cap.OCSPCheck(cap.OCSPOptions{Strict: true, LeafOnly: true, Client: srv.Client()})
	// Strict on the whole chain: the test intermediate names no responder.
	whole, _ := cap.NewVerifier(cap.VerifySettings{Roots: []string{p.rootPEM}})
	whole.Revoked = cap.OCSPCheck(cap.OCSPOptions{Strict: true})
	r.set(ocsp.Good, now.Add(time.Hour))
	if _, _, err := whole.Verify(signed); err == nil || !strings.Contains(err.Error(), `"Test Issuing CA" names no responder`) {
		t.Errorf("strict whole chain: %v", err)
	}

	r.set(ocsp.Good, now.Add(time.Hour))
	for name, v := range map[string]*cap.Verifier{"soft": soft, "strict": strict} {
		if _, _, err := v.Verify(signed); err != nil {
			t.Errorf("%s, good: %v", name, err)
		}
	}
	r.set(ocsp.Revoked, now.Add(time.Hour))
	for name, v := range map[string]*cap.Verifier{"soft": soft, "strict": strict} {
		if _, _, err := v.Verify(signed); !errors.Is(err, cap.ErrRevoked) {
			t.Errorf("%s, revoked: %v", name, err)
		}
	}
	for _, tc := range []struct {
		name   string
		status int
		next   time.Time
		doc    []byte
		want   string
	}{
		{"unknown", ocsp.Unknown, now.Add(time.Hour), signed, "does not know"},
		{"stale", ocsp.Good, now.Add(-time.Minute), signed, "stale"},
		{"down", -1, time.Time{}, signed, "answered 500"},
		{"no responder", ocsp.Good, now.Add(time.Hour), noResponder, "names no responder"},
	} {
		r.set(tc.status, tc.next)
		if _, _, err := soft.Verify(tc.doc); err != nil {
			t.Errorf("soft, %s: %v", tc.name, err)
		}
		if _, _, err := strict.Verify(tc.doc); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("strict, %s: %v, want %q", tc.name, err, tc.want)
		}
	}
	if r.queries == 0 {
		t.Error("the responder was never asked")
	}
	// A pinned certificate is a chain of one: nothing to ask.
	r.set(ocsp.Revoked, now.Add(time.Hour))
	if err := cap.OCSPCheck(cap.OCSPOptions{Strict: true})([]*x509.Certificate{p.root}); err != nil {
		t.Errorf("chain of one: %v", err)
	}
}
