// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPOptions configures OCSPCheck.
type OCSPOptions struct {
	// Client sends the requests; nil is a client with a 10 second timeout.
	Client *http.Client
	// Strict fails a chain when a certificate names no responder, the
	// responder cannot be reached, its answer is "unknown" or stale.
	// Without it those cases pass (soft fail) and only a "revoked" answer
	// refuses the chain.
	Strict bool
	// LeafOnly asks only about the signing certificate, not about the
	// intermediate CAs above it.
	LeafOnly bool
	// Now is the clock for freshness (tests); nil is time.Now.
	Now func() time.Time
}

// OCSPCheck returns a revocation check for Verifier.Revoked that asks the
// OCSP responder each certificate of the chain names (its Authority
// Information Access extension) about it, signed by or for its issuer,
// the next certificate of the chain (RFC 6960, via
// golang.org/x/crypto/ocsp). A "revoked" answer refuses the chain with
// ErrRevoked; see OCSPOptions.Strict for the other cases. Combine it with
// CRLCheck in a function of your own to use both.
func OCSPCheck(o OCSPOptions) func(chain []*x509.Certificate) error {
	client := o.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return func(chain []*x509.Certificate) error {
		for i := 0; i+1 < len(chain); i++ {
			if o.LeafOnly && i > 0 {
				break
			}
			c, issuer := chain[i], chain[i+1]
			err := ocspAsk(client, c, issuer, now())
			if errors.Is(err, ErrRevoked) || (err != nil && o.Strict) {
				return err
			}
		}
		return nil
	}
}

func ocspAsk(client *http.Client, c, issuer *x509.Certificate, at time.Time) error {
	if len(c.OCSPServer) == 0 {
		return fmt.Errorf("OCSP: certificate %q names no responder", c.Subject.CommonName)
	}
	req, err := ocsp.CreateRequest(c, issuer, nil)
	if err != nil {
		return fmt.Errorf("OCSP: %w", err)
	}
	var last error
	for _, server := range c.OCSPServer {
		resp, err := client.Post(server, "application/ocsp-request", bytes.NewReader(req))
		if err != nil {
			last = fmt.Errorf("OCSP: %s: %w", server, err)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			last = fmt.Errorf("OCSP: %s answered %d", server, resp.StatusCode)
			continue
		}
		r, err := ocsp.ParseResponseForCert(body, c, issuer)
		if err != nil {
			last = fmt.Errorf("OCSP: %s: %w", server, err)
			continue
		}
		switch {
		case r.Status == ocsp.Revoked:
			return fmt.Errorf("%w: %q (serial %s) per OCSP since %s", ErrRevoked, c.Subject.CommonName, c.SerialNumber, r.RevokedAt.Format(time.RFC3339))
		case !r.NextUpdate.IsZero() && at.After(r.NextUpdate):
			return fmt.Errorf("OCSP: the answer about %q is stale (next update %s)", c.Subject.CommonName, r.NextUpdate.Format(time.RFC3339))
		case r.Status == ocsp.Good:
			return nil
		default:
			return fmt.Errorf("OCSP: the responder does not know %q", c.Subject.CommonName)
		}
	}
	return last
}
