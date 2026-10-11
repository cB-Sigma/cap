// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// Certificate chains for signatures. goxmldsig accepts a signature only
// when its KeyInfo certificate is one it was given; to accept certificates
// issued by a trusted CA, the chain is built and checked here (crypto/x509)
// and the signing certificate alone is then handed to goxmldsig, which
// checks the signature itself.

// keyInfoCerts returns the certificates in the KeyInfo of the alert's
// signature, in document order (the signing certificate first).
func keyInfoCerts(root *etree.Element) ([]*x509.Certificate, error) {
	var sig *etree.Element
	for _, c := range root.ChildElements() {
		if c.Tag == "Signature" && c.NamespaceURI() == XMLDSigNamespace {
			sig = c
			break
		}
	}
	if sig == nil {
		return nil, nil
	}
	var out []*x509.Certificate
	for _, ki := range sig.ChildElements() {
		if ki.Tag != "KeyInfo" || ki.NamespaceURI() != XMLDSigNamespace {
			continue
		}
		for _, xd := range ki.ChildElements() {
			if xd.Tag != "X509Data" || xd.NamespaceURI() != XMLDSigNamespace {
				continue
			}
			for _, xc := range xd.ChildElements() {
				if xc.Tag != "X509Certificate" || xc.NamespaceURI() != XMLDSigNamespace {
					continue
				}
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(xc.Text()), ""))
				if err != nil {
					return nil, errors.New("a KeyInfo certificate is not base64")
				}
				c, err := x509.ParseCertificate(der)
				if err != nil {
					return nil, fmt.Errorf("a KeyInfo certificate cannot be read: %w", err)
				}
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// trustChain decides whether the signing certificate (keyInfo[0]) is
// trusted at the time at: pinned, or chained to a root through the other
// KeyInfo certificates and the configured intermediates. It returns the
// accepted chain after the revocation check.
func (v *Verifier) trustChain(keyInfo []*x509.Certificate, at time.Time) ([]*x509.Certificate, error) {
	leaf := keyInfo[0]
	for _, c := range v.certs {
		if c.Equal(leaf) {
			if at.Before(leaf.NotBefore) || at.After(leaf.NotAfter) {
				return nil, fmt.Errorf("certificate %q is not valid at %s", leaf.Subject.CommonName, at.Format(time.RFC3339))
			}
			chain := []*x509.Certificate{leaf}
			return chain, v.revoked(chain)
		}
	}
	if v.roots == nil {
		return nil, fmt.Errorf("certificate %q is not one of the trusted certificates", leaf.Subject.CommonName)
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) == 0 {
		return nil, fmt.Errorf("certificate %q may not be used for signatures (key usage)", leaf.Subject.CommonName)
	}
	inter := x509.NewCertPool()
	for _, c := range v.inters {
		inter.AddCert(c)
	}
	for _, c := range keyInfo[1:] {
		inter.AddCert(c)
	}
	usages := v.KeyUsages
	if len(usages) == 0 {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: v.roots, Intermediates: inter, CurrentTime: at, KeyUsages: usages})
	if err != nil {
		return nil, fmt.Errorf("certificate %q does not chain to a trusted root: %w", leaf.Subject.CommonName, err)
	}
	var first error
	for _, ch := range chains {
		err := v.revoked(ch)
		if err == nil {
			return ch, nil
		}
		if first == nil {
			first = err
		}
	}
	return nil, first
}

func (v *Verifier) revoked(chain []*x509.Certificate) error {
	if v.Revoked == nil {
		return nil
	}
	return v.Revoked(chain)
}

// ErrRevoked is wrapped by the error of a revocation check that found a
// certificate of the chain revoked.
var ErrRevoked = errors.New("certificate revoked")

// CRLCheck returns a revocation check for Verifier.Revoked that refuses a
// chain when one of its certificates is listed on one of the CRLs. A CRL
// counts for a certificate only when it names the certificate's issuer
// and is signed by the next certificate of the chain; other CRLs are
// ignored. A CRL past its next update is still used (its entries do not
// expire); refresh the list and the check to keep it current.
func CRLCheck(crls ...*x509.RevocationList) func(chain []*x509.Certificate) error {
	return func(chain []*x509.Certificate) error {
		for i := 0; i+1 < len(chain); i++ {
			c, issuer := chain[i], chain[i+1]
			for _, crl := range crls {
				if !bytes.Equal(crl.RawIssuer, c.RawIssuer) || crl.CheckSignatureFrom(issuer) != nil {
					continue
				}
				for _, e := range crl.RevokedCertificateEntries {
					if e.SerialNumber != nil && e.SerialNumber.Cmp(c.SerialNumber) == 0 {
						return fmt.Errorf("%w: %q (serial %s) on the CRL of %q since %s", ErrRevoked,
							c.Subject.CommonName, c.SerialNumber, issuer.Subject.CommonName, e.RevocationTime.Format(time.RFC3339))
					}
				}
			}
		}
		return nil
	}
}

// ParseCRLs reads certificate revocation lists given as PEM ("X509 CRL"
// blocks, several per input allowed) or DER.
func ParseCRLs(inputs ...[]byte) ([]*x509.RevocationList, error) {
	var out []*x509.RevocationList
	for i, in := range inputs {
		if !bytes.Contains(in, []byte("-----BEGIN")) {
			l, err := x509.ParseRevocationList(in)
			if err != nil {
				return nil, fmt.Errorf("CRL %d: %w", i, err)
			}
			out = append(out, l)
			continue
		}
		rest, n := in, 0
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if b.Type != "X509 CRL" {
				continue
			}
			l, err := x509.ParseRevocationList(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("CRL %d: %w", i, err)
			}
			out, n = append(out, l), n+1
		}
		if n == 0 {
			return nil, fmt.Errorf("CRL %d: no PEM X509 CRL block", i)
		}
	}
	return out, nil
}
