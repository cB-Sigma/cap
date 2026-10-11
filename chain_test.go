// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
)

// pki is a test CA hierarchy: root, intermediate, and signing
// certificates issued by the intermediate.
type pki struct {
	t               *testing.T
	rootKey, intKey crypto.Signer
	root, inter     *x509.Certificate
	rootPEM, intPEM string
	serial          int64
	eku             []x509.ExtKeyUsage // of the next signing certificates
	ocsp            []string           // OCSP responders of the next certificates
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	p := &pki{t: t, serial: 1}
	p.rootKey = ecKey(t)
	p.root = p.issue("Test Root CA", p.rootKey.Public(), nil, nil, true, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour), 0)
	p.intKey = ecKey(t)
	p.inter = p.issue("Test Issuing CA", p.intKey.Public(), p.root, p.rootKey, true, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour), 0)
	p.rootPEM, p.intPEM = certPEM(p.root), certPEM(p.inter)
	return p
}

func ecKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func certPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func keyPEM(t *testing.T, k crypto.Signer) string {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
}

func (p *pki) issue(cn string, pub crypto.PublicKey, parent *x509.Certificate, parentKey crypto.Signer, ca bool, nb, na time.Time, ku x509.KeyUsage) *x509.Certificate {
	p.t.Helper()
	p.serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(p.serial), Subject: pkix.Name{CommonName: cn}, NotBefore: nb, NotAfter: na, KeyUsage: ku, ExtKeyUsage: p.eku, OCSPServer: p.ocsp}
	if ca {
		tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if parent == nil {
		parent, parentKey = tmpl, p.rootKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		p.t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		p.t.Fatal(err)
	}
	return c
}

// signer returns a signer for a new certificate issued by the
// intermediate; withInter puts the intermediate in KeyInfo too.
func (p *pki) signer(cn string, withInter bool, nb, na time.Time, ku x509.KeyUsage) (*cap.Signer, *x509.Certificate) {
	p.t.Helper()
	k := ecKey(p.t)
	c := p.issue(cn, k.Public(), p.inter, p.intKey, false, nb, na, ku)
	chain := certPEM(c)
	if withInter {
		chain += p.intPEM
	}
	s, err := cap.NewSigner(cap.SignSettings{Key: keyPEM(p.t, k), Certificate: chain})
	if err != nil {
		p.t.Fatal(err)
	}
	return s, c
}

func (p *pki) crl(revoked ...*x509.Certificate) []byte {
	p.t.Helper()
	var entries []x509.RevocationListEntry
	for _, c := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: c.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries,
	}, p.inter, p.intKey)
	if err != nil {
		p.t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

func signedRain(t *testing.T, s *cap.Signer) []byte {
	t.Helper()
	doc, err := rainAlert("MET-PUNE-0200", "Alert", "Severe", "", time.Now()).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := s.Sign(doc)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// A signature by a certificate that is not pinned is accepted when the
// certificate chains to a configured root, through an intermediate carried
// in KeyInfo or configured; the chain is returned. A chain to an unknown
// root, an expired signing certificate, a certificate whose key usage
// excludes signing, and a revoked certificate are refused.
//
// Covers: SIG-IPE-711
func TestCAPVerifyChain(t *testing.T) {
	p := newPKI(t)
	now := time.Now()
	s, leaf := p.signer("warnings.example.test", true, now.Add(-time.Hour), now.Add(24*time.Hour), x509.KeyUsageDigitalSignature)
	signed := signedRain(t, s)

	v, err := cap.NewVerifier(cap.VerifySettings{Roots: []string{p.rootPEM}, Require: true})
	if err != nil {
		t.Fatal(err)
	}
	out, state, chain, err := v.VerifyChain(signed)
	if err != nil || state != cap.SignatureValid {
		t.Fatalf("chain verify = %q, %v", state, err)
	}
	if len(chain) != 3 || !chain[0].Equal(leaf) || !chain[1].Equal(p.inter) || !chain[2].Equal(p.root) {
		t.Fatalf("chain = %d certificates", len(chain))
	}
	if a, err := cap.Parse(out); err != nil || a.Identifier != "MET-PUNE-0200" {
		t.Fatalf("verified alert = %v, %v", a, err)
	}
	if _, state, err := v.Verify(signed); err != nil || state != cap.SignatureValid {
		t.Errorf("Verify = %q, %v", state, err)
	}

	// The intermediate left out of KeyInfo: found in Intermediates, else refused.
	s2, _ := p.signer("warnings2.example.test", false, now.Add(-time.Hour), now.Add(24*time.Hour), 0)
	signed2 := signedRain(t, s2)
	if _, _, err := v.Verify(signed2); err == nil || !strings.Contains(err.Error(), "does not chain") {
		t.Errorf("no intermediate: %v", err)
	}
	vi, _ := cap.NewVerifier(cap.VerifySettings{Roots: []string{p.rootPEM}, Intermediates: []string{p.intPEM}})
	if _, state, err := vi.Verify(signed2); err != nil || state != cap.SignatureValid {
		t.Errorf("configured intermediate: %q, %v", state, err)
	}

	// Another root.
	other := newPKI(t)
	vo, _ := cap.NewVerifier(cap.VerifySettings{Roots: []string{other.rootPEM}})
	if _, _, err := vo.Verify(signed); err == nil {
		t.Error("a chain to an untrusted root verified")
	}
	// An intermediate is not a root.
	vx, _ := cap.NewVerifier(cap.VerifySettings{Roots: []string{other.rootPEM}, Intermediates: []string{p.intPEM}})
	if _, _, err := vx.Verify(signed); err == nil {
		t.Error("an intermediate was trusted as a root")
	}

	// Expired signing certificate.
	v.Now = func() time.Time { return now.Add(30 * time.Hour) }
	if _, _, err := v.Verify(signed); err == nil {
		t.Error("an expired certificate verified")
	}
	v.Now = nil

	// Key usage without digital signature.
	s3, _ := p.signer("encrypt-only.example.test", true, now.Add(-time.Hour), now.Add(24*time.Hour), x509.KeyUsageKeyEncipherment)
	if _, _, err := v.Verify(signedRain(t, s3)); err == nil || !strings.Contains(err.Error(), "key usage") {
		t.Errorf("key usage: %v", err)
	}

	// Extended key usage restriction.
	p.eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	s4, _ := p.signer("tls-only.example.test", true, now.Add(-time.Hour), now.Add(24*time.Hour), 0)
	p.eku = nil
	signed4 := signedRain(t, s4)
	ve, _ := cap.NewVerifier(cap.VerifySettings{Roots: []string{p.rootPEM}})
	if _, _, err := ve.Verify(signed4); err != nil {
		t.Errorf("any extended key usage: %v", err)
	}
	ve.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	if _, _, err := ve.Verify(signed4); err == nil {
		t.Error("a certificate without the required extended key usage verified")
	}

	// Revocation through a CRL of the issuing CA.
	crls, err := cap.ParseCRLs(p.crl(leaf))
	if err != nil || len(crls) != 1 {
		t.Fatalf("ParseCRLs = %d, %v", len(crls), err)
	}
	v.Revoked = cap.CRLCheck(crls...)
	if _, _, err := v.Verify(signed); !errors.Is(err, cap.ErrRevoked) {
		t.Errorf("revoked certificate: %v", err)
	}
	clean, _ := cap.ParseCRLs(p.crl())
	v.Revoked = cap.CRLCheck(clean...)
	if _, _, err := v.Verify(signed); err != nil {
		t.Errorf("CRL without the certificate: %v", err)
	}
	// A CRL signed by someone else is ignored.
	forged, _ := cap.ParseCRLs(other.crl(leaf))
	v.Revoked = cap.CRLCheck(forged...)
	if _, _, err := v.Verify(signed); err != nil {
		t.Errorf("a CRL of another CA revoked the certificate: %v", err)
	}
	if _, err := cap.ParseCRLs([]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")); err == nil {
		t.Error("ParseCRLs read a file without a CRL")
	}
	if _, err := cap.ParseCRLs([]byte{1, 2, 3}); err == nil {
		t.Error("ParseCRLs read garbage DER")
	}
}

// Pinned certificates keep working next to roots, and the revocation hook
// is asked about them as a chain of one.
//
// Covers: SIG-IPE-711
func TestCAPVerifyPinnedWithHook(t *testing.T) {
	key, cert := keyPair(t, "pinned.example.test", true)
	s, err := cap.NewSigner(cap.SignSettings{Key: key, Certificate: cert})
	if err != nil {
		t.Fatal(err)
	}
	signed := signedRain(t, s)
	p := newPKI(t)
	v, err := cap.NewVerifier(cap.VerifySettings{Trusted: []string{cert}, Roots: []string{p.rootPEM}})
	if err != nil {
		t.Fatal(err)
	}
	var asked int
	v.Revoked = func(chain []*x509.Certificate) error {
		asked++
		if len(chain) != 1 {
			t.Errorf("pinned chain of %d", len(chain))
		}
		return nil
	}
	if _, chain, err := verifyChain(v, signed); err != nil || len(chain) != 1 || asked != 1 {
		t.Fatalf("pinned = %d certificates, %v, asked %d", len(chain), err, asked)
	}
	v.Revoked = func([]*x509.Certificate) error { return errors.New("revoked by test") }
	if _, _, err := v.Verify(signed); err == nil || !strings.Contains(err.Error(), "revoked by test") {
		t.Errorf("hook refusal: %v", err)
	}
	if v.Roots() == nil {
		t.Error("Roots is nil")
	}
	// Settings errors name their list.
	var skipped []string
	cap.NewVerifierSkipping(cap.VerifySettings{Trusted: []string{cert}, Roots: []string{"nope"}, Intermediates: []string{"nope"}}, func(_ int, err error) {
		skipped = append(skipped, err.Error())
	})
	if len(skipped) != 2 || !strings.HasPrefix(skipped[0], "root certificate 0") || !strings.HasPrefix(skipped[1], "intermediate certificate 0") {
		t.Errorf("skipped %q", skipped)
	}
	if _, err := cap.NewVerifier(cap.VerifySettings{Roots: []string{p.rootPEM}}); err != nil {
		t.Errorf("roots only: %v", err)
	}
}

func verifyChain(v *cap.Verifier, doc []byte) (string, []*x509.Certificate, error) {
	_, state, chain, err := v.VerifyChain(doc)
	return state, chain, err
}
