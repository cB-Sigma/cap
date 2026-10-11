// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop checks github.com/cB-Sigma/cap against github.com/tannerryan/cap
// (BSD-2-Clause), an independent CAP 1.2 implementation in Go: alerts we
// write validate there, alerts it writes validate here, our enveloped
// signatures (self-signed and chained to a root) verify there, and the two
// CAP-CP 1.0 checks agree on a complying and a failing alert.
package interop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
	theirs "github.com/tannerryan/cap"
)

func sample(now time.Time) *cap.Alert {
	return &cap.Alert{
		Identifier: "INTEROP-1", Sender: "interop@example.test", Sent: cap.FormatTime(now),
		Status: "Exercise", MsgType: "Alert", Scope: "Public",
		Info: []cap.Info{{
			Language: "en", Category: []string{"Met", "Safety"}, Event: "Heavy Rainfall",
			ResponseType: []string{"Prepare"}, Urgency: "Expected", Severity: "Severe", Certainty: "Likely",
			Expires:   cap.FormatTime(now.Add(24 * time.Hour)),
			Headline:  "Interop sample",
			Parameter: []cap.NamedValue{{ValueName: "source", Value: "interop"}},
			Area: []cap.Area{{
				AreaDesc: "Demo district",
				Polygon:  []string{"18.40,73.70 18.40,74.00 18.65,74.00 18.65,73.70 18.40,73.70"},
				Circle:   []string{"18.52,73.85 5"},
				Geocode:  []cap.NamedValue{{ValueName: "LGD_District", Value: "521"}},
			}},
		}},
	}
}

func TestOurAlertsValidateThere(t *testing.T) {
	doc, err := sample(time.Now()).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	a, err := theirs.ParseCAP(doc)
	if err != nil {
		t.Fatalf("tannerryan/cap cannot parse our alert: %v\n%s", err, doc)
	}
	if d := a.Validate(); d.HasErrors() {
		t.Fatalf("tannerryan/cap finds errors in our alert: %v", d.Err())
	}
}

func TestTheirAlertsValidateHere(t *testing.T) {
	doc, _ := sample(time.Now()).Marshal()
	a, err := theirs.ParseCAP(doc)
	if err != nil {
		t.Fatal(err)
	}
	out, err := theirs.MarshalCAP(a)
	if err != nil {
		t.Fatal(err)
	}
	ours, err := cap.Parse(out)
	if err != nil {
		t.Fatalf("our parser refuses tannerryan/cap's output: %v\n%s", err, out)
	}
	if err := ours.Validate(cap.Options{}); err != nil {
		t.Fatalf("our validation refuses tannerryan/cap's output: %v\n%s", err, out)
	}
	if ours.Identifier != "INTEROP-1" || len(ours.Info) != 1 || ours.Info[0].Area[0].Geocode[0].Value != "521" {
		t.Errorf("content lost: %+v", ours)
	}
}

// A CAP-CP 1.0 alert that complies here has no CAP-CP errors there, and an
// alert breaking rules 3, 5, 6 and 8 has errors in both.
func TestCAPCPAgrees(t *testing.T) {
	now := time.Now()
	block := func(lang string) cap.Info {
		return cap.Info{
			Language: lang, Category: []string{"Met"}, Event: "rainfall", ResponseType: []string{"Monitor"},
			Urgency: "Future", Severity: "Moderate", Certainty: "Likely", SenderName: "Demo office",
			EventCode: []cap.NamedValue{{ValueName: "profile:CAP-CP:Event:1.0", Value: "rainfall"}},
			Expires:   cap.FormatTime(now.Add(time.Hour)), Headline: "Rain " + lang,
			Area: []cap.Area{{AreaDesc: "Demo", Geocode: []cap.NamedValue{{ValueName: "profile:CAP-CP:Location:1.0", Value: "3506"}}}},
		}
	}
	good := &cap.Alert{Identifier: "CA-INTEROP-1", Sender: "interop.example.test", Sent: cap.FormatTime(now), Status: "Exercise",
		MsgType: "Alert", Scope: "Public", Code: []string{"profile:CAP-CP:1.0"}, Info: []cap.Info{block("en-CA"), block("fr-CA")}}
	bad := &cap.Alert{Identifier: "CA-INTEROP-2", Sender: "interop.example.test", Sent: cap.FormatTime(now), Status: "Exercise",
		MsgType: "Alert", Scope: "Public", Info: []cap.Info{block("")}}
	bad.Info[0].EventCode = nil
	bad.Info[0].Area = nil
	for _, tc := range []struct {
		a    *cap.Alert
		fail bool
	}{{good, false}, {bad, true}} {
		ours := tc.a.Validate(cap.Options{Profiles: []cap.Profile{cap.CAPCP()}})
		doc, _ := tc.a.Marshal()
		ta, err := theirs.ParseCAP(doc)
		if err != nil {
			t.Fatal(err)
		}
		d := ta.ValidateCAPCP()
		if (ours != nil) != tc.fail || d.HasErrors() != tc.fail {
			t.Errorf("%s: ours %v; theirs %v", tc.a.Identifier, ours, d.Err())
		}
	}
}

// An alert signed by a certificate issued by an intermediate CA (both in
// KeyInfo) verifies against the root here and there.
func TestChainSignaturesAgree(t *testing.T) {
	mk := func(cn string, ca bool, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, crypto.Signer) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if ca {
			tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign
		}
		if parent == nil {
			parent, parentKey = tmpl, k
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, k.Public(), parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, k
	}
	root, rootKey := mk("Interop Root", true, nil, nil)
	inter, interKey := mk("Interop Issuing", true, root, rootKey)
	leaf, leafKey := mk("interop-signer.example.test", false, inter, interKey)
	p := func(c *x509.Certificate) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	k, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	s, err := cap.NewSigner(cap.SignSettings{Key: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})), Certificate: p(leaf) + p(inter)})
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := sample(time.Now()).Marshal()
	signed, err := s.Sign(doc)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := theirs.VerifySignature(signed, theirs.SignatureOptions{Roots: roots}); err != nil {
		t.Errorf("tannerryan/cap does not verify our chained signature: %v", err)
	}
	v, err := cap.NewVerifier(cap.VerifySettings{Roots: []string{p(root)}, Require: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, state, err := v.Verify(signed); err != nil || state != cap.SignatureValid {
		t.Errorf("our chain verification: %q, %v", state, err)
	}
}

// The real-world alerts tannerryan/cap keeps in its testing directory
// (Environment Canada, the NAADS aggregator, the US National Weather
// Service, OASIS examples) parse here, pass the schema check, and have no
// profile errors under the profiles they declare (warnings are allowed).
func TestTheirSampleAlerts(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/tannerryan/cap").Output()
	if err != nil {
		t.Skipf("module directory not found: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(strings.TrimSpace(string(out)), "testing", "*.xml"))
	if len(files) < 20 {
		t.Fatalf("only %d sample alerts found", len(files))
	}
	profiled := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		a, err := cap.Parse(b)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
			continue
		}
		if err := cap.ValidateSchema(b); err != nil {
			t.Errorf("%s: schema: %v", filepath.Base(f), err)
		}
		ps := cap.DetectProfiles(a)
		if len(ps) > 0 {
			profiled++
		}
		if err := a.Validate(cap.Options{Profiles: ps}); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
	}
	if profiled < 20 {
		t.Errorf("only %d alerts declared CAP-CP or IPAWS", profiled)
	}
}

func TestOurSignaturesVerifyThere(t *testing.T) {
	for _, ec := range []bool{false, true} {
		var key crypto.Signer
		var err error
		if ec {
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		} else {
			key, err = rsa.GenerateKey(rand.Reader, 2048)
		}
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "interop.example.test"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		k, _ := x509.MarshalPKCS8PrivateKey(key)
		s, err := cap.NewSigner(cap.SignSettings{
			Key:         string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})),
			Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		})
		if err != nil {
			t.Fatal(err)
		}
		doc, _ := sample(time.Now()).Marshal()
		signed, err := s.Sign(doc)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		if _, err := theirs.VerifySignature(signed, theirs.SignatureOptions{Roots: roots}); err != nil {
			t.Errorf("ecdsa=%v: tannerryan/cap does not verify our signature: %v", ec, err)
		}
	}
}
