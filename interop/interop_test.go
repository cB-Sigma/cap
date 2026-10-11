// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop checks github.com/cB-Sigma/cap against github.com/tannerryan/cap
// (BSD-2-Clause), an independent CAP 1.2 implementation in Go: alerts we
// write validate there, alerts it writes validate here, and our enveloped
// signatures verify there.
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
