// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
)

// keyPair makes a self-signed certificate and returns the PEM key and
// certificate.
func keyPair(t *testing.T, cn string, ec bool) (keyPEM, certPEM string) {
	t.Helper()
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
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A signed alert carries an enveloped XML signature in the XMLDSig
// namespace as the alert's last child; it verifies against the signer's
// certificate, and any change to the signed content, an untrusted
// certificate or a missing signature (where required) is refused.
//
// Covers: SIG-IPE-710
func TestCAPSignAndVerify(t *testing.T) {
	for _, ec := range []bool{false, true} {
		name := map[bool]string{false: "rsa", true: "ecdsa"}[ec]
		t.Run(name, func(t *testing.T) {
			key, cert := keyPair(t, "iccc.pune.test", ec)
			_, other := keyPair(t, "someone-else.test", ec)
			sg, err := cap.NewSigner(cap.SignSettings{Key: key, Certificate: cert})
			if err != nil {
				t.Fatal(err)
			}
			doc, err := rainAlert("MET-PUNE-0100", "Alert", "Severe", "", time.Now()).Marshal()
			if err != nil {
				t.Fatal(err)
			}
			signed, err := sg.Sign(doc)
			if err != nil {
				t.Fatal(err)
			}
			s := string(signed)
			if i, j := strings.LastIndex(s, "Signature xmlns"), strings.LastIndex(s, "</alert>"); i < 0 || j < i ||
				!strings.Contains(s, cap.XMLDSigNamespace) || !strings.Contains(s, "X509Certificate") {
				t.Fatalf("no enveloped signature at the end of the alert:\n%s", s)
			}
			if _, err := sg.Sign(signed); err == nil {
				t.Error("an already signed alert was signed again")
			}
			// Still a CAP alert to a reader that ignores signatures.
			if a, err := cap.Parse(signed); err != nil || a.Identifier != "MET-PUNE-0100" {
				t.Fatalf("signed document parse = %v, %v", a, err)
			}
			v, err := cap.NewVerifier(cap.VerifySettings{Trusted: []string{cert}, Require: true})
			if err != nil {
				t.Fatal(err)
			}
			out, state, err := v.Verify(signed)
			if err != nil || state != cap.SignatureValid {
				t.Fatalf("verify = %q, %v", state, err)
			}
			if a, err := cap.Parse(out); err != nil || a.Info[0].Headline != "Heavy rainfall likely in Pune district" {
				t.Fatalf("verified alert = %v, %v", a, err)
			}
			tampered := bytes.Replace(signed, []byte("Heavy rainfall likely"), []byte("No rainfall expected"), 1)
			if _, _, err := v.Verify(tampered); err == nil {
				t.Error("a tampered alert verified")
			}
			untrusted, err := cap.NewVerifier(cap.VerifySettings{Trusted: []string{other}})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := untrusted.Verify(signed); err == nil {
				t.Error("a signature by an untrusted certificate verified")
			}
			if _, _, err := v.Verify(doc); err != cap.ErrUnsigned {
				t.Errorf("unsigned with require = %v", err)
			}
			lax, _ := cap.NewVerifier(cap.VerifySettings{Trusted: []string{cert}})
			if _, state, err := lax.Verify(doc); err != nil || state != cap.SignatureNone {
				t.Errorf("unsigned without require = %q, %v", state, err)
			}
			// Expired certificate: verification at a time after NotAfter fails.
			v.Now = func() time.Time { return time.Now().Add(48 * time.Hour) }
			if _, _, err := v.Verify(signed); err == nil {
				t.Error("a signature verified outside its certificate's validity")
			}
		})
	}
	// Settings errors.
	key, cert := keyPair(t, "a.test", false)
	key2, _ := keyPair(t, "b.test", false)
	for _, tc := range []struct {
		s    cap.SignSettings
		want string
	}{
		{cap.SignSettings{Key: "nope", Certificate: cert}, "not a PEM private key"},
		{cap.SignSettings{Key: key, Certificate: ""}, "no PEM CERTIFICATE"},
		{cap.SignSettings{Key: key2, Certificate: cert}, "does not belong"},
	} {
		if _, err := cap.NewSigner(tc.s); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.want, err, tc.want)
		}
	}
	_ = key
	if _, err := cap.NewVerifier(cap.VerifySettings{}); err == nil {
		t.Error("a verifier without trusted certificates")
	}
}
