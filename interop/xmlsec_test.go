// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

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
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
)

const xmlsecImage = "sigma-cap-interop:xmlsec1-alpine3.20"

var buildXmlsec sync.Once

// xmlsec runs xmlsec1 in Docker on files in dir (mounted at /work).
func xmlsec(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	if os.Getenv("SIGMA_CAP_INTEROP") != "1" {
		t.Skip("set SIGMA_CAP_INTEROP=1 to run the Docker interop tests")
	}
	var berr error
	var bout []byte
	buildXmlsec.Do(func() {
		bout, berr = exec.Command("docker", "build", "-q", "-t", xmlsecImage, "xmlsec").CombinedOutput()
	})
	if berr != nil {
		t.Fatalf("docker build: %v\n%s", berr, bout)
	}
	full := append([]string{"run", "--rm", "--network", "none", "-v", dir + ":/work", xmlsecImage}, args...)
	out, err := exec.Command("docker", full...).CombinedOutput()
	return string(out), err
}

func selfSigned(t *testing.T, ec bool) (keyPEM, certPEM string) {
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
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "xmlsec.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// Covers: SIG-IPE-7328
//
// Our RSA and ECDSA signatures verify in xmlsec1, and alerts xmlsec1 signs
// from a template (exclusive C14N, SHA-256, enveloped) verify here; a
// changed alert fails in both.
func TestSignaturesAgainstXmlsec1(t *testing.T) {
	for _, ec := range []bool{false, true} {
		dir := t.TempDir()
		keyPEM, certPEM := selfSigned(t, ec)
		s, err := cap.NewSigner(cap.SignSettings{Key: keyPEM, Certificate: certPEM})
		if err != nil {
			t.Fatal(err)
		}
		doc, _ := sample(time.Now()).Marshal()
		signed, err := s.Sign(doc)
		if err != nil {
			t.Fatal(err)
		}
		write := func(name, data string) {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		write("cert.pem", certPEM)
		write("key.pem", keyPEM)
		write("ours.xml", string(signed))
		if out, err := xmlsec(t, dir, "--verify", "--trusted-pem", "/work/cert.pem", "/work/ours.xml"); err != nil || !strings.Contains(out, "OK") {
			t.Fatalf("ec %v: xmlsec1 does not verify our signature: %v\n%s", ec, err, out)
		}
		write("tampered.xml", strings.Replace(string(signed), "<scope>Public</scope>", "<scope>Private</scope>", 1))
		if out, err := xmlsec(t, dir, "--verify", "--trusted-pem", "/work/cert.pem", "/work/tampered.xml"); err == nil {
			t.Fatalf("ec %v: xmlsec1 verified a changed alert:\n%s", ec, out)
		}

		// xmlsec1 signs a template; we verify against the pinned certificate.
		alg := "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
		if ec {
			alg = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
		}
		body := strings.TrimSpace(string(doc[strings.Index(string(doc), "?>")+2:]))
		tmpl := strings.Replace(body, "</alert>", `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>`+
			`<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="`+alg+`"/>`+
			`<Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>`+
			`<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>`+
			`<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue/></Reference></SignedInfo>`+
			`<SignatureValue/><KeyInfo><X509Data/></KeyInfo></Signature></alert>`, 1)
		write("tmpl.xml", tmpl)
		if out, err := xmlsec(t, dir, "--sign", "--lax-key-search", "--privkey-pem", "/work/key.pem,/work/cert.pem", "--output", "/work/theirs.xml", "/work/tmpl.xml"); err != nil {
			t.Fatalf("ec %v: xmlsec1 --sign: %v\n%s", ec, err, out)
		}
		theirs, err := os.ReadFile(filepath.Join(dir, "theirs.xml"))
		if err != nil {
			t.Fatal(err)
		}
		v, err := cap.NewVerifier(cap.VerifySettings{Trusted: []string{certPEM}, Require: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, state, err := v.Verify(theirs); err != nil || state != cap.SignatureValid {
			t.Fatalf("ec %v: we do not verify xmlsec1's signature: %q %v\n%s", ec, state, err, theirs)
		}
		if _, _, err := v.Verify([]byte(strings.Replace(string(theirs), "<scope>Public</scope>", "<scope>Private</scope>", 1))); err == nil {
			t.Fatalf("ec %v: we verified a changed alert signed by xmlsec1", ec)
		}
	}
}
