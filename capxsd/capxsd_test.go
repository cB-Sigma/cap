// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package capxsd_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
	"github.com/cB-Sigma/cap/capxsd"
)

const (
	head = `<?xml version="1.0"?><alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">`
	base = `<identifier>X</identifier><sender>s@example.test</sender><sent>2026-09-24T10:00:00+05:30</sent><status>Actual</status><msgType>Alert</msgType><scope>Public</scope>`
	info = `<info><category>Met</category><event>Rain</event><urgency>Expected</urgency><severity>Minor</severity><certainty>Likely</certainty>%s</info>`
)

// Covers: SIG-IPE-7320
//
// The embedded file is OASIS's, byte for byte.
func TestSchemaIsOASISFile(t *testing.T) {
	b, err := os.ReadFile(capxsd.SchemaFile)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != capxsd.SchemaSHA256 {
		t.Fatal("CAP-v1.2.xsd differs from the OASIS file")
	}
	if !strings.Contains(string(b), "Copyright OASIS Open 2010") {
		t.Fatal("the OASIS notice is missing")
	}
}

// Covers: SIG-IPE-7320
//
// Every document the content-model check refuses, the OASIS schema
// refuses too, and good documents (a signed one included) pass both: the
// two checks agree, case by case.
func TestAgreesWithContentModel(t *testing.T) {
	v, err := capxsd.Validator()
	if err != nil {
		t.Fatal(err)
	}
	good := []string{
		head + base + `</alert>`,
		head + base + strings.Replace(info, "%s", `<area><areaDesc>A</areaDesc><polygon>1,1 1,2 2,2 1,1</polygon><circle>1,1 5</circle><geocode><valueName>FIPS6</valueName><value>1</value></geocode><altitude>10</altitude><ceiling>20</ceiling></area>`, 1) + `</alert>`,
		head + base + `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/></ds:Signature></alert>`,
	}
	for _, d := range good {
		if err := cap.ValidateSchema([]byte(d)); err != nil {
			t.Fatalf("content model refuses a good document: %v", err)
		}
		if err := v.ValidateSchema([]byte(d)); err != nil {
			t.Fatalf("OASIS schema refuses a good document: %v\n%s", err, d)
		}
	}
	bad := map[string]string{
		"order":           `<sender>s@example.test</sender><identifier>X</identifier><sent>2026-09-24T10:00:00+05:30</sent><status>Actual</status><msgType>Alert</msgType><scope>Public</scope>`,
		"twice":           base + `<note>a</note><note>b</note>`,
		"missing":         `<identifier>X</identifier><sender>s@example.test</sender><status>Actual</status><msgType>Alert</msgType><scope>Public</scope>`,
		"missing at end":  `<identifier>X</identifier><sender>s@example.test</sender><sent>2026-09-24T10:00:00+05:30</sent><status>Actual</status><msgType>Alert</msgType>`,
		"unknown":         base + `<colour>red</colour>`,
		"enum":            strings.Replace(base, "Actual", "actual", 1),
		"date Z":          strings.Replace(base, "+05:30", "Z", 1),
		"date fraction":   strings.Replace(base, "10:00:00+05:30", "10:00:00.5+05:30", 1),
		"attribute":       base + `<note lang="en">a</note>`,
		"nested":          base + `<note><b>x</b></note>`,
		"foreign at end":  base + `<x:Other xmlns:x="urn:example"/>`,
		"after signature": base + `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/><note>late</note>`,
		"no category":     base + `<info><event>Rain</event><urgency>Expected</urgency><severity>Minor</severity><certainty>Likely</certainty></info>`,
		"size":            base + strings.Replace(info, "%s", `<resource><resourceDesc>map</resourceDesc><mimeType>image/png</mimeType><size>12kB</size></resource>`, 1),
		"altitude":        base + strings.Replace(info, "%s", `<area><areaDesc>A</areaDesc><altitude>high</altitude></area>`, 1),
		"geocode pair":    base + strings.Replace(info, "%s", `<area><areaDesc>A</areaDesc><geocode><value>1</value></geocode></area>`, 1),
		"severity":        base + strings.Replace(strings.Replace(info, "Minor", "Bad", 1), "%s", "", 1),
	}
	for name, body := range bad {
		d := []byte(head + body + `</alert>`)
		if cap.ValidateSchema(d) == nil {
			t.Errorf("%s: the content model accepts it", name)
		}
		err := v.ValidateSchema(d)
		var ve cap.ValidationError
		if !errors.As(err, &ve) || len(ve) == 0 || !strings.HasPrefix(ve[0].Rule, "XSD (CAP-v1.2.xsd)") {
			t.Errorf("%s: OASIS schema: %v", name, err)
		}
	}
	// Through cap.ValidateSchema and ParseStrict, as an extra validator.
	if _, err := cap.ParseStrict([]byte(good[1]), v); err != nil {
		t.Fatal(err)
	}
}

// Covers: SIG-IPE-7320
//
// An alert signed by this module passes the OASIS schema.
func TestSignedAlert(t *testing.T) {
	a := &cap.Alert{Identifier: "SIG-1", Sender: "s@example.test", Sent: "2026-10-12T00:00:00+05:30",
		Status: "Actual", MsgType: "Alert", Scope: "Public",
		Info: []cap.Info{{Category: []string{"Met"}, Event: "Heat", Urgency: "Expected", Severity: "Moderate", Certainty: "Likely"}}}
	doc, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "capxsd.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	s, err := cap.NewSigner(cap.SignSettings{Key: keyPEM, Certificate: certPEM})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := s.Sign(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := capxsd.Validate(signed); err != nil {
		t.Fatalf("%v\n%s", err, signed)
	}
}
