// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
)

func stripHeader(b []byte) string {
	s := string(b)
	if i := strings.Index(s, "?>"); strings.HasPrefix(s, "<?xml") && i >= 0 {
		s = s[i+2:]
	}
	return strings.TrimSpace(s)
}

// EDXL-DE 1.0 and 2.0 envelopes are read: the routing facts, alerts
// embedded as XML (own or inherited namespace, CAP 1.2 or 1.1), alerts in
// base64 non-XML content, alerts given by URI; other content is skipped,
// and an embedded signed alert still verifies from Entry.Raw. ParseFeed
// takes an envelope as well.
func TestParseEDXLDE(t *testing.T) {
	sent := time.Date(2026, 9, 24, 10, 0, 0, 0, time.FixedZone("IST", 19800))
	doc12, _ := rainAlert("MET-PUNE-0400", "Alert", "Severe", "", sent).Marshal()
	key, cert := keyPair(t, "edxl.example.test", false)
	sg, _ := cap.NewSigner(cap.SignSettings{Key: key, Certificate: cert})
	signed, err := sg.Sign(doc12)
	if err != nil {
		t.Fatal(err)
	}
	cap11 := `<alert xmlns="urn:oasis:names:tc:emergency:cap:1.1"><identifier>OLD-1</identifier><sender>s@example.test</sender><sent>2026-09-24T10:00:00+05:30</sent><status>Actual</status><msgType>Alert</msgType><scope>Public</scope></alert>`
	env := `<?xml version="1.0" encoding="UTF-8"?>
<EDXLDistribution xmlns="urn:oasis:names:tc:emergency:EDXL:DE:1.0" xmlns:c="urn:oasis:names:tc:emergency:cap:1.2">
  <distributionID>DIST-77</distributionID>
  <senderID>hub@example.test</senderID>
  <dateTimeSent>2026-09-24T10:01:00+05:30</dateTimeSent>
  <distributionStatus>Actual</distributionStatus>
  <distributionType>Report</distributionType>
  <combinedConfidentiality>UNCLASSIFIED AND NOT SENSITIVE</combinedConfidentiality>
  <contentObject>
    <contentDescription>signed alert</contentDescription>
    <xmlContent><embeddedXMLContent>` + stripHeader(signed) + `</embeddedXMLContent></xmlContent>
  </contentObject>
  <contentObject>
    <xmlContent><embeddedXMLContent><c:alert><c:identifier>PFX-1</c:identifier><c:sender>s@example.test</c:sender><c:sent>2026-09-24T10:00:00+05:30</c:sent><c:status>Actual</c:status><c:msgType>Alert</c:msgType><c:scope>Public</c:scope></c:alert></embeddedXMLContent></xmlContent>
  </contentObject>
  <contentObject>
    <nonXMLContent><mimeType>application/cap+xml</mimeType><contentData>` + base64.StdEncoding.EncodeToString([]byte(cap11)) + `</contentData></nonXMLContent>
  </contentObject>
  <contentObject>
    <nonXMLContent><mimeType>application/cap+xml</mimeType><uri>https://alerts.example.test/cap/42.xml</uri></nonXMLContent>
  </contentObject>
  <contentObject>
    <nonXMLContent><mimeType>image/png</mimeType><uri>https://alerts.example.test/map.png</uri></nonXMLContent>
  </contentObject>
  <contentObject>
    <xmlContent><embeddedXMLContent><report xmlns="urn:example:other"><x>1</x></report></embeddedXMLContent></xmlContent>
  </contentObject>
</EDXLDistribution>`
	d, err := cap.ParseEDXLDE([]byte(env))
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != "1.0" || d.ID != "DIST-77" || d.SenderID != "hub@example.test" || d.Sent != "2026-09-24T10:01:00+05:30" || d.Status != "Actual" || d.Type != "Report" {
		t.Errorf("routing = %+v", d)
	}
	if len(d.Entries) != 4 {
		t.Fatalf("entries = %d, want 4", len(d.Entries))
	}
	e := d.Entries
	if e[0].Alert == nil || e[0].Alert.Identifier != "MET-PUNE-0400" || e[0].ID != "DIST-77#1" || e[0].Updated != d.Sent {
		t.Errorf("entry 0 = %+v", e[0])
	}
	v, _ := cap.NewVerifier(cap.VerifySettings{Trusted: []string{cert}, Require: true})
	if _, state, err := v.Verify(e[0].Raw); err != nil || state != cap.SignatureValid {
		t.Errorf("embedded signed alert: %q, %v", state, err)
	}
	if e[1].Alert == nil || e[1].Alert.Identifier != "PFX-1" {
		t.Errorf("prefixed alert = %+v", e[1].Alert)
	}
	if e[2].Alert == nil || e[2].Alert.Identifier != "OLD-1" || e[2].Alert.Version != "1.1" || !bytes.Equal(e[2].Raw, []byte(cap11)) {
		t.Errorf("base64 alert = %+v", e[2].Alert)
	}
	if e[3].Alert != nil || e[3].Link != "https://alerts.example.test/cap/42.xml" || e[3].ID != "DIST-77#4" {
		t.Errorf("linked alert = %+v", e[3])
	}

	entries, err := cap.ParseFeed([]byte(env))
	if err != nil || len(entries) != 4 {
		t.Fatalf("ParseFeed = %d, %v", len(entries), err)
	}

	v2 := `<edxlDistribution xmlns="urn:oasis:names:tc:emergency:EDXL:DE:2.0"><distributionID>D2</distributionID><senderID>x@example.test</senderID><dateTimeSent>2026-09-24T10:01:00+05:30</dateTimeSent><dateTimeExpires>2026-09-25T10:01:00+05:30</dateTimeExpires><distributionStatus>Exercise</distributionStatus><distributionKind>Report</distributionKind>` +
		`<content><contentObject><contentDescriptor><contentDescription>rain</contentDescription></contentDescriptor><contentXML><embeddedXMLContent>` + stripHeader(doc12) + `</embeddedXMLContent></contentXML></contentObject>` +
		`<contentObject><otherContent><mimeType>application/cap+xml</mimeType><uri>https://alerts.example.test/cap/43.xml</uri></otherContent></contentObject></content></edxlDistribution>`
	d2, err := cap.ParseEDXLDE([]byte(v2))
	if err != nil || d2.Version != "2.0" || d2.Status != "Exercise" || d2.Type != "Report" || len(d2.Entries) != 2 ||
		d2.Entries[0].Alert.Identifier != "MET-PUNE-0400" || d2.Entries[1].Link != "https://alerts.example.test/cap/43.xml" {
		t.Fatalf("EDXL-DE 2.0 = %+v, %v", d2, err)
	}

	for _, bad := range []string{`<feed xmlns="http://www.w3.org/2005/Atom"/>`, `<EDXLDistribution>`, ``} {
		if _, err := cap.ParseEDXLDE([]byte(bad)); err == nil {
			t.Errorf("%q read as EDXL-DE", bad)
		}
	}
	// Written and read back; the embedded signature still verifies.
	out, err := cap.WriteEDXLDE(cap.Distribution{ID: "OUT-1", SenderID: "hub@example.test", Sent: "2026-09-24T10:02:00+05:30", Status: "Exercise", Type: "Report"}, signed, doc12)
	if err != nil {
		t.Fatal(err)
	}
	back, err := cap.ParseEDXLDE(out)
	if err != nil || back.ID != "OUT-1" || back.Confidentiality != "UNCLASSIFIED AND NOT SENSITIVE" || len(back.Entries) != 2 {
		t.Fatalf("written envelope = %+v, %v\n%s", back, err, out)
	}
	if _, state, err := v.Verify(back.Entries[0].Raw); err != nil || state != cap.SignatureValid {
		t.Errorf("signature after writing: %q, %v", state, err)
	}
	if _, err := cap.WriteEDXLDE(cap.Distribution{ID: "X"}, doc12); err == nil || !strings.Contains(err.Error(), "senderID is required") {
		t.Errorf("missing senderID: %v", err)
	}
	if _, err := cap.WriteEDXLDE(cap.Distribution{ID: "X", SenderID: "a", Sent: "b", Status: "Test", Type: "Report"}, []byte("<feed/>")); err == nil {
		t.Error("a document that is not CAP was embedded")
	}

	broken := strings.Replace(env, base64.StdEncoding.EncodeToString([]byte(cap11)), "!!!", 1)
	if _, err := cap.ParseEDXLDE([]byte(broken)); err == nil || !strings.Contains(err.Error(), "base64") {
		t.Errorf("bad base64: %v", err)
	}
}
