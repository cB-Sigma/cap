// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cB-Sigma/cap"
	"github.com/cB-Sigma/cap/capxsd"
)

// validatorImage is xmlschema 3.4.3 (MIT), built from ./xmlschema.
const validatorImage = "sigma-cap-interop:xmlschema-3.4.3"

var buildValidator sync.Once

// xmlschemaValidate checks doc against a schema of testdata with
// xmlschema in Docker; the test is skipped unless SIGMA_CAP_INTEROP=1.
func xmlschemaValidate(t *testing.T, schema string, doc []byte) string {
	t.Helper()
	if os.Getenv("SIGMA_CAP_INTEROP") != "1" {
		t.Skip("set SIGMA_CAP_INTEROP=1 to run the Docker interop tests")
	}
	var err error
	var out []byte
	buildValidator.Do(func() {
		out, err = exec.Command("docker", "build", "-q", "-t", validatorImage, "xmlschema").CombinedOutput()
	})
	if err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	abs, _ := filepath.Abs("testdata")
	capDir, _ := filepath.Abs("../capxsd")
	cmd := exec.Command("docker", "run", "--rm", "-i", "--network", "none", "-v", abs+":/schemas:ro", "-v", capDir+":/cap:ro", validatorImage, "/schemas/"+schema)
	cmd.Stdin = bytes.NewReader(doc)
	res, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("xmlschema: %v\n%s", err, res)
	}
	return strings.TrimSpace(string(res))
}

// edxl2Envelope writes an EDXL-DE 2.0 envelope with an embedded, a base64
// and a linked alert.
func edxl2Envelope(t *testing.T) ([]byte, []byte) {
	t.Helper()
	a := &cap.Alert{Identifier: "EDXL-1", Sender: "s@example.test", Sent: "2026-10-12T00:00:00+05:30",
		Status: "Actual", MsgType: "Alert", Scope: "Public",
		Info: []cap.Info{{Category: []string{"Met"}, Event: "Heat", Urgency: "Expected", Severity: "Moderate", Certainty: "Likely",
			Expires: "2026-10-13T00:00:00+05:30"}}}
	doc, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	d := cap.Distribution{ID: "D-1", SenderID: "sender@example.test", Sent: "2026-10-12T00:00:01+05:30",
		Status: "Actual", Type: "Report", Confidentiality: "Unclassified"}
	out, err := cap.WriteEDXLDE2(d,
		cap.EDXLContent{Doc: doc, Description: "heat alert", Language: "en"},
		cap.EDXLContent{Doc: doc, Base64: true},
		cap.EDXLContent{Link: "https://alerts.example.test/EDXL-1.xml", Size: 900})
	if err != nil {
		t.Fatal(err)
	}
	return out, doc
}

// Covers: SIG-IPE-7321
//
// WriteEDXLDE2 envelopes read back with ParseEDXLDE; required fields and
// 2.0's confidentiality values are enforced; the OASIS CS02 example that
// carries an alert parses.
func TestEDXLDE2RoundTrip(t *testing.T) {
	out, doc := edxl2Envelope(t)
	back, err := cap.ParseEDXLDE(out)
	if err != nil {
		t.Fatal(err)
	}
	if back.Version != "2.0" || back.Expires != "2026-10-13T00:00:00+05:30" || back.Type != "Report" || back.Confidentiality != "Unclassified" || len(back.Entries) != 3 {
		t.Fatalf("read back %+v", back)
	}
	if !bytes.Equal(back.Entries[0].Raw, bytes.TrimSpace(doc[bytes.Index(doc, []byte("?>"))+2:])) || back.Entries[1].Alert == nil || back.Entries[2].Link == "" {
		t.Fatalf("entries %+v", back.Entries)
	}
	if err := capxsd.Validate(back.Entries[0].Raw); err != nil {
		t.Fatalf("the embedded alert: %v", err)
	}
	if _, err := cap.WriteEDXLDE2(cap.Distribution{ID: "x"}, cap.EDXLContent{Doc: doc}); err == nil {
		t.Fatal("an envelope without its required fields was written")
	}
	if _, err := cap.WriteEDXLDE2(cap.Distribution{ID: "D", SenderID: "s", Sent: "2026-10-12T00:00:01+05:30", Status: "Actual", Type: "Report",
		Confidentiality: "UNCLASSIFIED AND NOT SENSITIVE"}, cap.EDXLContent{Doc: doc}); err == nil {
		t.Fatal("a 1.0 confidentiality value was written in 2.0")
	}
	ex, err := os.ReadFile("testdata/DE_2.0_Example_Appendix_B2_9.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cap.ParseEDXLDE(ex); err != nil {
		t.Fatalf("the OASIS example: %v", err)
	}
}

// Covers: SIG-IPE-7321
//
// The OASIS EDXL-DE 2.0 schema set (CS02, in testdata unmodified, with the
// W3C xml.xsd it imports) accepts our envelope, checked by xmlschema in
// Docker. github.com/cB-Sigma/xsd v0.3.0 cannot load that set yet (it
// refuses the GML length types that extend a simple-content type with
// complex content, and the xlink namespace imported from two files).
func TestEDXLDE2AgainstOASISSchema(t *testing.T) {
	out, _ := edxl2Envelope(t)
	if got := xmlschemaValidate(t, "edxl-de-v2.0-cs02/edxl-de-v2.0-wd11.xsd", out); got != "valid" {
		t.Fatalf("the EDXL-DE 2.0 schema refuses our envelope:\n%s\n%s", got, out)
	}
	// The validator does refuse: the same envelope without dateTimeExpires.
	broken := bytes.Replace(out, []byte("<dateTimeExpires>2026-10-13T00:00:00+05:30</dateTimeExpires>"), nil, 1)
	if got := xmlschemaValidate(t, "edxl-de-v2.0-cs02/edxl-de-v2.0-wd11.xsd", broken); got == "valid" {
		t.Fatal("xmlschema accepted an envelope without dateTimeExpires")
	}
}
