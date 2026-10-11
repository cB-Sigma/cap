// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
)

// Check warns about resources whose derefUri is not base64, whose digest
// is not a SHA-1 hash or whose size is not a number, and about a ceiling
// below the altitude; Validate still accepts such an alert.
//
// Covers: SIG-IPE-380
func TestCheckWarnings(t *testing.T) {
	a := rainAlert("MET-PUNE-0310", "Alert", "Severe", "", time.Now())
	a.Info[0].Resource = []cap.Resource{{ResourceDesc: "map", MimeType: "image/png", Size: "12kB", DerefURI: "not base64!", Digest: "abc"}}
	a.Info[0].Area[0].Altitude, a.Info[0].Area[0].Ceiling = "500", "100"
	ps := a.Check(cap.Options{})
	for _, f := range []string{"info[0].resource[0].derefUri", "info[0].resource[0].digest", "info[0].resource[0].size", "info[0].area[0].ceiling"} {
		if !find(ps, "", f, "", true) {
			t.Errorf("no warning for %s:\n%s", f, dump(ps))
		}
	}
	if err := a.Validate(cap.Options{}); err != nil {
		t.Errorf("warnings failed Validate: %v", err)
	}
	a.Info[0].Resource[0] = cap.Resource{ResourceDesc: "map", MimeType: "image/png", Size: "12", DerefURI: "aGVsbG8=", Digest: strings.Repeat("ab", 20)}
	a.Info[0].Area[0].Ceiling = "900"
	if ps := a.Check(cap.Options{}); len(ps) != 0 {
		t.Errorf("good resource:\n%s", dump(ps))
	}
}

// ValidateSchema checks the document's structure against the CAP 1.2
// content model: our own output passes; elements out of order, repeated,
// unknown or missing, wrong simple types, attributes, stray text, CAP
// elements after the signature and other namespaces are reported, each
// problem marked with rule "XSD".
func TestValidateSchema(t *testing.T) {
	doc, err := rainAlert("MET-PUNE-0300", "Alert", "Severe", "", time.Now()).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := cap.ValidateSchema(doc); err != nil {
		t.Fatalf("our own alert fails the schema check: %v", err)
	}
	key, cert := keyPair(t, "schema.example.test", true)
	s, _ := cap.NewSigner(cap.SignSettings{Key: key, Certificate: cert})
	signed, err := s.Sign(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := cap.ValidateSchema(signed); err != nil {
		t.Fatalf("the signed alert fails the schema check: %v", err)
	}

	head := `<?xml version="1.0"?><alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">`
	base := `<identifier>X</identifier><sender>s@example.test</sender><sent>2026-09-24T10:00:00+05:30</sent><status>Actual</status><msgType>Alert</msgType><scope>Public</scope>`
	info := `<info><category>Met</category><event>Rain</event><urgency>Expected</urgency><severity>Minor</severity><certainty>Likely</certainty>%s</info>`
	for _, tc := range []struct {
		name, body, field, issue string
	}{
		{"order", `<sender>s@example.test</sender><identifier>X</identifier><sent>2026-09-24T10:00:00+05:30</sent><status>Actual</status><msgType>Alert</msgType><scope>Public</scope>`, "alert/identifier", "out of order"},
		{"twice", base + `<note>a</note><note>b</note>`, "alert/note", "only once"},
		{"missing", `<identifier>X</identifier><sender>s@example.test</sender><status>Actual</status><msgType>Alert</msgType><scope>Public</scope>`, "alert/sent", "required before status"},
		{"missing at end", `<identifier>X</identifier><sender>s@example.test</sender><sent>2026-09-24T10:00:00+05:30</sent><status>Actual</status><msgType>Alert</msgType>`, "alert/scope", "is required"},
		{"unknown", base + `<colour>red</colour>`, "alert/colour", "not an element of alert"},
		{"enum", strings.Replace(base, "Actual", "actual", 1), "alert/status", "not one of"},
		{"date", strings.Replace(base, "+05:30", "Z", 1), "alert/sent", "not a CAP date-time"},
		{"attribute", strings.Replace(base, "<note", "<note", 1) + `<note lang="en">a</note>`, "alert/note", `attribute "lang"`},
		{"nested", base + `<note><b>x</b></note>`, "alert/note", "text only"},
		{"stray text", base + `hello`, "alert", "text outside"},
		{"after signature", base + `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/><note>late</note>`, "alert/note", "comes after the signature"},
		{"foreign at end", base + `<x:Other xmlns:x="urn:example"/>`, "alert/Other", "not allowed here"},
		{"foreign after signature", base + `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/><x:Other xmlns:x="urn:example"/>`, "alert/Other", "not allowed here"},
		{"foreign in info", base + strings.Replace(info, "%s", `<x:Other xmlns:x="urn:example"/>`, 1), "alert/info[0]/Other", "not allowed here"},
		{"no category", base + `<info><event>Rain</event><urgency>Expected</urgency><severity>Minor</severity><certainty>Likely</certainty></info>`, "alert/info[0]/category", "required before event"},
		{"size", base + strings.Replace(info, "%s", `<resource><resourceDesc>map</resourceDesc><mimeType>image/png</mimeType><size>12kB</size></resource>`, 1), "alert/info[0]/resource[0]/size", "not an integer"},
		{"altitude", base + strings.Replace(info, "%s", `<area><areaDesc>A</areaDesc><altitude>high</altitude></area>`, 1), "alert/info[0]/area[0]/altitude", "not a decimal"},
		{"geocode pair", base + strings.Replace(info, "%s", `<area><areaDesc>A</areaDesc><geocode><value>1</value></geocode></area>`, 1), "alert/info[0]/area[0]/geocode[0]/valueName", "required before value"},
		{"language", base + `<info><language>en IN</language><category>Met</category><event>Rain</event><urgency>Expected</urgency><severity>Minor</severity><certainty>Likely</certainty></info>`, "alert/info[0]/language", "not a language tag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := cap.ValidateSchema([]byte(head + tc.body + `</alert>`))
			var ve cap.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("err = %v", err)
			}
			for _, p := range ve {
				if p.Field == tc.field && strings.Contains(p.Issue, tc.issue) && p.Rule == "XSD" {
					return
				}
			}
			t.Errorf("want %s: %s; got %v", tc.field, tc.issue, err)
		})
	}

	if a, err := cap.ParseStrict(doc); err != nil || a.Identifier != "MET-PUNE-0300" {
		t.Errorf("ParseStrict of a good document: %v", err)
	}
	if _, err := cap.ParseStrict([]byte(head + base + `<colour>red</colour></alert>`)); err == nil {
		t.Error("ParseStrict read a document with an unknown element")
	}

	// Other namespaces and roots are reported, not read as 1.2.
	if err := cap.ValidateSchema([]byte(`<alert xmlns="urn:oasis:names:tc:emergency:cap:1.1">` + base + `</alert>`)); err == nil || !strings.Contains(err.Error(), "not alert in") {
		t.Errorf("CAP 1.1: %v", err)
	}
	if err := cap.ValidateSchema([]byte(`<alert`)); err == nil || !strings.Contains(err.Error(), "well-formed") {
		t.Errorf("broken XML: %v", err)
	}

	// An extra validator's problems are added.
	extra := cap.SchemaValidatorFunc(func([]byte) error { return errors.New("xsd engine says no") })
	if err := cap.ValidateSchema(doc, extra); err == nil || !strings.Contains(err.Error(), "xsd engine says no") {
		t.Errorf("extra validator: %v", err)
	}
	listing := cap.SchemaValidatorFunc(func([]byte) error {
		return cap.ValidationError{{Field: "alert/x", Issue: "from the engine", Rule: "XSD"}}
	})
	var ve cap.ValidationError
	if err := cap.ValidateSchema(doc, listing); !errors.As(err, &ve) || len(ve) != 1 || ve[0].Field != "alert/x" {
		t.Errorf("listing validator: %v", err)
	}
}
