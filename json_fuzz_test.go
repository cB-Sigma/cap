// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
)

// JSON with CAP element names round-trips an alert, resources included.
func TestAlertJSON(t *testing.T) {
	a := rainAlert("MET-PUNE-0600", "Alert", "Severe", "", time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC))
	a.Info[0].Resource = []cap.Resource{{ResourceDesc: "map", MimeType: "image/png", Size: "1024", URI: "https://example.test/map.png"}}
	a.Version = "1.2"
	b, err := a.MarshalJSONCAP()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"identifier":"MET-PUNE-0600"`, `"msgType":"Alert"`, `"areaDesc":"Pune district"`, `"resourceDesc":"map"`, `"valueName":"LGD_District"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("JSON lacks %s:\n%s", k, b)
		}
	}
	back, err := cap.ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, back) {
		t.Errorf("round trip:\n%+v\n%+v", a, back)
	}
	if _, err := cap.ParseJSON([]byte(`{"x":1}`)); err == nil {
		t.Error("ParseJSON took JSON without a CAP alert")
	}
	if _, err := cap.ParseJSON([]byte(`[`)); err == nil {
		t.Error("ParseJSON took broken JSON")
	}
}

// The readers never panic on arbitrary input.
func FuzzReaders(f *testing.F) {
	doc, _ := rainAlert("MET-PUNE-0700", "Alert", "Severe", "", time.Now()).Marshal()
	f.Add(doc)
	f.Add([]byte(`<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>1</id><link href="x.xml"/></entry></feed>`))
	f.Add([]byte(`<EDXLDistribution xmlns="urn:oasis:names:tc:emergency:EDXL:DE:1.0"><distributionID>D</distributionID><contentObject><nonXMLContent><mimeType>application/cap+xml</mimeType><contentData>PGFsZXJ0Lz4=</contentData></nonXMLContent></contentObject></EDXLDistribution>`))
	f.Add([]byte(`<alert xmlns="urn:oasis:names:tc:emergency:cap:1.1"><identifier>a</identifier></alert>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if a, err := cap.Parse(b); err == nil {
			_ = a.Check(cap.Options{Profiles: []cap.Profile{cap.CAPCP(), cap.IPAWS(), cap.India()}})
			_ = a.GeoJSON()
			_ = cap.RepairIndia(a)
		}
		_, _ = cap.ParseFeed(b)
		_, _ = cap.ParseEDXLDE(b)
		_ = cap.ValidateSchema(b)
		_, _ = cap.ParseJSON(b)
	})
}
