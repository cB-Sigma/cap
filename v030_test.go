// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
)

// Covers: SIG-IPE-7326
//
// Base validation problems name the CAP 1.2 clause of their element, and
// circles can be drawn with any number of sides.
func TestClausesAndCircleSides(t *testing.T) {
	a := &cap.Alert{Identifier: "C-1", Sender: "s@example.test", Sent: "2026-10-12T00:00:00+05:30",
		Status: "Actual", MsgType: "Alert", Scope: "Restricted",
		Info: []cap.Info{{Category: []string{"Met"}, Event: "Rain", Urgency: "Soon", Severity: "Minor", Certainty: "Likely",
			Resource: []cap.Resource{{}},
			Area:     []cap.Area{{AreaDesc: "A", Circle: []string{"18.5,73.8 5"}, Ceiling: "10"}}}}}
	var ve cap.ValidationError
	if err := a.Validate(cap.Options{}); !errors.As(err, &ve) {
		t.Fatal(err)
	}
	want := map[string]string{"restriction": "CAP 1.2 3.2.1", "info[0].urgency": "CAP 1.2 3.2.2",
		"info[0].resource[0]": "CAP 1.2 3.2.3", "info[0].area[0].ceiling": "CAP 1.2 3.2.4"}
	for _, p := range ve {
		if w, ok := want[p.Field]; ok {
			if p.Rule != w {
				t.Errorf("%s: rule %q, want %q", p.Field, p.Rule, w)
			}
			delete(want, p.Field)
		}
	}
	if len(want) > 0 {
		t.Errorf("problems not found: %v (got %v)", want, ve)
	}
	if ring := cap.CirclePolygonN([]float64{73.8, 18.5}, 5, 90); len(ring) != 91 || ring[0][0] != ring[90][0] {
		t.Fatalf("ring of %d points", len(ring))
	}
	g := a.GeoJSONWith(8)
	f := g["features"].([]any)[0].(map[string]any)
	if n := len(f["geometry"].(map[string]any)["coordinates"].([][][]float64)[0]); n != 9 {
		t.Fatalf("8-sided circle has %d points", n)
	}
}

// Covers: SIG-IPE-7328
//
// ECDSA signatures are written as r||s by default (XML Signature), as ASN.1
// on request, and both verify here; RSA is unaffected.
func TestECDSAEncodings(t *testing.T) {
	key, certPEM := keyPair(t, "enc.example.test", true)
	v, err := cap.NewVerifier(cap.VerifySettings{Trusted: []string{certPEM}, Require: true})
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := rainAlert("ENC-1", "Alert", "Minor", "", time.Now()).Marshal()
	for _, enc := range []string{"", "raw", "der"} {
		s, err := cap.NewSigner(cap.SignSettings{Key: key, Certificate: certPEM, ECDSAEncoding: enc})
		if err != nil {
			t.Fatal(err)
		}
		signed, err := s.Sign(doc)
		if err != nil {
			t.Fatal(err)
		}
		val := string(signed[strings.Index(string(signed), "SignatureValue>")+15:])
		val = val[:strings.Index(val, "<")]
		raw, _ := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(val), ""))
		if (enc == "der") != (len(raw) != 64) {
			t.Fatalf("encoding %q: a %d-byte signature value", enc, len(raw))
		}
		if _, state, err := v.Verify(signed); err != nil || state != cap.SignatureValid {
			t.Fatalf("encoding %q: %v", enc, err)
		}
	}
	if _, err := cap.NewSigner(cap.SignSettings{Key: key, Certificate: certPEM, ECDSAEncoding: "hex"}); err == nil {
		t.Fatal("an unknown encoding was accepted")
	}
}
