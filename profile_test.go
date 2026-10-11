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

// find reports whether ps holds a problem of the profile on the field
// whose issue contains the text, as an error (warning false) or warning.
func find(ps []cap.Problem, profile, field, text string, warning bool) bool {
	for _, p := range ps {
		if p.Profile == profile && p.Field == field && strings.Contains(p.Issue, text) && p.Warning == warning {
			return true
		}
	}
	return false
}

func dump(ps []cap.Problem) string {
	var s []string
	for _, p := range ps {
		s = append(s, p.String())
	}
	return strings.Join(s, "\n")
}

// canadian returns a CAP-CP alert of the given version with an English and
// a French block that comply.
func canadian(ver string) *cap.Alert {
	block := func(lang, headline string) cap.Info {
		return cap.Info{
			Language: lang, Category: []string{"Met"}, Event: "rainfall", ResponseType: []string{"Monitor"},
			Urgency: "Future", Severity: "Moderate", Certainty: "Likely",
			EventCode: []cap.NamedValue{{ValueName: "profile:CAP-CP:Event:" + map[string]string{"0.4": "0.4", "1.0": "1.0"}[ver], Value: "rainfall"}},
			Expires:   "2026-09-25T10:00:00-04:00", SenderName: "Demo Weather Office", Headline: headline,
			Area: []cap.Area{{AreaDesc: "Demo County", Geocode: []cap.NamedValue{{ValueName: "profile:CAP-CP:Location:0.3", Value: "3506"}}}},
		}
	}
	return &cap.Alert{
		Identifier: "CA-DEMO-1", Sender: "alerts.example.test", Sent: "2026-09-24T10:00:00-04:00", Status: "Actual",
		MsgType: "Alert", Scope: "Public", Code: []string{"profile:CAP-CP:" + ver},
		Info: []cap.Info{block("en-CA", "Rainfall warning"), block("fr-CA", "Avertissement de pluie")},
	}
}

// CAP-CP 0.4 and 1.0: a complying alert has no problem; each rule is
// reported with its version and number, recommendations as warnings.
func TestProfileCAPCP(t *testing.T) {
	for _, ver := range []string{"0.4", "1.0"} {
		t.Run(ver, func(t *testing.T) {
			a := canadian(ver)
			if ps := a.Check(cap.Options{Profiles: []cap.Profile{cap.CAPCP()}}); len(ps) != 0 {
				t.Fatalf("complying alert:\n%s", dump(ps))
			}
			if got := cap.DetectProfiles(a); len(got) != 1 || got[0].Name() != "CAP-CP" {
				t.Errorf("DetectProfiles = %v", got)
			}

			b := canadian(ver)
			b.Code = nil
			b.MsgType = "Update"
			b.Info[0].Language = ""
			b.Info[1].Language = "fr-FR"
			b.Info[0].EventCode = nil
			b.Info[1].EventCode[0].Value = "not listed"
			b.Info[1].SenderName = ""
			b.Info[1].Instruction = "Stay indoors."
			b.Info[1].ResponseType = nil
			b.Info[1].Area[0].Geocode[0].Value = "Ontario"
			b.Info[1].Parameter = []cap.NamedValue{{ValueName: "profile:CAP-CP:1.0:AutoTranslated", Value: "maybe"}}
			ps := cap.CAPCP().Check(b)
			for _, w := range []struct {
				field, text string
				warn        bool
			}{
				{"code", "must include profile:CAP-CP", false},
				{"references", "must reference", false},
				{"info[0].language", "is required", false},
				{"info[1].language", "neither en-CA nor fr-CA", true},
				{"info[0].eventCode", "eventCode is required", false},
				{"info[1].eventCode", "not a CAP-CP event code", false},
				{"info[1].senderName", "should be given", true},
				{"info[1].responseType", "should accompany", true},
				{"info[1].area[0].geocode", "not a CAP-CP location code", false},
				{"info[1].parameter", "neither yes nor no", true},
			} {
				if !find(ps, "CAP-CP", w.field, w.text, w.warn) {
					t.Errorf("missing %s: %s (warning %v) in\n%s", w.field, w.text, w.warn, dump(ps))
				}
			}
			for _, p := range ps {
				if p.Rule == "" || (!strings.HasPrefix(p.Rule, "1.0 ") && !strings.HasPrefix(p.Rule, ver+" ")) {
					t.Errorf("rule reference %q of %s", p.Rule, p)
				}
			}
		})
	}

	// Further rules: one event per message, area required, warnings for an
	// unlisted event code, translations that differ, minor changes.
	a := canadian("0.4")
	a.Info[0].EventCode[0].Value = "snowfall"
	ps := cap.CAPCP().Check(a)
	if !find(ps, "CAP-CP", "info[1].eventCode", "differs from the first", false) {
		t.Errorf("event code across blocks:\n%s", dump(ps))
	}
	if !find(ps, "CAP-CP", "info[1].eventCode", "differs from the en-ca block", false) {
		t.Errorf("translation check:\n%s", dump(ps))
	}
	a = canadian("0.4")
	a.Info[0].EventCode[0].Value, a.Info[1].EventCode[0].Value = "meteorShower", "meteorShower"
	a.Info[0].Expires, a.Info[1].Expires = "", ""
	a.Info[1].Area = nil
	ps = cap.CAPCP().Check(a)
	if !find(ps, "CAP-CP", "info[0].eventCode", "not on the CAP-CP event list", true) ||
		!find(ps, "CAP-CP", "info[0].expires", "should be given", true) ||
		!find(ps, "CAP-CP", "info[1].area", "at least one area", false) {
		t.Errorf("list, expires, area:\n%s", dump(ps))
	}
	a = canadian("1.0")
	a.Info[0].Area[0].Geocode = []cap.NamedValue{{ValueName: "PostalCode", Value: "K1A"}}
	a.Info[1].Area[0].Geocode = nil
	a.Info[1].Area[0].Polygon = []string{"45,-75 45,-74 46,-74 45,-75"}
	ps = cap.CAPCP().Check(a)
	if !find(ps, "CAP-CP", "info[0].area[0].geocode", "needs a profile:CAP-CP:Location geocode", false) {
		t.Errorf("1.0 location:\n%s", dump(ps))
	}
	// A location list loaded by the application.
	a = canadian("0.4")
	a.Info[1].Area[0].Geocode[0].Value = "9999"
	known := map[string]bool{"3506": true}
	ps = cap.CAPCPWithLocations(func(c string) bool { return known[c] }).Check(a)
	if !find(ps, "CAP-CP", "info[1].area[0].geocode", `"9999" is not on the location list`, false) || len(ps) != 2 {
		// the second problem: the blocks no longer match across languages
		t.Errorf("location list:\n%s", dump(ps))
	}
	a = canadian("1.0")
	a.Scope, a.Info = "Public", nil
	if ps := cap.CAPCP().Check(a); !find(ps, "CAP-CP", "info", "needs at least one info block", false) {
		t.Errorf("no info:\n%s", dump(ps))
	}
	a = canadian("1.0")
	mc := []cap.NamedValue{{ValueName: "profile:CAP-CP:1.0:MinorChange", Value: "other"}}
	a.Info[0].Parameter = mc
	ps = cap.CAPCP().Check(a)
	for _, f := range []string{"note", "msgType", "info[1].parameter"} {
		if !find(ps, "CAP-CP", f, "MinorChange", true) {
			t.Errorf("minor change %s:\n%s", f, dump(ps))
		}
	}
	a.Info[0].Parameter[0].Value = "huge"
	if ps := cap.CAPCP().Check(a); !find(ps, "CAP-CP", "info[0].parameter", "is not one of", true) {
		t.Errorf("minor change value:\n%s", dump(ps))
	}
}

// IPAWS 1.0: a complying alert passes; the profile's rules are errors,
// recommendations and rules from outside the profile are warnings.
func TestProfileIPAWS(t *testing.T) {
	ok := &cap.Alert{
		Identifier: "US-DEMO-1", Sender: "w-nws.example.test", Sent: "2026-09-24T10:00:00-05:00", Status: "Actual",
		MsgType: "Alert", Scope: "Public", Code: []string{"IPAWSv1.0"},
		Info: []cap.Info{{
			Language: "en-US", Category: []string{"Met"}, Event: "Flash Flood Warning", Urgency: "Immediate",
			Severity: "Severe", Certainty: "Likely", EventCode: []cap.NamedValue{{ValueName: "SAME", Value: "FFW"}},
			Expires: "2026-09-24T13:00:00-05:00", Description: "Flash flooding is occurring.",
			Parameter: []cap.NamedValue{{ValueName: "EAS-ORG", Value: "WXR"}, {ValueName: "CMAMtext", Value: "Flash Flood Warning this area. Avoid travel."}},
			Area:      []cap.Area{{AreaDesc: "Demo County", Geocode: []cap.NamedValue{{ValueName: "SAME", Value: "048201"}}}},
		}},
	}
	if ps := ok.Check(cap.Options{Profiles: cap.DetectProfiles(ok)}); len(ps) != 0 {
		t.Fatalf("complying alert:\n%s", dump(ps))
	}
	b := *ok
	b.Code = nil
	b.MsgType = "Cancel"
	in := ok.Info[0]
	in.EventCode = []cap.NamedValue{{ValueName: "SAME", Value: "ffw"}, {ValueName: "SAME", Value: "FFA"}}
	in.Expires, in.Description = "", ""
	in.Parameter = []cap.NamedValue{{ValueName: "EAS-ORG", Value: "XYZ"}, {ValueName: "CMAMtext", Value: strings.Repeat("x", 91)},
		{ValueName: "CMAMlongtext", Value: strings.Repeat("y", 361)}, {ValueName: "BLOCKCHANNEL", Value: "TV"}, {ValueName: "WEAHandling", Value: "Maybe"},
		{ValueName: "EAS-Must-Carry", Value: "yes"}}
	in.Resource = []cap.Resource{{ResourceDesc: "EAS Broadcast Content", MimeType: "audio/mpeg"}}
	in.Area = []cap.Area{{AreaDesc: "x", Geocode: []cap.NamedValue{{ValueName: "SAME", Value: "48201"}}}, {AreaDesc: "y"}}
	in2 := ok.Info[0]
	in2.Category = []string{"Safety"}
	in2.Area = nil
	b.Info = []cap.Info{in, in2}
	ps := cap.IPAWS().Check(&b)
	for _, w := range []struct {
		field, text string
		warn        bool
	}{
		{"code", "IPAWSv1.0", false},
		{"references", "must reference", false},
		{"info[0].eventCode", "at most one SAME", false},
		{"info[0].eventCode", "not three capital letters", false},
		{"info[0].expires", "is required", false},
		{"info[0].description", "should say", true},
		{"info[0].resource[0].mimeType", "is not one of", false},
		{"info[0].area[0].geocode", "not six digits", false},
		{"info[0].area[1].geocode", "should include a SAME", true},
		{"info[0].parameter", "EAS-ORG \"XYZ\"", false},
		{"info[0].parameter", "at most 90", false},
		{"info[0].parameter", "at most 360", true},
		{"info[0].parameter", "BLOCKCHANNEL", true},
		{"info[0].parameter", "WEAHandling", true},
		{"info[0].parameter", "EAS-Must-Carry", true},
		{"info[1].category", "differs from the first", false},
		{"info[1].eventCode", "differs from the first", false},
		{"info[1].area", "at least one area", false},
	} {
		if !find(ps, "IPAWS", w.field, w.text, w.warn) {
			t.Errorf("missing %s: %s (warning %v) in\n%s", w.field, w.text, w.warn, dump(ps))
		}
	}
	c := *ok
	c.Info = []cap.Info{ok.Info[0]}
	c.Info[0].EventCode = []cap.NamedValue{{ValueName: "NWS", Value: "x"}}
	c.Info[0].Parameter = nil
	if ps := cap.IPAWS().Check(&c); !find(ps, "IPAWS", "info[0].eventCode", "a SAME event code is needed", true) {
		t.Errorf("no SAME code:\n%s", dump(ps))
	}
	c.Info[0].EventCode = nil
	if ps := cap.IPAWS().Check(&c); !find(ps, "IPAWS", "info[0].eventCode", "is required", false) {
		t.Errorf("no event code:\n%s", dump(ps))
	}
}

// India: SACHET's conventions are warnings; RepairIndia turns its language
// codes into tags and a point in altitude and ceiling into a circle, after
// which the alert validates as CAP 1.2.
func TestProfileIndia(t *testing.T) {
	sent := time.Date(2026, 10, 10, 18, 0, 0, 0, time.FixedZone("IST", 19800))
	a := &cap.Alert{
		Identifier: "IN-DEMO-1_1", Sender: "Demo-SDMA", Sent: cap.FormatTime(sent), Status: "Actual", MsgType: "Alert", Scope: "Public",
		Info: []cap.Info{{
			Language: "en-IN", Category: []string{"Met"}, Event: "Flood", Urgency: "Future", Severity: "Moderate", Certainty: "Possible",
			Parameter: []cap.NamedValue{{ValueName: "Polygon URL", Value: "https://alerts.example.test/polygon?id=1"}},
			Area: []cap.Area{
				{AreaDesc: "River gauge", Altitude: "26.10", Ceiling: "85.20"},
				{AreaDesc: "District", Geocode: []cap.NamedValue{{ValueName: cap.LGDDistrictCode, Value: "D-12"}}},
				{AreaDesc: "Elsewhere"},
			},
		}, {
			Language: "TL", Category: []string{"Met"}, Event: "Flood", Urgency: "Future", Severity: "Moderate", Certainty: "Possible",
		}, {
			Language: "XX", Category: []string{"Met"}, Event: "Flood", Urgency: "Future", Severity: "Moderate", Certainty: "Possible",
		}},
	}
	ps := a.Check(cap.Options{Profiles: []cap.Profile{cap.India()}})
	for _, w := range []struct{ field, text string }{
		{"info[0].area[0].altitude", "latitude and longitude"},
		{"info[0].area[1].geocode", "not a number"},
		{"info[0].area[2].polygon", "https://alerts.example.test/polygon?id=1"},
		{"info[1].language", "te-IN is meant"},
		{"info[2].language", "not a language tag"},
	} {
		if !find(ps, "India", w.field, w.text, true) {
			t.Errorf("missing %s: %s in\n%s", w.field, w.text, dump(ps))
		}
	}
	for _, p := range ps {
		if !p.Warning && p.Profile == "India" {
			t.Errorf("India finding is not a warning: %s", p)
		}
	}
	if err := a.Validate(cap.Options{Profiles: []cap.Profile{cap.India()}}); err != nil {
		t.Errorf("warnings failed validation: %v", err)
	}
	changed := cap.RepairIndia(a)
	if len(changed) != 2 || a.Info[1].Language != "te-IN" || a.Info[0].Area[0].Altitude != "" || len(a.Info[0].Area[0].Circle) != 1 || a.Info[0].Area[0].Circle[0] != "26.1,85.2 0" {
		t.Fatalf("repair = %q, %+v", changed, a.Info[0].Area[0])
	}
	if ps := cap.India().Check(a); find(ps, "India", "info[0].area[0].altitude", "latitude", true) {
		t.Error("the repaired point is still reported")
	}
	for code, want := range map[string]string{"HI": "hi-IN", "PN": "pa-IN", "ML": "ml-IN", "BN": "bn-IN", "en-IN": "en-IN"} {
		if got, ok := cap.IndianLanguageTag(code); !ok || got != want {
			t.Errorf("IndianLanguageTag(%q) = %q, %v", code, got, ok)
		}
	}
	if cap.PolygonURL(cap.Info{}) != "" {
		t.Error("PolygonURL of an empty block")
	}
}

// Registry, detection and the application's own profiles; Validate fails
// on profile errors but not on warnings, and Problem names its profile.
func TestProfileRegistry(t *testing.T) {
	names := cap.ProfileNames()
	for _, want := range []string{"CAP-CP", "IPAWS", "India"} {
		if j := "," + strings.Join(names, ",") + ","; !strings.Contains(j, ","+want+",") {
			t.Errorf("ProfileNames = %v, lacks %s", names, want)
		}
	}
	for _, n := range []string{"cap-cp", "ipaws", " India "} {
		if _, ok := cap.ProfileByName(n); !ok {
			t.Errorf("ProfileByName(%q) not found", n)
		}
	}
	if _, ok := cap.ProfileByName("none"); ok {
		t.Error("unknown profile found")
	}
	own := cap.NewProfile("Utility", func(a *cap.Alert) []cap.Problem {
		if a.Source == "" {
			return []cap.Problem{{Field: "source", Issue: "names the control room", Rule: "U1"}}
		}
		return nil
	})
	cap.RegisterProfile("Utility", func() cap.Profile { return own })
	defer cap.RegisterProfile("Utility", func() cap.Profile { return cap.NewProfile("Utility", func(*cap.Alert) []cap.Problem { return nil }) })
	p, ok := cap.ProfileByName("utility")
	if !ok {
		t.Fatal("own profile not registered")
	}
	a := rainAlert("MET-PUNE-0500", "Alert", "Severe", "", time.Now())
	err := a.Validate(cap.Options{Profiles: []cap.Profile{p, nil}})
	var ve cap.ValidationError
	if !errors.As(err, &ve) || len(ve) != 1 || ve[0].Profile != "Utility" || ve[0].Essential() {
		t.Fatalf("own profile: %v", err)
	}
	if s := ve[0].String(); s != "source: names the control room (Utility U1)" {
		t.Errorf("String = %q", s)
	}
	w := cap.Problem{Field: "x", Issue: "y", Profile: "P", Warning: true}
	if w.String() != "warning: x: y (P)" || w.Essential() {
		t.Errorf("warning String = %q", w.String())
	}
	if cap.DetectProfiles(a) != nil {
		t.Error("profiles detected in a plain alert")
	}
}
