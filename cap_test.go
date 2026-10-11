// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
)

// rainAlert is a district weather warning (our own sample content).
func rainAlert(id, msgType, severity, refs string, sent time.Time) *cap.Alert {
	return &cap.Alert{
		Identifier: id, Sender: "warnings@met-office.test", Sent: cap.FormatTime(sent), Status: "Actual",
		MsgType: msgType, Scope: "Public", References: refs,
		Info: []cap.Info{{
			Language: "en-IN", Category: []string{"Met"}, Event: "Heavy Rainfall", ResponseType: []string{"Prepare"},
			Urgency: "Expected", Severity: severity, Certainty: "Likely",
			Expires:  cap.FormatTime(sent.Add(24 * time.Hour)),
			Headline: "Heavy rainfall likely in Pune district", Description: "Sample warning for tests.",
			Area: []cap.Area{{
				AreaDesc: "Pune district",
				Polygon:  []string{"18.40,73.70 18.40,74.00 18.65,74.00 18.65,73.70 18.40,73.70"},
				Circle:   []string{"18.52,73.85 5"},
				Geocode:  []cap.NamedValue{{ValueName: "LGD_District", Value: "521"}},
			}},
		}, {
			Language: "mr-IN", Category: []string{"Met"}, Event: "Mushaldhar paus",
			Urgency: "Expected", Severity: severity, Certainty: "Likely",
			Expires: cap.FormatTime(sent.Add(24 * time.Hour)),
			Area:    []cap.Area{{AreaDesc: "Pune jilha", Geocode: []cap.NamedValue{{ValueName: "LGD_District", Value: "521"}}}},
		}},
	}
}

// Covers: SIG-IPE-380
func TestCAPParseAndValidate(t *testing.T) {
	sent := time.Date(2026, 9, 24, 10, 0, 0, 0, time.FixedZone("IST", 19800))
	a := rainAlert("MET-PUNE-0001", "Alert", "Severe", "", sent)
	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">`) || !strings.Contains(string(b), "<sent>2026-09-24T10:00:00+05:30</sent>") {
		t.Fatalf("encoding: %s", b)
	}
	got, err := cap.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(cap.Options{}); err != nil {
		t.Fatalf("a valid alert was refused: %v", err)
	}
	if got.Info[1].Language != "mr-IN" || got.Info[0].Area[0].Geocode[0].Value != "521" || got.MostSevere() != "Severe" {
		t.Errorf("round trip lost data: %+v", got.Info)
	}
	if cap.FormatTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) != "2026-01-01T00:00:00-00:00" {
		t.Error("UTC must be written with -00:00")
	}
	// Earlier CAP versions are read as 1.2 and say so (SIG-IPE-3542).
	if a, err := cap.Parse([]byte(`<alert xmlns="urn:oasis:names:tc:emergency:cap:1.1"><identifier>x</identifier></alert>`)); err != nil || a.Version != "1.1" || a.Identifier != "x" {
		t.Errorf("CAP 1.1: %+v %v", a, err)
	}
	if got.Version != "1.2" {
		t.Errorf("version %q", got.Version)
	}
	if _, err := cap.Parse([]byte(`<alert`)); err == nil {
		t.Error("malformed XML was accepted")
	}

	cases := map[string]struct {
		mut  func(a *cap.Alert)
		want string
	}{
		"no identifier":        {func(a *cap.Alert) { a.Identifier = "" }, "identifier: is required"},
		"comma in sender":      {func(a *cap.Alert) { a.Sender = "a,b" }, "sender: must not contain"},
		"bad status":           {func(a *cap.Alert) { a.Status = "Real" }, `status: "Real" is not one of`},
		"bad msgType":          {func(a *cap.Alert) { a.MsgType = "Notice" }, "msgType"},
		"restricted":           {func(a *cap.Alert) { a.Scope = "Restricted" }, "restriction: is required"},
		"private":              {func(a *cap.Alert) { a.Scope = "Private" }, "addresses: is required"},
		"Z time strict":        {func(a *cap.Alert) { a.Sent = "2026-09-24T04:30:00Z" }, "sent:"},
		"bad reference":        {func(a *cap.Alert) { a.References = "only-two,parts" }, "references:"},
		"no category":          {func(a *cap.Alert) { a.Info[0].Category = nil }, "info[0].category: at least one"},
		"bad urgency":          {func(a *cap.Alert) { a.Info[0].Urgency = "Soon" }, "info[0].urgency"},
		"bad severity":         {func(a *cap.Alert) { a.Info[1].Severity = "" }, "info[1].severity: is required"},
		"open polygon":         {func(a *cap.Alert) { a.Info[0].Area[0].Polygon = []string{"1,1 2,2 3,3 4,4"} }, "first and last"},
		"short polygon":        {func(a *cap.Alert) { a.Info[0].Area[0].Polygon = []string{"1,1 2,2 1,1"} }, "at least 4 points"},
		"latitude range":       {func(a *cap.Alert) { a.Info[0].Area[0].Circle = []string{"95,73 1"} }, "circle"},
		"negative radius":      {func(a *cap.Alert) { a.Info[0].Area[0].Circle = []string{"18,73 -1"} }, "radius"},
		"ceiling w/o altitude": {func(a *cap.Alert) { a.Info[0].Area[0].Ceiling = "100" }, "ceiling: needs altitude"},
		"no areaDesc":          {func(a *cap.Alert) { a.Info[1].Area[0].AreaDesc = " " }, "areaDesc: is required"},
	}
	for name, c := range cases {
		a := rainAlert("MET-PUNE-0001", "Alert", "Severe", "", sent)
		c.mut(a)
		err := a.Validate(cap.Options{})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want it to mention %q", name, err, c.want)
		}
	}
	lenient := rainAlert("x", "Alert", "Severe", "", sent)
	lenient.Sent = "2026-09-24T04:30:00.123Z"
	if err := lenient.Validate(cap.Options{LenientTime: true}); err != nil {
		t.Errorf("lenient time refused: %v", err)
	}
}

// Covers: SIG-IPE-381
func TestCAPAreaGeoJSON(t *testing.T) {
	a := rainAlert("x", "Alert", "Severe", "", time.Now())
	g := a.GeoJSON()
	b, _ := json.Marshal(g)
	var fc struct {
		Features []struct {
			Geometry *struct {
				Type        string          `json:"type"`
				Coordinates json.RawMessage `json:"coordinates"`
			} `json:"geometry"`
			Properties map[string]any `json:"properties"`
		} `json:"features"`
	}
	if err := json.Unmarshal(b, &fc); err != nil {
		t.Fatal(err)
	}
	if len(fc.Features) != 2 {
		t.Fatalf("features = %d, want one per area (2)", len(fc.Features))
	}
	f0 := fc.Features[0]
	if f0.Geometry == nil || f0.Geometry.Type != "MultiPolygon" {
		t.Fatalf("polygon plus circle should be a MultiPolygon: %s", b)
	}
	var mp [][][][]float64
	_ = json.Unmarshal(f0.Geometry.Coordinates, &mp)
	// GeoJSON is [lon, lat]: CAP "18.40,73.70" becomes [73.7, 18.4].
	if p := mp[0][0][0]; p[0] != 73.70 || p[1] != 18.40 {
		t.Errorf("first position = %v, want [73.7 18.4]", p)
	}
	ring := mp[1][0]
	if len(ring) != 33 || ring[0][0] != ring[32][0] || ring[0][1] != ring[32][1] {
		t.Errorf("circle ring has %d points or is not closed", len(ring))
	}
	// Every circle point lies ~5 km from the centre (1 deg lat ~ 111.2 km).
	north := ring[0]
	if d := (north[1] - 18.52) * 111.195; d < 4.99 || d > 5.01 {
		t.Errorf("circle north point is %.3f km from the centre, want 5", d)
	}
	if f0.Properties["areaDesc"] != "Pune district" || f0.Properties["geocodes"].(map[string]any)["LGD_District"] != "521" {
		t.Errorf("properties = %v", f0.Properties)
	}
	if fc.Features[1].Geometry != nil || fc.Features[1].Properties["language"] != "mr-IN" {
		t.Errorf("a geocode-only area has no geometry and keeps its language: %+v", fc.Features[1])
	}
}

// Covers: SIG-IPE-382
func TestCAPFeedFormats(t *testing.T) {
	a := rainAlert("MET-1", "Alert", "Severe", "", time.Now())
	doc, _ := a.Marshal()
	body := strings.TrimPrefix(string(doc), `<?xml version="1.0" encoding="UTF-8"?>`+"\n")
	atom := `<feed xmlns="http://www.w3.org/2005/Atom" xmlns:cap="urn:oasis:names:tc:emergency:cap:1.2"><title>t</title>
	  <entry><id>e1</id><updated>2026-09-24T04:30:00Z</updated><title>one</title><content type="application/cap+xml">` + body + `</content></entry>
	  <entry><id>e2</id><updated>2026-09-24T04:31:00Z</updated><link rel="self" href="/self"/><link rel="alternate" type="application/cap+xml" href="https://x.test/e2.xml"/></entry>
	</feed>`
	es, err := cap.ParseFeed([]byte(atom))
	if err != nil || len(es) != 2 {
		t.Fatalf("atom: %v %d", err, len(es))
	}
	if es[0].Alert == nil || es[0].Alert.Identifier != "MET-1" || es[0].Alert.Info[0].Area[0].AreaDesc != "Pune district" {
		t.Errorf("embedded alert = %+v", es[0].Alert)
	}
	if es[1].Link != "https://x.test/e2.xml" || es[1].Alert != nil {
		t.Errorf("linked entry = %+v", es[1])
	}
	rss := `<?xml version="1.0"?><rss version="2.0"><channel><title>Alerts</title>
	  <item><title>Warning</title><link>https://alerts.test/cap/1.xml</link><guid>g1</guid><pubDate>Thu, 24 Sep 2026 10:00:00 +0530</pubDate></item>
	</channel></rss>`
	es, err = cap.ParseFeed([]byte(rss))
	if err != nil || len(es) != 1 || es[0].Link != "https://alerts.test/cap/1.xml" || es[0].ID != "g1" {
		t.Fatalf("rss: %v %+v", err, es)
	}
	es, err = cap.ParseFeed(doc)
	if err != nil || len(es) != 1 || es[0].Alert == nil {
		t.Fatalf("bare CAP: %v %+v", err, es)
	}
	if _, err := cap.ParseFeed([]byte(`<html><body/></html>`)); err == nil {
		t.Error("an HTML page was accepted as a feed")
	}
	// Our own Atom output reads back.
	out, err := cap.WriteAtom(cap.FeedMeta{ID: "urn:x", Title: "t", Author: "a"}, []*cap.Alert{a}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	es, err = cap.ParseFeed(out)
	if err != nil || len(es) != 1 || es[0].Alert == nil || es[0].Alert.Validate(cap.Options{}) != nil {
		t.Fatalf("WriteAtom does not read back: %v %+v\n%s", err, es, out)
	}
}
