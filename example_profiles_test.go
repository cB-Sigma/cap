// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap_test

import (
	"fmt"

	"github.com/cB-Sigma/cap"
)

// Profiles add a community's rules: the profiles an alert declares are
// found with DetectProfiles, Check lists errors and warnings, and Validate
// fails only on errors.
func ExampleAlert_Check() {
	doc := []byte(`<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
  <identifier>CA-DEMO-1</identifier><sender>alerts.example.test</sender>
  <sent>2026-09-24T10:00:00-04:00</sent><status>Actual</status><msgType>Alert</msgType><scope>Public</scope>
  <code>profile:CAP-CP:0.4</code>
  <info><language>en-CA</language><category>Met</category><event>rainfall</event>
    <urgency>Future</urgency><severity>Moderate</severity><certainty>Likely</certainty>
    <eventCode><valueName>profile:CAP-CP:Event:0.4</valueName><value>rainfall</value></eventCode>
    <expires>2026-09-25T10:00:00-04:00</expires>
    <area><areaDesc>Demo county</areaDesc></area></info>
</alert>`)
	a, _ := cap.Parse(doc)
	o := cap.Options{Profiles: cap.DetectProfiles(a)}
	for _, p := range a.Check(o) {
		fmt.Println(p)
	}
	fmt.Println("valid:", a.Validate(o) == nil)
	// Output:
	// info[0].area[0].geocode: a profile:CAP-CP:Location geocode is required (CAP-CP 0.4 rule 9)
	// warning: info[0].senderName: should be given (CAP-CP 0.4 rule 14)
	// valid: false
}

// An application adds its own profile with NewProfile (or by implementing
// Profile) and can register it for configurations that name profiles.
func ExampleNewProfile() {
	control := cap.NewProfile("Control room", func(a *cap.Alert) []cap.Problem {
		if a.Source == "" {
			return []cap.Problem{{Field: "source", Issue: "must name the duty officer", Rule: "CR-1"}}
		}
		return nil
	})
	cap.RegisterProfile("control-room", func() cap.Profile { return control })
	p, _ := cap.ProfileByName("Control-Room")
	a := &cap.Alert{Identifier: "X-1", Sender: "ops@example.test", Sent: "2026-09-24T10:00:00+05:30",
		Status: "Exercise", MsgType: "Alert", Scope: "Public"}
	fmt.Println(a.Validate(cap.Options{Profiles: []cap.Profile{p}}))
	// Output:
	// the CAP alert is not valid: source: must name the duty officer (Control room CR-1)
}

// ValidateSchema checks a document's structure against the CAP 1.2
// schema's content model, which Parse does not.
func ExampleValidateSchema() {
	doc := []byte(`<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
  <sender>ops@example.test</sender><identifier>X-1</identifier>
  <sent>2026-09-24T10:00:00+05:30</sent><status>Exercise</status><msgType>Alert</msgType><scope>Public</scope>
</alert>`)
	_, err := cap.Parse(doc)
	fmt.Println("parse:", err)
	fmt.Println(cap.ValidateSchema(doc))
	// Output:
	// parse: <nil>
	// the CAP alert is not valid: alert/identifier: is required before sender; alert/identifier: is out of order
}

// CAP alerts in an EDXL-DE envelope are read with their routing facts.
func ExampleParseEDXLDE() {
	doc := []byte(`<EDXLDistribution xmlns="urn:oasis:names:tc:emergency:EDXL:DE:1.0">
  <distributionID>DIST-1</distributionID><senderID>hub@example.test</senderID>
  <dateTimeSent>2026-09-24T10:01:00+05:30</dateTimeSent>
  <distributionStatus>Exercise</distributionStatus><distributionType>Report</distributionType>
  <contentObject><xmlContent><embeddedXMLContent>
    <alert xmlns="urn:oasis:names:tc:emergency:cap:1.2"><identifier>X-1</identifier><sender>ops@example.test</sender>
      <sent>2026-09-24T10:00:00+05:30</sent><status>Exercise</status><msgType>Alert</msgType><scope>Public</scope></alert>
  </embeddedXMLContent></xmlContent></contentObject>
</EDXLDistribution>`)
	d, err := cap.ParseEDXLDE(doc)
	if err != nil {
		panic(err)
	}
	fmt.Println(d.Version, d.ID, d.SenderID, len(d.Entries), d.Entries[0].Alert.Identifier)
	// Output:
	// 1.0 DIST-1 hub@example.test 1 X-1
}

// SACHET alerts use their own language codes and sometimes put a point in
// altitude and ceiling; RepairIndia turns them into CAP 1.2.
func ExampleRepairIndia() {
	a := &cap.Alert{Info: []cap.Info{{Language: "TL", Area: []cap.Area{{AreaDesc: "River gauge", Altitude: "17.0", Ceiling: "81.8"}}}}}
	for _, c := range cap.RepairIndia(a) {
		fmt.Println(c)
	}
	// Output:
	// info[0].language: TL -> te-IN
	// info[0].area[0]: altitude 17.0 and ceiling 81.8 -> circle 17,81.8 0
}
