// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap_test

import (
	"fmt"

	"github.com/cB-Sigma/cap"
)

// A CAP 1.1 alert is read as 1.2; Validate lists every problem, and
// Essential tells whether the alert can still be kept.
func Example() {
	doc := []byte(`<alert xmlns="urn:oasis:names:tc:emergency:cap:1.1">
  <identifier>DEMO-1</identifier><sender>demo@example.test</sender>
  <sent>2026-09-24T10:00:00Z</sent><status>Actual</status><msgType>Alert</msgType><scope>Public</scope>
  <info><category>Met</category><event>Heavy Rainfall</event><urgency>Expected</urgency>
    <severity>Severe</severity><certainty>Likely</certainty>
    <area><areaDesc>Demo district</areaDesc><circle>18.52,73.85 5</circle></area></info>
</alert>`)
	a, err := cap.Parse(doc)
	if err != nil {
		panic(err)
	}
	fmt.Println(a.Version, a.Identifier, a.MostSevere())
	if err := a.Validate(cap.Options{}); err != nil {
		fmt.Println(err, "- essential:", err.(cap.ValidationError).Essential())
	}
	fmt.Println(a.Validate(cap.Options{LenientTime: true}) == nil)
	// Output:
	// 1.1 DEMO-1 Severe
	// the CAP alert is not valid: sent: "2026-09-24T10:00:00Z" is not in the form 2026-09-24T10:00:00+05:30 - essential: true
	// true
}
