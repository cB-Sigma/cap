// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The Canadian Profile of CAP (CAP-CP), published by Public Safety Canada.
// Two versions are in use: Beta 0.4 ("Introduction and Rule Set Beta
// 0.4"), which Canadian alerts carry today as profile:CAP-CP:0.4, and 1.0
// (the "Introduction and Rule Set 1.0" pages, still marked as drafts
// without a final date). The rules below are written in our own words
// from those pages, read on 2026-10-11:
//
//	https://www.publicsafety.gc.ca/cnt/rsrcs/pblctns/capcp-ntro-rl-st/index2-en.aspx (0.4)
//	https://www.publicsafety.gc.ca/cnt/rsrcs/pblctns/capcp-ntro-rl-st/index5-en.aspx (1.0)
//	https://www.publicsafety.gc.ca/cnt/rsrcs/pblctns/capcp-vnt-rfrncs/index2-en.aspx (event list 0.4)
//
// Rule references name the version and the rule or recommendation number
// of that version's document. Checks that need history (whether every
// active message is referenced) or the full Statistics Canada location
// list are out of reach of a single message: references are required on
// Update and Cancel, and location codes are checked for form only.

// CAPCPEvents are the event codes of the CAP-CP event lists 0.4 and 1.0
// (a few are misspelt in the list itself and must be used as listed).
var CAPCPEvents = []string{
	"911Service", "accident", "admin", "aircraftCras", "airportClose", "airQuality", "airspaceClos", "amber",
	"ambulance", "animalDang", "animalDiseas", "animalFeed", "animalHealth", "arcticOut", "avalanche", "aviation",
	"biological", "blizzard", "bloodSupply", "blowingSnow", "bridgeClose", "cable", "chemical", "civil",
	"civilEmerg", "civilEvent", "cold", "coldWave", "crime", "damBreach", "damOverflow", "dangerPerson", "diesel",
	"drinkingWate", "dustStorm", "earthquake", "electric", "emergFacil", "emergSupport", "explosive", "facility",
	"fallObject", "fire", "flashFlood", "flashFreeze", "flood", "fog", "foodSupply", "forestFire", "freezeDrzl",
	"freezeRain", "freezngSpray", "frost", "galeWind", "gasoline", "geophysical", "geophyiscal", "hazmat",
	"health", "heat", "heatHumidity", "heatingOil", "heatWave", "highWater", "homeCrime", "hospital", "hurricane",
	"hurricFrcWnd", "ice", "iceberg", "icePressure", "industCrime", "industryFire", "infectious", "internet",
	"lahar", "landslide", "lavaFlow", "magnetStorm", "marine", "marineSecure", "meteor", "missingPer",
	"missingVPer", "naturalGas", "nautical", "notam", "other", "overflood", "plant", "plantInfect", "product",
	"publicServic", "pyroclasFlow", "pyroclaSurge", "radiological", "railway", "rainfall", "rdCondition",
	"reminder", "rescue", "retailCrime", "road", "roadClose", "roadDelay", "roadUsage", "rpdCloseLead",
	"satellite", "schoolBus", "schoolClose", "schoolLock", "sewer", "silver", "snowfall", "snowSquall",
	"spclIce", "spclMarine", "squall", "storm", "stormFrcWnd", "stormSurge", "strongWind", "telephone",
	"temperature", "terrorism", "testMessage", "thunderstorm", "tornado", "traffic", "train", "transit",
	"tropStorm", "tsunami", "urbanFire", "utility", "vehicleCrime", "volcanicAsh", "volcano", "volunteer",
	"waste", "water", "waterspout", "weather", "wildFire", "wind", "windchill", "winterStorm",
}

// CAP-CP minor change values (parameter profile:CAP-CP:<version>:MinorChange).
var capcpMinorChanges = []string{"none", "text", "correction", "resource", "layer", "other"}

var capcpLocationRE = regexp.MustCompile(`^[0-9]{2,}$`)

// CAPCP returns the Canadian profile. It follows the version the alert
// declares in its code (profile:CAP-CP:0.4 or profile:CAP-CP:1.0); an
// alert that declares neither is checked as 1.0 and told to declare it.
func CAPCP() Profile { return capcp{} }

// CAPCPWithLocations is CAPCP that also checks each CAP-CP location code
// against a list the application loads (Statistics Canada's SGC codes and
// the profile's location annex, which are published separately and not
// included here): known reports whether a code is on it. "00" and "none"
// are always accepted.
func CAPCPWithLocations(known func(code string) bool) Profile { return capcp{locations: known} }

type capcp struct {
	locations func(string) bool
}

func (capcp) Name() string { return "CAP-CP" }

func (cp capcp) Check(a *Alert) []Problem {
	p := &problems{profile: "CAP-CP"}
	ver := ""
	for _, c := range a.Code {
		switch strings.TrimSpace(c) {
		case "profile:CAP-CP:0.4":
			ver = "0.4"
		case "profile:CAP-CP:1.0":
			if ver == "" {
				ver = "1.0"
			}
		}
	}
	if ver == "" {
		p.err("1.0 rule 3", "code", "must include profile:CAP-CP:1.0 (or profile:CAP-CP:0.4 for the beta profile)")
		ver = "1.0"
	}
	r := func(n04, n10 string) string {
		if ver == "0.4" {
			return "0.4 " + n04
		}
		return "1.0 " + n10
	}

	// An alert, update or cancel for the public carries information.
	if a.Scope == "Public" && len(a.Info) == 0 && (a.MsgType == "Alert" || a.MsgType == "Update" || a.MsgType == "Cancel") {
		p.err(r("rule 5", "rule 4"), "info", "a public %s needs at least one info block", a.MsgType)
	}
	// Updates and cancels refer to the messages they follow.
	if (a.MsgType == "Update" || a.MsgType == "Cancel") && strings.TrimSpace(a.References) == "" {
		p.err(r("rule 12", "rule 9"), "references", "an %s must reference the active messages it follows", a.MsgType)
	}

	var firstEvent string
	for i, in := range a.Info {
		f := infoField(i)
		// Language: stated, English or French Canadian.
		switch strings.TrimSpace(in.Language) {
		case "":
			p.err(r("rule 6", "rule 5"), f+"language", "is required (en-CA or fr-CA)")
		case "en-CA", "fr-CA":
		default:
			p.warn(r("rule 6", "rule 5"), f+"language", "%q is neither en-CA nor fr-CA", in.Language)
		}
		// Exactly one CAP-CP event code, from the list.
		var events []string
		for _, ec := range in.EventCode {
			if strings.HasPrefix(ec.ValueName, "profile:CAP-CP:Event:") {
				events = append(events, ec.Value)
			}
		}
		switch len(events) {
		case 0:
			p.err(r("rule 8", "rule 6"), f+"eventCode", "a profile:CAP-CP:Event eventCode is required")
		case 1:
			ev := strings.TrimSpace(events[0])
			if ev == "" || strings.ContainsAny(ev, " \t") || len(ev) > 12 {
				p.err(r("rule 8", "rule 6"), f+"eventCode", "%q is not a CAP-CP event code (at most 12 characters, no spaces)", events[0])
			} else if !containsFold(CAPCPEvents, ev) {
				p.warn(r("rule 8", "rule 6"), f+"eventCode", "%q is not on the CAP-CP event list", ev)
			}
			if firstEvent == "" {
				firstEvent = ev
			} else if !strings.EqualFold(firstEvent, ev) {
				p.err(r("rule 2", "rule 2"), f+"eventCode", "%q differs from the first info block's %q; a message covers one event", ev, firstEvent)
			}
		default:
			p.err(r("rule 8", "rule 6"), f+"eventCode", "only one profile:CAP-CP:Event eventCode is allowed, found %d", len(events))
		}
		// Areas.
		if len(in.Area) == 0 {
			p.err(r("rule 10", "rule 8"), f+"area", "at least one area is required")
		}
		for j, ar := range in.Area {
			af := f + "area[" + itoa(j) + "]."
			var locs []string
			for _, g := range ar.Geocode {
				if strings.HasPrefix(g.ValueName, "profile:CAP-CP:Location:") {
					locs = append(locs, g.Value)
				}
			}
			if ver == "0.4" && len(locs) == 0 {
				p.err("0.4 rule 9", af+"geocode", "a profile:CAP-CP:Location geocode is required")
			}
			if ver == "1.0" && len(ar.Polygon) == 0 && len(ar.Circle) == 0 {
				if len(ar.Geocode) == 0 {
					p.err("1.0 rule 7", af+"geocode", "a polygon, circle or geocode is required")
				} else if len(locs) == 0 {
					p.err("1.0 rule 7", af+"geocode", "an area given by geocodes only needs a profile:CAP-CP:Location geocode")
				}
			}
			for _, l := range locs {
				l = strings.TrimSpace(l)
				switch {
				case strings.EqualFold(l, "none") || l == "00":
				case !capcpLocationRE.MatchString(l):
					p.err(r("rule 9", "rule 7"), af+"geocode", "%q is not a CAP-CP location code (Statistics Canada SGC digits, 00 or none)", l)
				case cp.locations != nil && !cp.locations(l):
					p.err(r("rule 9", "rule 7"), af+"geocode", "%q is not on the location list", l)
				}
			}
		}
		// Recommendations.
		if ver == "0.4" && strings.TrimSpace(in.Expires) == "" {
			p.warn("0.4 rule 13", f+"expires", "should be given")
		}
		if strings.TrimSpace(in.SenderName) == "" {
			p.warn(r("rule 14", "recommendation 4"), f+"senderName", "should be given")
		}
		if strings.TrimSpace(in.Instruction) != "" && len(in.ResponseType) == 0 {
			p.warn(r("rule 15", "recommendation 5"), f+"responseType", "should accompany the instruction")
		}
		auto := values(in.Parameter, "profile:CAP-CP:"+ver+":AutoTranslated")
		if len(auto) > 1 {
			p.warn(r("rule 17", "recommendation 6"), f+"parameter", "AutoTranslated is given %d times", len(auto))
		}
		for _, v := range auto {
			if !strings.EqualFold(v, "yes") && !strings.EqualFold(v, "no") {
				p.warn(r("rule 17", "recommendation 6"), f+"parameter", "AutoTranslated %q is neither yes nor no", v)
			}
		}
	}

	// Minor changes: on updates only, in every info block.
	name := "profile:CAP-CP:" + ver + ":MinorChange"
	with := 0
	for i, in := range a.Info {
		for _, v := range values(in.Parameter, name) {
			with++
			if !containsFold(capcpMinorChanges, v) {
				p.warn(r("rule 16", "recommendation 7"), infoField(i)+"parameter", "MinorChange %q is not one of %s", v, strings.Join(capcpMinorChanges, ", "))
			}
			if strings.EqualFold(v, "other") && strings.TrimSpace(a.Note) == "" {
				p.warn(r("rule 16", "recommendation 7"), "note", "MinorChange other needs a note")
			}
		}
	}
	if with > 0 {
		if a.MsgType != "Update" || strings.TrimSpace(a.References) == "" {
			p.warn(r("rule 16", "recommendation 7"), "msgType", "MinorChange belongs on an Update with references")
		}
		for i, in := range a.Info {
			if len(values(in.Parameter, name)) == 0 {
				p.warn(r("rule 16", "recommendation 7"), infoField(i)+"parameter", "MinorChange must be in every info block when in one")
			}
		}
	}

	// Language variants carry the same non-text content.
	p.list = append(p.list, sameAcrossLanguages(a, "CAP-CP", r("rule 6", "rule 5"))...)
	return p.list
}

// sameAcrossLanguages compares the n-th info block of each language with
// the n-th of the first language (when every language has the same
// number of blocks): their non-text content must be equal.
func sameAcrossLanguages(a *Alert, profile, rule string) []Problem {
	byLang := map[string][]int{}
	var order []string
	for i, in := range a.Info {
		l := strings.ToLower(strings.TrimSpace(in.Language))
		if _, ok := byLang[l]; !ok {
			order = append(order, l)
		}
		byLang[l] = append(byLang[l], i)
	}
	if len(order) < 2 {
		return nil
	}
	n := len(byLang[order[0]])
	for _, l := range order[1:] {
		if len(byLang[l]) != n {
			return []Problem{{Field: "info", Issue: "the languages have different numbers of info blocks", Profile: profile, Rule: rule, Warning: true}}
		}
	}
	first := order[0]
	if first == "" {
		first = "unlabelled"
	}
	var out []Problem
	for k := 0; k < n; k++ {
		base := a.Info[byLang[order[0]][k]]
		for _, l := range order[1:] {
			i := byLang[l][k]
			if d := nonTextDiff(base, a.Info[i]); d != "" {
				out = append(out, Problem{Field: infoField(i) + d, Issue: "differs from the " + first + " block it translates", Profile: profile, Rule: rule})
			}
		}
	}
	return out
}

func nonTextDiff(x, y Info) string {
	eq := func(a, b []string) bool {
		a, b = append([]string(nil), a...), append([]string(nil), b...)
		sort.Strings(a)
		sort.Strings(b)
		return strings.Join(a, "\x00") == strings.Join(b, "\x00")
	}
	nv := func(l []NamedValue) []string {
		var out []string
		for _, v := range l {
			out = append(out, v.ValueName+"="+v.Value)
		}
		return out
	}
	switch {
	case !eq(x.Category, y.Category):
		return "category"
	case !eq(x.ResponseType, y.ResponseType):
		return "responseType"
	case x.Urgency != y.Urgency:
		return "urgency"
	case x.Severity != y.Severity:
		return "severity"
	case x.Certainty != y.Certainty:
		return "certainty"
	case !eq(nv(x.EventCode), nv(y.EventCode)):
		return "eventCode"
	case x.Effective != y.Effective:
		return "effective"
	case x.Onset != y.Onset:
		return "onset"
	case x.Expires != y.Expires:
		return "expires"
	case len(x.Area) != len(y.Area):
		return "area"
	}
	for j := range x.Area {
		ax, ay := x.Area[j], y.Area[j]
		if !eq(ax.Polygon, ay.Polygon) || !eq(ax.Circle, ay.Circle) || !eq(nv(ax.Geocode), nv(ay.Geocode)) || ax.Altitude != ay.Altitude || ax.Ceiling != ay.Ceiling {
			return "area[" + itoa(j) + "]"
		}
	}
	return ""
}

func infoField(i int) string { return "info[" + itoa(i) + "]." }

func itoa(i int) string { return strconv.Itoa(i) }

func containsFold(set []string, v string) bool {
	for _, s := range set {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}
