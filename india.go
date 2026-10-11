// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap

import (
	"strconv"
	"strings"
)

// India. Public warnings in India go out through SACHET, the CAP-based
// Integrated Alert System of the National Disaster Management Authority
// (NDMA), built by C-DOT, which publishes RSS feeds of CAP 1.2 alerts
// (https://sachet.ndma.gov.in/cap_public_website/rss/rss_india.xml and one
// per state). India adopted CAP through ITU-T X.1303, which is CAP 1.2
// itself. No public document of NDMA, C-DOT, TEC or TSDSI defining a CAP
// profile (rules beyond CAP 1.2) was found on 2026-10-11, so this profile
// does not claim to be an official one: its rules are the conventions the
// SACHET feed was seen to use in 50 alerts read on 2026-10-11, and every
// finding is a warning. RepairIndia fixes the departures from CAP 1.2
// that those alerts showed.
//
// Observed conventions: English blocks in en-IN and regional blocks with
// bare upper-case codes (HI, ML, BN, and PN for Punjabi and TL for Telugu,
// which are not those languages' codes); areas located by geocode
// "LGD District Code" (district numbers of the Local Government
// Directory), with a "Polygon URL" parameter linking to the polygon; some
// river alerts give a point as latitude in altitude and longitude in
// ceiling, without geocodes.

// LGD geocode valueName of SACHET alerts.
const LGDDistrictCode = "LGD District Code"

var sachetLanguages = map[string]string{
	"HI": "hi-IN", "ML": "ml-IN", "BN": "bn-IN", "PN": "pa-IN", "TL": "te-IN",
	"TA": "ta-IN", "KN": "kn-IN", "MR": "mr-IN", "GU": "gu-IN", "OR": "or-IN", "AS": "as-IN", "UR": "ur-IN",
}

// IndianLanguageTag turns a SACHET language code into a language tag
// ("HI" is hi-IN; "PN" is pa-IN, Punjabi; "TL" is te-IN, Telugu, as the
// script of SACHET's TL blocks shows). ok is false for a code it does not
// know; a well-formed tag is returned unchanged with ok true.
func IndianLanguageTag(code string) (tag string, ok bool) {
	c := strings.TrimSpace(code)
	if t, ok := sachetLanguages[c]; ok {
		return t, true
	}
	if strings.Contains(c, "-") && languageRE.MatchString(c) {
		return c, true
	}
	return c, false
}

// PolygonURL returns the "Polygon URL" parameter of a SACHET info block
// ("" when there is none): the address of the polygon its areas leave out.
func PolygonURL(in Info) string {
	if v := values(in.Parameter, "Polygon URL"); len(v) > 0 {
		return strings.TrimSpace(v[0])
	}
	return ""
}

// India returns the profile of the conventions SACHET alerts follow (see
// above; all findings are warnings).
func India() Profile { return india{} }

type india struct{}

func (india) Name() string { return "India" }

const sachetRule = "SACHET convention"

func (india) Check(a *Alert) []Problem {
	p := &problems{profile: "India"}
	for i, in := range a.Info {
		f := infoField(i)
		if l := strings.TrimSpace(in.Language); l == "" {
			p.warn(sachetRule, f+"language", "should be given (en-IN for English)")
		} else if t, ok := IndianLanguageTag(l); !ok {
			p.warn(sachetRule, f+"language", "%q is not a language tag", l)
		} else if t != l {
			p.warn(sachetRule, f+"language", "%q is not a language tag; %s is meant (RepairIndia fixes it)", l, t)
		}
		for j, ar := range in.Area {
			af := f + "area[" + itoa(j) + "]."
			for _, v := range values(ar.Geocode, LGDDistrictCode) {
				if _, err := strconv.Atoi(strings.TrimSpace(v)); err != nil {
					p.warn(sachetRule, af+"geocode", "LGD district code %q is not a number", v)
				}
			}
			if _, _, ok := latLonInAltitude(ar); ok {
				p.warn(sachetRule, af+"altitude", "altitude and ceiling hold a latitude and longitude (RepairIndia moves them to a circle)")
			} else if len(ar.Geocode) == 0 && len(ar.Polygon) == 0 && len(ar.Circle) == 0 {
				if u := PolygonURL(in); u != "" {
					p.warn(sachetRule, af+"polygon", "the area has no geometry or geocode in the alert; its polygon is at %s", u)
				} else {
					p.warn(sachetRule, af+"geocode", "the area has no geometry or geocode")
				}
			}
		}
	}
	return p.list
}

// latLonInAltitude tells whether an area without geometry carries a point
// as latitude in altitude and longitude in ceiling (both within India's
// bounding box, 6 to 38 N and 68 to 98 E).
func latLonInAltitude(ar Area) (lat, lon float64, ok bool) {
	if len(ar.Polygon) > 0 || len(ar.Circle) > 0 || ar.Altitude == "" || ar.Ceiling == "" {
		return 0, 0, false
	}
	lat, err1 := strconv.ParseFloat(strings.TrimSpace(ar.Altitude), 64)
	lon, err2 := strconv.ParseFloat(strings.TrimSpace(ar.Ceiling), 64)
	if err1 != nil || err2 != nil || lat < 6 || lat > 38 || lon < 68 || lon > 98 {
		return 0, 0, false
	}
	return lat, lon, true
}

// RepairIndia fixes the departures from CAP 1.2 seen in SACHET alerts, in
// place, and lists what it changed: SACHET language codes become language
// tags, and a point given as latitude in altitude and longitude in ceiling
// becomes a circle of radius 0 (altitude and ceiling are cleared). Run it
// before Validate and GeoJSON.
func RepairIndia(a *Alert) []string {
	var changed []string
	for i := range a.Info {
		in := &a.Info[i]
		f := infoField(i)
		if t, ok := IndianLanguageTag(in.Language); ok && t != strings.TrimSpace(in.Language) {
			changed = append(changed, f+"language: "+in.Language+" -> "+t)
			in.Language = t
		}
		for j := range in.Area {
			ar := &in.Area[j]
			if lat, lon, ok := latLonInAltitude(*ar); ok {
				c := strconv.FormatFloat(lat, 'f', -1, 64) + "," + strconv.FormatFloat(lon, 'f', -1, 64) + " 0"
				changed = append(changed, f+"area["+itoa(j)+"]: altitude "+ar.Altitude+" and ceiling "+ar.Ceiling+" -> circle "+c)
				ar.Circle = append(ar.Circle, c)
				ar.Altitude, ar.Ceiling = "", ""
			}
		}
	}
	return changed
}

func init() {
	RegisterProfile("CAP-CP", CAPCP)
	RegisterProfile("IPAWS", IPAWS)
	RegisterProfile("India", India)
}
