// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// The US IPAWS profile: "Common Alerting Protocol, v. 1.2 USA Integrated
// Public Alert and Warning System Profile Version 1.0", OASIS Committee
// Specification 01, 13 October 2009:
//
//	https://docs.oasis-open.org/emergency/cap/v1.2/ipaws-profile/v1.0/cs01/cap-v1.2-ipaws-profile-cs01.html
//
// Rules are written in our own words; rule references are the profile's
// element names. A few checks come from documents outside the profile and
// are only warnings, with the source named in the rule: the originator
// codes of EAS-ORG (FCC rules, 47 CFR 11.31), BLOCKCHANNEL values (US
// National Weather Service CAP v1.2 documentation, 2017-03-07), and
// CMAMlongtext and WEAHandling (FEMA IPAWS-OPEN material, 2018). Whether a
// message is meant for EAS, wireless alerts or HazCollect is not stated in
// the message, so the profile's channel-specific requirements (exactly one
// SAME event code, EAS-ORG) are warnings when absent and errors when
// malformed.

var (
	sameEventRE = regexp.MustCompile(`^[A-Z]{3}$`)
	sameAreaRE  = regexp.MustCompile(`^[0-9]{6}$`)
)

// IPAWSMediaTypes are the mimeType values of the profile for resources of
// broadcast content.
var IPAWSMediaTypes = []string{"audio/x-ipaws-audio", "audio/x-ipaws-streaming-audio", "video/x-ipaws-video", "video/x-ipaws-streaming-video"}

// IPAWS returns the US IPAWS profile 1.0.
func IPAWS() Profile { return ipaws{} }

type ipaws struct{}

func (ipaws) Name() string { return "IPAWS" }

func (ipaws) Check(a *Alert) []Problem {
	p := &problems{profile: "IPAWS"}
	if !contains(a.Code, "IPAWSv1.0") {
		p.err("code", "code", "must include IPAWSv1.0")
	}
	if (a.MsgType == "Update" || a.MsgType == "Cancel") && strings.TrimSpace(a.References) == "" {
		p.err("references", "references", "an %s must reference the related messages that have not expired", a.MsgType)
	}
	var firstCat, firstCodes string
	for i, in := range a.Info {
		f := infoField(i)
		cats := strings.Join(in.Category, " ")
		var codes []string
		for _, ec := range in.EventCode {
			codes = append(codes, ec.ValueName+"="+ec.Value)
		}
		ecs := strings.Join(codes, " ")
		if i == 0 {
			firstCat, firstCodes = cats, ecs
		} else {
			if cats != firstCat {
				p.err("info", f+"category", "differs from the first info block; all blocks cover one event")
			}
			if ecs != firstCodes {
				p.err("info", f+"eventCode", "differs from the first info block; all blocks cover one event")
			}
		}
		if len(in.EventCode) == 0 {
			p.err("eventCode", f+"eventCode", "is required")
		}
		same := values(in.EventCode, "SAME")
		switch {
		case len(same) == 0:
			p.warn("eventCode", f+"eventCode", "a SAME event code is needed for EAS, wireless alerts and HazCollect")
		case len(same) > 1:
			p.err("eventCode", f+"eventCode", "at most one SAME event code is allowed, found %d", len(same))
		}
		for _, v := range same {
			if !sameEventRE.MatchString(v) {
				p.err("eventCode", f+"eventCode", "SAME event code %q is not three capital letters", v)
			}
		}
		if strings.TrimSpace(in.Expires) == "" {
			p.err("expires", f+"expires", "is required")
		}
		if strings.TrimSpace(in.Description) == "" {
			p.warn("description", f+"description", "should say what is happening")
		}
		for j, r := range in.Resource {
			if r.ResourceDesc == "EAS Broadcast Content" && !contains(IPAWSMediaTypes, r.MimeType) {
				p.err("resource", f+"resource["+itoa(j)+"].mimeType", "%q is not one of %s", r.MimeType, strings.Join(IPAWSMediaTypes, ", "))
			}
		}
		if len(in.Area) == 0 {
			p.err("area", f+"area", "at least one area is required")
		}
		for j, ar := range in.Area {
			sameAreas := values(ar.Geocode, "SAME")
			if len(sameAreas) == 0 {
				p.warn("geocode", f+"area["+itoa(j)+"].geocode", "should include a SAME location code")
			}
			for _, v := range sameAreas {
				if !sameAreaRE.MatchString(v) {
					p.err("geocode", f+"area["+itoa(j)+"].geocode", "SAME location code %q is not six digits", v)
				}
			}
		}
		org := values(in.Parameter, "EAS-ORG")
		if len(same) > 0 && len(org) == 0 {
			p.warn("parameter", f+"parameter", "EAS-ORG is needed for EAS and HazCollect")
		}
		for _, v := range org {
			if !contains([]string{"EAS", "CIV", "WXR", "PEP"}, v) {
				p.err("parameter (47 CFR 11.31)", f+"parameter", "EAS-ORG %q is not EAS, CIV, WXR or PEP", v)
			}
		}
		for _, v := range values(in.Parameter, "EAS-Must-Carry") {
			if !strings.EqualFold(v, "TRUE") && !strings.EqualFold(v, "FALSE") {
				p.warn("parameter", f+"parameter", "EAS-Must-Carry %q is neither TRUE nor FALSE", v)
			}
		}
		for _, name := range []string{"CMAMtext", "CMAMText"} {
			for _, v := range values(in.Parameter, name) {
				if n := utf8.RuneCountInString(v); n > 90 {
					// The profile states the limit for English text.
					if l := strings.ToLower(in.Language); l == "" || strings.HasPrefix(l, "en") {
						p.err("parameter", f+"parameter", "%s has %d characters, at most 90", name, n)
					} else {
						p.warn("parameter", f+"parameter", "%s has %d characters; English text has at most 90", name, n)
					}
				}
			}
		}
		for _, v := range values(in.Parameter, "CMAMlongtext") {
			if n := utf8.RuneCountInString(v); n > 360 {
				p.warn("parameter (IPAWS-OPEN)", f+"parameter", "CMAMlongtext has %d characters, at most 360", n)
			}
		}
		for _, v := range values(in.Parameter, "WEAHandling") {
			if !contains([]string{"Presidential", "Amber", "Imminent Threat", "Public Safety", "WEA Test"}, v) {
				p.warn("parameter (IPAWS-OPEN)", f+"parameter", "WEAHandling %q is not a known value", v)
			}
		}
		for _, v := range values(in.Parameter, "BLOCKCHANNEL") {
			if !contains([]string{"CMAS", "EAS", "NWEM", "PUBLIC"}, v) {
				p.warn("parameter (NWS)", f+"parameter", "BLOCKCHANNEL %q is not CMAS, EAS, NWEM or PUBLIC", v)
			}
		}
	}
	return p.list
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if strings.TrimSpace(s) == v {
			return true
		}
	}
	return false
}
