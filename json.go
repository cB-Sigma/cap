// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap

import (
	"encoding/json"
	"errors"
)

// JSON with CAP element names. Alert's own fields carry no JSON tags (the
// Go names would be used by encoding/json, which v0.1 callers may rely
// on), so CAP-named JSON goes through MarshalJSONCAP and ParseJSON. There
// is no standard JSON form of CAP; this one uses the element names of the
// XML ("identifier", "info", "areaDesc", ...), arrays for elements that
// may repeat, and omits empty optional elements.

type jsonAlert struct {
	Identifier  string     `json:"identifier"`
	Sender      string     `json:"sender"`
	Sent        string     `json:"sent"`
	Status      string     `json:"status"`
	MsgType     string     `json:"msgType"`
	Source      string     `json:"source,omitempty"`
	Scope       string     `json:"scope"`
	Restriction string     `json:"restriction,omitempty"`
	Addresses   string     `json:"addresses,omitempty"`
	Code        []string   `json:"code,omitempty"`
	Note        string     `json:"note,omitempty"`
	References  string     `json:"references,omitempty"`
	Incidents   string     `json:"incidents,omitempty"`
	Info        []jsonInfo `json:"info,omitempty"`
}

type jsonInfo struct {
	Language     string         `json:"language,omitempty"`
	Category     []string       `json:"category"`
	Event        string         `json:"event"`
	ResponseType []string       `json:"responseType,omitempty"`
	Urgency      string         `json:"urgency"`
	Severity     string         `json:"severity"`
	Certainty    string         `json:"certainty"`
	Audience     string         `json:"audience,omitempty"`
	EventCode    []NamedValue   `json:"eventCode,omitempty"`
	Effective    string         `json:"effective,omitempty"`
	Onset        string         `json:"onset,omitempty"`
	Expires      string         `json:"expires,omitempty"`
	SenderName   string         `json:"senderName,omitempty"`
	Headline     string         `json:"headline,omitempty"`
	Description  string         `json:"description,omitempty"`
	Instruction  string         `json:"instruction,omitempty"`
	Web          string         `json:"web,omitempty"`
	Contact      string         `json:"contact,omitempty"`
	Parameter    []NamedValue   `json:"parameter,omitempty"`
	Resource     []jsonResource `json:"resource,omitempty"`
	Area         []Area         `json:"area,omitempty"`
}

type jsonResource struct {
	ResourceDesc string `json:"resourceDesc"`
	MimeType     string `json:"mimeType"`
	Size         string `json:"size,omitempty"`
	URI          string `json:"uri,omitempty"`
	DerefURI     string `json:"derefUri,omitempty"`
	Digest       string `json:"digest,omitempty"`
}

// MarshalJSONCAP encodes the alert as JSON with CAP element names.
func (a *Alert) MarshalJSONCAP() ([]byte, error) {
	j := jsonAlert{Identifier: a.Identifier, Sender: a.Sender, Sent: a.Sent, Status: a.Status, MsgType: a.MsgType,
		Source: a.Source, Scope: a.Scope, Restriction: a.Restriction, Addresses: a.Addresses, Code: a.Code, Note: a.Note,
		References: a.References, Incidents: a.Incidents}
	for _, in := range a.Info {
		ji := jsonInfo{Language: in.Language, Category: in.Category, Event: in.Event, ResponseType: in.ResponseType,
			Urgency: in.Urgency, Severity: in.Severity, Certainty: in.Certainty, Audience: in.Audience, EventCode: in.EventCode,
			Effective: in.Effective, Onset: in.Onset, Expires: in.Expires, SenderName: in.SenderName, Headline: in.Headline,
			Description: in.Description, Instruction: in.Instruction, Web: in.Web, Contact: in.Contact, Parameter: in.Parameter,
			Area: in.Area}
		for _, r := range in.Resource {
			ji.Resource = append(ji.Resource, jsonResource(r))
		}
		j.Info = append(j.Info, ji)
	}
	return json.Marshal(j)
}

// ParseJSON reads an alert written by MarshalJSONCAP (or any JSON with
// CAP element names). Like Parse it does not validate; Version is "1.2".
func ParseJSON(b []byte) (*Alert, error) {
	var j jsonAlert
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	if j.Identifier == "" && j.Sender == "" && j.Sent == "" {
		return nil, errors.New("not a CAP alert in JSON (no identifier, sender or sent)")
	}
	a := &Alert{Identifier: j.Identifier, Sender: j.Sender, Sent: j.Sent, Status: j.Status, MsgType: j.MsgType,
		Source: j.Source, Scope: j.Scope, Restriction: j.Restriction, Addresses: j.Addresses, Code: j.Code, Note: j.Note,
		References: j.References, Incidents: j.Incidents, Version: "1.2"}
	for _, ji := range j.Info {
		in := Info{Language: ji.Language, Category: ji.Category, Event: ji.Event, ResponseType: ji.ResponseType,
			Urgency: ji.Urgency, Severity: ji.Severity, Certainty: ji.Certainty, Audience: ji.Audience, EventCode: ji.EventCode,
			Effective: ji.Effective, Onset: ji.Onset, Expires: ji.Expires, SenderName: ji.SenderName, Headline: ji.Headline,
			Description: ji.Description, Instruction: ji.Instruction, Web: ji.Web, Contact: ji.Contact, Parameter: ji.Parameter,
			Area: ji.Area}
		for _, r := range ji.Resource {
			in.Resource = append(in.Resource, Resource(r))
		}
		a.Info = append(a.Info, in)
	}
	return a, nil
}
