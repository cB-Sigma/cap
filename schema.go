// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Schema checks. Parse reads leniently: encoding/xml ignores unknown
// elements, element order and repeats of single elements. ValidateSchema
// checks a document's structure against the CAP 1.2 schema's content
// model instead: which elements may appear where, in which order and how
// often, the simple types of their values, and the place of the signature
// (only XML Signature elements may follow the CAP elements).
// The content model below is written from the schema's element
// declarations (facts every implementation shares); the schema file itself
// is not copied or shipped. A full XSD validator can be added as a
// SchemaValidator.

// SchemaValidator validates a whole document, for example an XSD engine
// loaded with the OASIS cap-v1.2.xsd file the application provides.
type SchemaValidator interface {
	ValidateSchema(doc []byte) error
}

// SchemaValidatorFunc adapts a function to SchemaValidator.
type SchemaValidatorFunc func(doc []byte) error

// ValidateSchema calls f.
func (f SchemaValidatorFunc) ValidateSchema(doc []byte) error { return f(doc) }

type particle struct {
	name     string
	min, max int // max -1: unbounded
	typ      string
	children []particle
}

const unbounded = -1

var (
	pairModel = []particle{{name: "valueName", min: 1, max: 1}, {name: "value", min: 1, max: 1}}
	capModel  = particle{name: "alert", children: []particle{
		{name: "identifier", min: 1, max: 1},
		{name: "sender", min: 1, max: 1},
		{name: "sent", min: 1, max: 1, typ: "dateTime"},
		{name: "status", min: 1, max: 1, typ: "status"},
		{name: "msgType", min: 1, max: 1, typ: "msgType"},
		{name: "source", max: 1},
		{name: "scope", min: 1, max: 1, typ: "scope"},
		{name: "restriction", max: 1},
		{name: "addresses", max: 1},
		{name: "code", max: unbounded},
		{name: "note", max: 1},
		{name: "references", max: 1},
		{name: "incidents", max: 1},
		{name: "info", max: unbounded, children: []particle{
			{name: "language", max: 1, typ: "language"},
			{name: "category", min: 1, max: unbounded, typ: "category"},
			{name: "event", min: 1, max: 1},
			{name: "responseType", max: unbounded, typ: "responseType"},
			{name: "urgency", min: 1, max: 1, typ: "urgency"},
			{name: "severity", min: 1, max: 1, typ: "severity"},
			{name: "certainty", min: 1, max: 1, typ: "certainty"},
			{name: "audience", max: 1},
			{name: "eventCode", max: unbounded, children: pairModel},
			{name: "effective", max: 1, typ: "dateTime"},
			{name: "onset", max: 1, typ: "dateTime"},
			{name: "expires", max: 1, typ: "dateTime"},
			{name: "senderName", max: 1},
			{name: "headline", max: 1},
			{name: "description", max: 1},
			{name: "instruction", max: 1},
			{name: "web", max: 1, typ: "anyURI"},
			{name: "contact", max: 1},
			{name: "parameter", max: unbounded, children: pairModel},
			{name: "resource", max: unbounded, children: []particle{
				{name: "resourceDesc", min: 1, max: 1},
				{name: "mimeType", min: 1, max: 1},
				{name: "size", max: 1, typ: "integer"},
				{name: "uri", max: 1, typ: "anyURI"},
				{name: "derefUri", max: 1},
				{name: "digest", max: 1},
			}},
			{name: "area", max: unbounded, children: []particle{
				{name: "areaDesc", min: 1, max: 1},
				{name: "polygon", max: unbounded},
				{name: "circle", max: unbounded},
				{name: "geocode", max: unbounded, children: pairModel},
				{name: "altitude", max: 1, typ: "decimal"},
				{name: "ceiling", max: 1, typ: "decimal"},
			}},
		}},
	}}
	enumTypes = map[string]*[]string{
		"status": &Statuses, "msgType": &MsgTypes, "scope": &Scopes, "category": &Categories,
		"responseType": &Responses, "urgency": &Urgencies, "severity": &SeverityList, "certainty": &Certainties,
	}
	languageRE = regexp.MustCompile(`^[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})*$`)
	decimalRE  = regexp.MustCompile(`^[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)$`)
	integerRE  = regexp.MustCompile(`^[+-]?[0-9]+$`)
)

// node is an element read for the schema check.
type node struct {
	name     xml.Name
	attrs    []xml.Attr
	text     string
	children []*node
	hasText  bool // non-blank character data directly inside
}

func readTree(doc []byte) (*node, error) {
	d := xml.NewDecoder(bytes.NewReader(doc))
	d.Strict = true
	var stack []*node
	var root *node
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("the CAP document is not well-formed XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &node{name: t.Name, attrs: t.Attr}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.children = append(p.children, n)
			} else if root == nil {
				root = n
			}
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				n := stack[len(stack)-1]
				n.text += string(t)
				if strings.TrimSpace(string(t)) != "" {
					n.hasText = true
				}
			}
		}
	}
	if root == nil {
		return nil, errors.New("the CAP document has no root element")
	}
	return root, nil
}

// ValidateSchema checks the document against the CAP 1.2 schema's content
// model and, when given, each extra validator (a full XSD engine, say),
// and returns every problem found as a ValidationError (nil when there is
// none). It checks the document as written: unlike Parse, it does not read
// CAP 1.1 or 1.0 as 1.2, and reports their namespace instead.
func ValidateSchema(doc []byte, extra ...SchemaValidator) error {
	var ps ValidationError
	root, err := readTree(doc)
	if err != nil {
		return ValidationError{{Field: "document", Issue: err.Error(), Rule: "XML"}}
	}
	if root.name.Local != "alert" || root.name.Space != Namespace {
		ps = append(ps, Problem{Field: "alert", Issue: fmt.Sprintf("root element is {%s}%s, not alert in %s", root.name.Space, root.name.Local, Namespace), Rule: "XSD"})
	} else {
		checkNode(&ps, root, capModel, "alert", true)
	}
	for _, x := range extra {
		if err := x.ValidateSchema(doc); err != nil {
			var ve ValidationError
			if errors.As(err, &ve) {
				ps = append(ps, ve...)
			} else {
				ps = append(ps, Problem{Field: "document", Issue: err.Error(), Rule: "XSD"})
			}
		}
	}
	if len(ps) > 0 {
		return ps
	}
	return nil
}

// ParseStrict reads a CAP 1.2 document only when it passes ValidateSchema
// (and the extra validators): for receivers that refuse a non-conforming
// document outright instead of reading it and listing its problems.
func ParseStrict(doc []byte, extra ...SchemaValidator) (*Alert, error) {
	if err := ValidateSchema(doc, extra...); err != nil {
		return nil, err
	}
	return Parse(doc)
}

func checkNode(ps *ValidationError, n *node, model particle, path string, isRoot bool) {
	add := func(f, format string, args ...any) {
		*ps = append(*ps, Problem{Field: f, Issue: fmt.Sprintf(format, args...), Rule: "XSD"})
	}
	for _, a := range n.attrs {
		if a.Name.Space == "xmlns" || (a.Name.Space == "" && a.Name.Local == "xmlns") {
			continue
		}
		add(path, "attribute %q is not allowed", a.Name.Local)
	}
	if model.children == nil {
		if len(n.children) > 0 {
			add(path, "must hold text only, not element %s", n.children[0].name.Local)
		}
		checkValue(add, path, model.typ, n.text)
		return
	}
	if n.hasText {
		add(path, "must not hold text outside its elements")
	}
	i := 0 // position in the content model
	count := 0
	counts := map[string]int{}
	for ci, c := range n.children {
		if c.name.Space != Namespace {
			// The alert ends with any number of elements of the XML
			// Signature namespace (checked laxly); nothing else may.
			if isRoot && c.name.Space == XMLDSigNamespace {
				for _, rest := range n.children[ci:] {
					switch rest.name.Space {
					case XMLDSigNamespace:
					case Namespace:
						add(path+"/"+rest.name.Local, "comes after the signature; CAP elements must come first")
					default:
						add(path+"/"+rest.name.Local, "element {%s}%s is not allowed here", rest.name.Space, rest.name.Local)
					}
				}
				break
			}
			add(path+"/"+c.name.Local, "element {%s}%s is not allowed here", c.name.Space, c.name.Local)
			continue
		}
		// Advance through the model to the particle naming c.
		j := i
		for j < len(model.children) && model.children[j].name != c.name.Local {
			j++
		}
		if j == len(model.children) {
			known := false
			for _, p := range model.children[:i] {
				if p.name == c.name.Local {
					known = true
				}
			}
			if known {
				add(path+"/"+c.name.Local, "is out of order")
			} else {
				add(path+"/"+c.name.Local, "is not an element of %s", model.name)
			}
			continue
		}
		for k := i; k < j; k++ {
			if model.children[k].min > 0 && (k != i || count == 0) {
				add(path+"/"+model.children[k].name, "is required before %s", c.name.Local)
			}
		}
		if j != i {
			i, count = j, 0
		}
		p := model.children[i]
		count++
		idx := counts[p.name]
		counts[p.name]++
		if p.max != unbounded && count > p.max {
			add(path+"/"+p.name, "may appear only once")
		}
		cp := path + "/" + p.name
		if p.max == unbounded {
			cp += "[" + strconv.Itoa(idx) + "]"
		}
		checkNode(ps, c, p, cp, false)
	}
	for k := i; k < len(model.children); k++ {
		p := model.children[k]
		if p.min > 0 && !(k == i && count > 0) && counts[p.name] == 0 {
			add(path+"/"+p.name, "is required")
		}
	}
}

func checkValue(add func(string, string, ...any), path, typ, v string) {
	switch typ {
	case "":
		return
	case "dateTime":
		if !strictTime(strings.TrimSpace(v)) {
			add(path, "%q is not a CAP date-time such as 2026-09-24T10:00:00+05:30", v)
		}
	case "language":
		if !languageRE.MatchString(strings.TrimSpace(v)) {
			add(path, "%q is not a language tag", v)
		}
	case "decimal":
		if !decimalRE.MatchString(strings.TrimSpace(v)) {
			add(path, "%q is not a decimal number", v)
		}
	case "integer":
		if !integerRE.MatchString(strings.TrimSpace(v)) {
			add(path, "%q is not an integer", v)
		}
	case "anyURI":
		if _, err := url.Parse(strings.TrimSpace(v)); err != nil {
			add(path, "%q is not a URI", v)
		}
	default:
		set := *enumTypes[typ]
		for _, s := range set {
			if s == v {
				return
			}
		}
		add(path, "%q is not one of %s", v, strings.Join(set, ", "))
	}
}
