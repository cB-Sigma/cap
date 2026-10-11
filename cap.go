// Package cap reads, checks, writes and signs OASIS Common Alerting
// Protocol 1.2 alert messages, and reads and writes the Atom and RSS feeds
// that carry them.
//
// CAP 1.1 and 1.0 alerts (and alerts without a namespace) are read as
// CAP 1.2, and Validate lists every problem rather than stopping at the
// first, so an application can store an alert that strays from the schema
// with its problems noted (Problem.Essential tells which problems leave an
// alert unusable). Signatures are enveloped XML signatures over the whole
// alert, verified against certificates the application pins (sign.go).
// Areas convert to GeoJSON (geo.go).
//
// The message model follows the CAP 1.2 schema; no schema or
// specification text is copied here.
package cap

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Namespace is the CAP 1.2 XML namespace.
const Namespace = "urn:oasis:names:tc:emergency:cap:1.2"

// MediaType is the media type of a CAP document.
const MediaType = "application/cap+xml"

// Alert is a CAP 1.2 alert message.
type Alert struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:emergency:cap:1.2 alert"`
	Identifier  string   `xml:"identifier"`
	Sender      string   `xml:"sender"`
	Sent        string   `xml:"sent"`
	Status      string   `xml:"status"`
	MsgType     string   `xml:"msgType"`
	Source      string   `xml:"source,omitempty"`
	Scope       string   `xml:"scope"`
	Restriction string   `xml:"restriction,omitempty"`
	Addresses   string   `xml:"addresses,omitempty"`
	Code        []string `xml:"code,omitempty"`
	Note        string   `xml:"note,omitempty"`
	References  string   `xml:"references,omitempty"`
	Incidents   string   `xml:"incidents,omitempty"`
	Info        []Info   `xml:"info,omitempty"`
	// Version is the CAP version the document was written in ("1.2",
	// "1.1", "1.0", or "none" without a namespace); it is always
	// marshalled as 1.2.
	Version string `xml:"-"`
}

// Info is one info block (one language, one event).
type Info struct {
	Language     string       `xml:"language,omitempty"`
	Category     []string     `xml:"category"`
	Event        string       `xml:"event"`
	ResponseType []string     `xml:"responseType,omitempty"`
	Urgency      string       `xml:"urgency"`
	Severity     string       `xml:"severity"`
	Certainty    string       `xml:"certainty"`
	Audience     string       `xml:"audience,omitempty"`
	EventCode    []NamedValue `xml:"eventCode,omitempty"`
	Effective    string       `xml:"effective,omitempty"`
	Onset        string       `xml:"onset,omitempty"`
	Expires      string       `xml:"expires,omitempty"`
	SenderName   string       `xml:"senderName,omitempty"`
	Headline     string       `xml:"headline,omitempty"`
	Description  string       `xml:"description,omitempty"`
	Instruction  string       `xml:"instruction,omitempty"`
	Web          string       `xml:"web,omitempty"`
	Contact      string       `xml:"contact,omitempty"`
	Parameter    []NamedValue `xml:"parameter,omitempty"`
	Resource     []Resource   `xml:"resource,omitempty"`
	Area         []Area       `xml:"area,omitempty"`
}

// NamedValue is an eventCode, parameter or geocode.
type NamedValue struct {
	ValueName string `xml:"valueName" json:"valueName"`
	Value     string `xml:"value" json:"value"`
}

// Resource is a file attached to an info block.
type Resource struct {
	ResourceDesc string `xml:"resourceDesc"`
	MimeType     string `xml:"mimeType"`
	Size         string `xml:"size,omitempty"`
	URI          string `xml:"uri,omitempty"`
	DerefURI     string `xml:"derefUri,omitempty"`
	Digest       string `xml:"digest,omitempty"`
}

// Area is an affected area.
// The JSON names are the CAP element names, so an area can be given in a
// JSON configuration.
type Area struct {
	AreaDesc string       `xml:"areaDesc" json:"areaDesc"`
	Polygon  []string     `xml:"polygon,omitempty" json:"polygon,omitempty"`
	Circle   []string     `xml:"circle,omitempty" json:"circle,omitempty"`
	Geocode  []NamedValue `xml:"geocode,omitempty" json:"geocode,omitempty"`
	Altitude string       `xml:"altitude,omitempty" json:"altitude,omitempty"`
	Ceiling  string       `xml:"ceiling,omitempty" json:"ceiling,omitempty"`
}

// Enumerations of the CAP 1.2 schema.
var (
	Statuses     = []string{"Actual", "Exercise", "System", "Test", "Draft"}
	MsgTypes     = []string{"Alert", "Update", "Cancel", "Ack", "Error"}
	Scopes       = []string{"Public", "Restricted", "Private"}
	Categories   = []string{"Geo", "Met", "Safety", "Security", "Rescue", "Fire", "Health", "Env", "Transport", "Infra", "CBRNE", "Other"}
	Responses    = []string{"Shelter", "Evacuate", "Prepare", "Execute", "Avoid", "Monitor", "Assess", "AllClear", "None"}
	Urgencies    = []string{"Immediate", "Expected", "Future", "Past", "Unknown"}
	SeverityList = []string{"Extreme", "Severe", "Moderate", "Minor", "Unknown"}
	Certainties  = []string{"Observed", "Likely", "Possible", "Unlikely", "Unknown"}
)

// Namespaces of the earlier CAP versions, read like CAP 1.2 (Parse).
const (
	Namespace11 = "urn:oasis:names:tc:emergency:cap:1.1"
	Namespace10 = "http://www.incident.com/cap/1.0"
)

// Version is the CAP version of an alert element's namespace, and whether
// it is one.
func Version(space string) (string, bool) {
	switch space {
	case Namespace:
		return "1.2", true
	case Namespace11:
		return "1.1", true
	case Namespace10, "urn:oasis:names:tc:emergency:cap:1.0":
		return "1.0", true
	}
	return "", false
}

// nsMap reads a CAP 1.0 or 1.1 document (or one without a namespace) as
// CAP 1.2: element names in those namespaces are given the 1.2 one. The
// elements the versions share have the same names.
type nsMap struct {
	d       *xml.Decoder
	version string
}

func (n *nsMap) Token() (xml.Token, error) {
	t, err := n.d.Token()
	switch x := t.(type) {
	case xml.StartElement:
		x.Name.Space = n.space(x.Name.Space)
		t = x
	case xml.EndElement:
		x.Name.Space = n.space(x.Name.Space)
		t = x
	}
	return t, err
}

func (n *nsMap) space(s string) string {
	v, ok := Version(s)
	if s == "" {
		v, ok = "none", true
	}
	if !ok {
		return s
	}
	if n.version == "" {
		n.version = v
	}
	return Namespace
}

// Parse decodes a CAP document: CAP 1.2, and also CAP 1.1, 1.0 or an
// alert without a namespace, read as 1.2 (Alert.Version says which). It
// checks the root element but not the content; call Validate for that.
func Parse(b []byte) (*Alert, error) {
	inner := xml.NewDecoder(bytes.NewReader(b))
	inner.Strict = true
	m := &nsMap{d: inner}
	d := xml.NewTokenDecoder(m)
	var a Alert
	if err := d.Decode(&a); err != nil {
		var ue xml.UnmarshalError
		if errors.As(err, &ue) || strings.Contains(err.Error(), "expected element type") {
			return nil, fmt.Errorf("not a CAP alert (root element must be alert in a CAP namespace such as %s): %w", Namespace, err)
		}
		return nil, fmt.Errorf("the CAP document is not well-formed XML: %w", err)
	}
	a.Version = m.version
	return &a, nil
}

// Marshal encodes the alert as a CAP 1.2 document with an XML declaration.
func (a *Alert) Marshal() ([]byte, error) {
	a.XMLName = xml.Name{Space: Namespace, Local: "alert"}
	b, err := xml.MarshalIndent(a, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), b...), nil
}

// Key identifies a message: sender, identifier and sent together are
// unique (the same triple a references entry uses).
func (a *Alert) Key() string { return a.Sender + "," + a.Identifier + "," + a.Sent }

// Reference is one entry of an alert's references.
type Reference struct {
	Sender, Identifier, Sent string
}

// Key is the reference in the "sender,identifier,sent" form.
func (r Reference) Key() string { return r.Sender + "," + r.Identifier + "," + r.Sent }

// ParseReferences splits a references value into its entries.
func ParseReferences(s string) ([]Reference, error) {
	var out []Reference
	for _, f := range strings.Fields(s) {
		p := strings.Split(f, ",")
		if len(p) != 3 || p[0] == "" || p[1] == "" || p[2] == "" {
			return nil, fmt.Errorf("reference %q is not sender,identifier,sent", f)
		}
		out = append(out, Reference{p[0], p[1], p[2]})
	}
	return out, nil
}

// FormatTime writes t in CAP's date-time form: seconds precision with an
// explicit offset ("2026-09-24T10:00:00+05:30"); UTC is written "-00:00".
func FormatTime(t time.Time) string {
	s := t.Truncate(time.Second).Format("2006-01-02T15:04:05-07:00")
	if strings.HasSuffix(s, "+00:00") {
		s = s[:len(s)-6] + "-00:00"
	}
	return s
}

// ParseTime reads a CAP date-time. Strict CAP has seconds precision and a
// numeric offset; feeds in the field also use "Z" and fractions, which are
// accepted too.
func ParseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("%q is not a CAP date-time such as 2026-09-24T10:00:00+05:30", s)
}

func strictTime(s string) bool {
	// YYYY-MM-DDThh:mm:ss±hh:mm, nothing else.
	if len(s) != 25 {
		return false
	}
	for i, c := range []byte(s) {
		switch i {
		case 4, 7:
			if c != '-' {
				return false
			}
		case 10:
			if c != 'T' {
				return false
			}
		case 13, 16, 22:
			if c != ':' {
				return false
			}
		case 19:
			if c != '+' && c != '-' {
				return false
			}
		default:
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	_, err := ParseTime(s)
	return err == nil
}

// Problem is one validation finding.
type Problem struct {
	Field string `json:"field"`
	Issue string `json:"issue"`
}

func (p Problem) String() string { return p.Field + ": " + p.Issue }

// ValidationError lists every problem of an alert.
type ValidationError []Problem

func (v ValidationError) Error() string {
	s := make([]string, len(v))
	for i, p := range v {
		s[i] = p.String()
	}
	return "the CAP alert is not valid: " + strings.Join(s, "; ")
}

// Options relax validation for feeds that stray from the schema.
type Options struct {
	// LenientTime accepts "Z" and fractional seconds in date-times.
	LenientTime bool
}

// Essential tells whether a validation problem leaves the alert unusable:
// without its identifier, sender or a readable sent time it cannot be
// told apart from others or referenced.
func (p Problem) Essential() bool {
	switch p.Field {
	case "identifier", "sender":
		return p.Issue == "is required"
	case "sent":
		return true
	}
	return false
}

// Essential tells whether any of the problems is essential.
func (v ValidationError) Essential() bool {
	for _, p := range v {
		if p.Essential() {
			return true
		}
	}
	return false
}

// Validate checks the alert against the CAP 1.2 rules: required elements,
// enumerations, date-time form, references, identifier characters, the
// restriction and addresses conditions of the scope, and area geometry.
func (a *Alert) Validate(o Options) error {
	var ps ValidationError
	add := func(f, format string, args ...any) { ps = append(ps, Problem{f, fmt.Sprintf(format, args...)}) }
	idChars := func(f, v string) {
		if v == "" {
			add(f, "is required")
		} else if strings.ContainsAny(v, " ,<&\t\r\n") {
			add(f, "must not contain spaces, commas, '<' or '&'")
		}
	}
	checkTime := func(f, v string, required bool) {
		if v == "" {
			if required {
				add(f, "is required")
			}
			return
		}
		if o.LenientTime {
			if _, err := ParseTime(v); err != nil {
				add(f, "%v", err)
			}
		} else if !strictTime(v) {
			add(f, "%q is not in the form 2026-09-24T10:00:00+05:30", v)
		}
	}
	enum := func(f, v string, set []string) {
		if v == "" {
			add(f, "is required")
			return
		}
		for _, s := range set {
			if s == v {
				return
			}
		}
		add(f, "%q is not one of %s", v, strings.Join(set, ", "))
	}
	idChars("identifier", a.Identifier)
	idChars("sender", a.Sender)
	checkTime("sent", a.Sent, true)
	enum("status", a.Status, Statuses)
	enum("msgType", a.MsgType, MsgTypes)
	enum("scope", a.Scope, Scopes)
	if a.Scope == "Restricted" && strings.TrimSpace(a.Restriction) == "" {
		add("restriction", "is required when scope is Restricted")
	}
	if a.Scope == "Private" && strings.TrimSpace(a.Addresses) == "" {
		add("addresses", "is required when scope is Private")
	}
	if a.References != "" {
		if refs, err := ParseReferences(a.References); err != nil {
			add("references", "%v", err)
		} else {
			for _, r := range refs {
				checkTime("references", r.Sent, true)
			}
		}
	}
	for i, in := range a.Info {
		p := fmt.Sprintf("info[%d].", i)
		if len(in.Category) == 0 {
			add(p+"category", "at least one is required")
		}
		for _, c := range in.Category {
			enum(p+"category", c, Categories)
		}
		if strings.TrimSpace(in.Event) == "" {
			add(p+"event", "is required")
		}
		for _, r := range in.ResponseType {
			enum(p+"responseType", r, Responses)
		}
		enum(p+"urgency", in.Urgency, Urgencies)
		enum(p+"severity", in.Severity, SeverityList)
		enum(p+"certainty", in.Certainty, Certainties)
		checkTime(p+"effective", in.Effective, false)
		checkTime(p+"onset", in.Onset, false)
		checkTime(p+"expires", in.Expires, false)
		for j, r := range in.Resource {
			if r.ResourceDesc == "" || r.MimeType == "" {
				add(fmt.Sprintf("%sresource[%d]", p, j), "needs resourceDesc and mimeType")
			}
		}
		for j, ar := range in.Area {
			ap := fmt.Sprintf("%sarea[%d].", p, j)
			if strings.TrimSpace(ar.AreaDesc) == "" {
				add(ap+"areaDesc", "is required")
			}
			for _, pg := range ar.Polygon {
				if _, err := ParsePolygon(pg); err != nil {
					add(ap+"polygon", "%v", err)
				}
			}
			for _, c := range ar.Circle {
				if _, _, err := ParseCircle(c); err != nil {
					add(ap+"circle", "%v", err)
				}
			}
			if ar.Ceiling != "" && ar.Altitude == "" {
				add(ap+"ceiling", "needs altitude")
			}
			for _, f := range []struct{ n, v string }{{"altitude", ar.Altitude}, {"ceiling", ar.Ceiling}} {
				if f.v != "" {
					if _, err := strconv.ParseFloat(f.v, 64); err != nil {
						add(ap+f.n, "%q is not a number", f.v)
					}
				}
			}
		}
	}
	if len(ps) > 0 {
		return ps
	}
	return nil
}

// Expires is the latest expiry of the alert's info blocks, or zero when
// one of them has none (it stays in effect).
func (a *Alert) Expires() time.Time {
	var latest time.Time
	for _, in := range a.Info {
		if in.Expires == "" {
			return time.Time{}
		}
		t, err := ParseTime(in.Expires)
		if err != nil {
			return time.Time{}
		}
		if t.After(latest) {
			latest = t
		}
	}
	return latest
}

// MostSevere is the highest severity among the info blocks ("Unknown"
// when none says).
func (a *Alert) MostSevere() string {
	best, rank := "Unknown", len(SeverityList)
	for _, in := range a.Info {
		for i, s := range SeverityList {
			if s == in.Severity && i < rank {
				best, rank = s, i
			}
		}
	}
	return best
}
