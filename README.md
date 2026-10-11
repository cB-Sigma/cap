# cap

OASIS Common Alerting Protocol 1.2 in pure Go: the alert model, reading and validation, XML signatures, area geometry and alert feeds.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/cap.svg)](https://pkg.go.dev/github.com/cB-Sigma/cap) [![test](https://github.com/cB-Sigma/cap/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/cap/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.27.1-00ADD8.svg)](go.mod)

It reads CAP 1.2 and also takes CAP 1.1 and 1.0, lists every validation
problem instead of stopping at the first, checks national profiles
(Canada, the US, India) and the application's own, checks documents
against the CAP 1.2 schema's content model, signs alerts and verifies
enveloped XML signatures against pinned certificates or CA chains with
revocation, converts areas to GeoJSON, reads and writes the Atom and RSS
feeds and EDXL-DE 1.0 and 2.0 envelopes that carry or link alerts, and
plays the network roles: feed poller and server, push receiver and
sender, and client of Canada's NAADS stream. It was written
for SigmaM2M, a oneM2M platform, as the protocol half of its CAP feed
ingest, publishing and public warning integrations.

## Features

| Feature | Status |
|---|---|
| CAP 1.2 read and write | yes; XML, and JSON with CAP element names (`MarshalJSONCAP`, `ParseJSON`) |
| CAP 1.1, 1.0, no namespace | read as 1.2; `Alert.Version` records the original |
| Validation | required elements, enumerations, date-time form (strict or lenient), references, identifier characters, scope conditions, polygon, circle, altitude and ceiling; `Problem.Essential` tells which problems leave an alert unusable; `Check` adds warnings |
| Schema check | `ValidateSchema`: element order, occurrence, unknown elements, attributes, simple types and signature placement, from the CAP 1.2 schema's content model; package `capxsd` validates against the OASIS CAP-v1.2.xsd file itself (shipped) on a pure-Go XSD engine, alone or as a `SchemaValidator` |
| Profiles | Canada CAP-CP 0.4 and 1.0 (`CAPCP`), US IPAWS 1.0 (`IPAWS`), India's SACHET conventions (`India`, warnings only, with `RepairIndia`); your own through the `Profile` interface; `DetectProfiles` finds the ones an alert declares |
| XML signatures | enveloped, exclusive C14N, SHA-256, RSA or ECDSA (r and s side by side as XML Signature requires, or ASN.1 for goxmldsig-based readers); verification against pinned certificates or a chain to trusted roots (intermediates from KeyInfo or settings, system roots optional), key usage checks, a revocation hook with CRL and OCSP checks built in |
| Message history | `History`: whether an Update or Cancel references every message of its chain still in effect |
| Feeds and envelopes | Atom (RFC 4287) with embedded or linked alerts, RSS 2.0, EDXL-DE 1.0 and 2.0 (embedded, base64 or linked alerts), a bare alert in; Atom and EDXL-DE 1.0 and 2.0 out (`WriteEDXLDE2`); RSS out through `capnet.FeedHandler` |
| Network roles (`capnet`) | feed poller (conditional GETs, linked documents, RFC 5005 paging, de-duplication, history); feed server and push receiver as `http.Handler`s; push sender with retries; client for the TCP stream of Canada's NAAD System |
| GeoJSON (RFC 7946) | areas as a FeatureCollection; circles as polygons of 32 sides, or as many as asked (`GeoJSONWith`) |

Limits, stated plainly:

- Profiles check one message at a time. The rule that needs the message
  history (CAP-CP and IPAWS: an Update or Cancel must reference every
  message of its chain still in effect) is checked by `History`, which
  knows only the messages it has been given. CAP-CP location codes are
  checked for form; `CAPCPWithLocations` checks them against a list the
  application loads (Statistics Canada's codes are not included).
- India has no published CAP profile (NDMA, C-DOT, TEC and TSDSI were
  searched on 2026-10-11; India adopted CAP 1.2 itself through ITU-T
  X.1303). `India` checks the conventions seen in 50 alerts of NDMA's
  SACHET feed, as warnings, and says so in every finding's rule.
- The OASIS EDXL-DE 2.0 schema set cannot yet be loaded by
  github.com/cB-Sigma/xsd v0.3.0 (GML types that extend a simple-content
  type with complex content, and the xlink namespace imported from two
  files), so `WriteEDXLDE2` output is checked against it with xmlschema
  in the interop tests, not in Go.
- Enumerations are strings with exported value lists; typed values (as
  tannerryan/cap has) would change the `Alert` fields, so they wait for
  the v1 API review.
- IPAWS-OPEN publishing (SOAP with a FEMA certificate) is not here; it
  needs a FEMA account.
- `OCSPCheck` soft-fails by default (an unreachable responder passes);
  `OCSPOptions.Strict` makes every certificate's answer required.

## Choosing a Go CAP library

Compared from each library's source at the versions named, in October
2026. Check the projects themselves before relying on a row.

| | this module (v0.3.0) | tannerryan/cap v1.1.1 (still the latest on 2026-10-12) | IBM/cap (2019 commit) | alerting/go-cap (2018 commit) |
|---|---|---|---|---|
| Maintained | yes | yes (tagged 2026-10-03) | archived | archived |
| Licence | Apache-2.0 | BSD-2-Clause | Apache-2.0 | MIT |
| Reads CAP 1.2 | yes, leniently (`Parse`) or refusing non-conforming documents (`ParseStrict`) | yes, strictly (refuses unknown elements at parse) | yes | yes, without namespace checks |
| Reads CAP 1.1 and 1.0 | yes, as 1.2 | no, refuses other namespaces | 1.1 as a separate type | yes, without namespace checks |
| Validation | every problem listed, errors and warnings, profile and rule named; base problems with their CAP 1.2 clause; strict or lenient date-times; derefUri, digest, size and ceiling warnings; schema content-model check and the OASIS schema file itself (`capxsd`) | errors and warnings, each with its clause; derefUri and digest checks | no | no |
| Enumerations | strings, with the value lists exported | typed values | strings | strings |
| Canadian profile (CAP-CP) | 0.4 (what Canadian feeds carry) and 1.0; event list as a warning | 1.0 only | no | no |
| US IPAWS profile, India | yes; India as SACHET's observed conventions | no | no | no |
| Own profiles | `Profile` interface and registry | no | no | no |
| Verifies XML signatures | yes, pinned certificates or a chain to trusted roots; CRL and OCSP checks, revocation hook | yes, a chain to trusted roots, with a certificate check hook | no | no |
| Signs alerts | yes (RSA, ECDSA) | no | no | no |
| Reference chains across messages | `History` | no | no | no |
| Feeds, envelopes | reads Atom, RSS and EDXL-DE 1.0/2.0, writes Atom, RSS and EDXL-DE 1.0/2.0 | no | reads the US NWS Atom feed | no |
| Network roles | feed poller, feed server, push receiver and sender, NAADS stream client (`capnet`) | no | no | no |
| Signature interop | xmlsec1 both ways (RSA, ECDSA in XML Signature's r\|\|s form), tannerryan/cap (with ASN.1 ECDSA) | verifies through goxmldsig, which reads ECDSA values only in ASN.1 form (so not those of xmlsec1 or this module by default) | no | no |
| JSON | CAP element names, through `MarshalJSONCAP`/`ParseJSON` | typed enums with JSON tags on the types | no | no |
| Areas as GeoJSON | yes | polygon and circle parsing only | no | polygon and circle types |

Both maintained libraries sign or verify through
github.com/russellhaering/goxmldsig and github.com/beevik/etree. Our
interop tests cross-check the two (see Testing).

Pick this module for most uses: it covers what the others check and adds
older CAP versions, feeds, envelopes, the IPAWS and Indian profiles,
CAP-CP 0.4, your own profiles, reference chains, revocation and signing. Pick
tannerryan/cap when you prefer typed enumeration values (urgency,
severity and so on as Go types with their own JSON encoding) to strings;
that is a matter of API style, not of what is checked.

## Install

```
go get github.com/cB-Sigma/cap@latest
```

Requires Go 1.27.1 or later.

## Quick start

```go
import "github.com/cB-Sigma/cap"

a, err := cap.Parse(doc) // a CAP 1.1 alert is read as 1.2
if err != nil {
	return err
}
fmt.Println(a.Version, a.Identifier, a.MostSevere())
if err := a.Validate(cap.Options{}); err != nil {
	fmt.Println(err, "- essential:", err.(cap.ValidationError).Essential())
}
fmt.Println(a.Validate(cap.Options{LenientTime: true}) == nil)
// 1.1 DEMO-1 Severe
// the CAP alert is not valid: sent: "2026-09-24T10:00:00Z" is not in the form 2026-09-24T10:00:00+05:30 - essential: true
// true
```

This is the runnable `Example` in example_test.go, which holds the CAP 1.1
document it reads.

Profiles: the profiles an alert declares, errors and warnings
(`ExampleAlert_Check` in example_profiles_test.go, which holds the
CAP-CP 0.4 alert it reads):

```go
a, _ := cap.Parse(doc)
o := cap.Options{Profiles: cap.DetectProfiles(a)}
for _, p := range a.Check(o) {
	fmt.Println(p)
}
fmt.Println("valid:", a.Validate(o) == nil)
// info[0].area[0].geocode: a profile:CAP-CP:Location geocode is required (CAP-CP 0.4 rule 9)
// warning: info[0].senderName: should be given (CAP-CP 0.4 rule 14)
// valid: false
```

Signatures from a CA hierarchy, with a CRL:

```go
v, err := cap.NewVerifier(cap.VerifySettings{Roots: []string{rootPEM}, Require: true})
if err != nil {
	return err
}
crls, err := cap.ParseCRLs(crlPEM)
if err != nil {
	return err
}
v.Revoked = cap.CRLCheck(crls...)
verified, state, chain, err := v.VerifyChain(doc) // parse verified, never doc
```

`ExampleNewProfile`, `ExampleValidateSchema`, `ExampleParseEDXLDE` and
`ExampleRepairIndia` show the rest.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/cap

| Package | What it does |
|---|---|
| `cap` (module root) | `Alert` and its parts, `Parse` (CAP 1.2, 1.1, 1.0, no namespace), `ParseStrict`, `Marshal`, `MarshalJSONCAP`/`ParseJSON`, `Validate` and `Check` with `Options.LenientTime`, `Options.Profiles` and `Problem.Essential`; `Profile`, `NewProfile`, `RegisterProfile`, `ProfileByName`, `DetectProfiles`, `CAPCP`, `CAPCPWithLocations`, `IPAWS`, `India`, `RepairIndia`; `History`; `ValidateSchema` and `SchemaValidator`; references, date-times, `MostSevere`, `Expires`; `ParsePolygon`, `ParseCircle`, `CirclePolygon`, `Alert.GeoJSON`; `ParseFeed`, `ParseEDXLDE`, `WriteAtom`, `WriteEDXLDE` and `WriteEDXLDE2`; `CirclePolygonN`, `GeoJSONWith`; `Signer`, `Verifier` (`VerifyChain`, `Revoked`, `KeyUsages`), `CRLCheck`, `ParseCRLs`, `OCSPCheck` |
| `capxsd` | `Validate`, `Validator`, `Schema`: the OASIS CAP-v1.2.xsd file on the pure-Go engine github.com/cB-Sigma/xsd |
| `capnet` | `Poller`, `FeedHandler`, `Receiver`, `Pusher`, `NAADSStream`, `SplitStream` |
| `interop` (nested module, tests only) | cross-checks against github.com/tannerryan/cap; with `SIGMA_CAP_INTEROP=1`, xmlsec1 and xmlschema in Docker |

## Testing

```
go test -race ./...
go test -run XXX -fuzz FuzzReaders -fuzztime 1m   # every reader on arbitrary input
```

Tests carry `// Covers: SIG-...` comments: these are requirement IDs of
the SigmaM2M project's compliance report and have no meaning outside it.

`interop/` is a nested module with its own go.mod, so its dependency stays
out of this one. It runs with `go test ./...` inside it:

```
cd interop && go test ./...                         # tannerryan/cap
cd interop && SIGMA_CAP_INTEROP=1 go test ./...     # also xmlsec1 and xmlschema in Docker
SIGMA_CAP_LIVE=1 go test -run Live ./capnet         # the public NWS, Environment Canada, SACHET and NAADS sources
```

### Interop tested against

- github.com/tannerryan/cap v1.1.1 (`interop/`): our alerts parse and
  validate there without errors, its output parses and validates here, our
  RSA and ECDSA signatures verify there (self-signed, and chained through
  an intermediate to a root; ECDSA in the ASN.1 form it reads), and its CAP-CP 1.0 check agrees with ours on
  a complying and a failing alert.
- NDMA's SACHET feed, by hand on 2026-10-11 (not an automated test): 50
  live alerts were read with `Parse`; all passed `ValidateSchema` and
  `Validate`; the `India` profile reported their regional language codes
  (31) and areas given as a point in altitude and ceiling (21) or without
  geometry (23), and every alert still validated after `RepairIndia`. The
  live alerts are not kept in this repository.
- Real Canadian and US alerts, in `interop/`: the 33 sample alerts
  tannerryan/cap v1.1.1 ships in its testing directory (17 CAP-CP 0.4
  alerts from Environment Canada and the NAADS aggregator, 12 IPAWS
  alerts from the US National Weather Service, 4 OASIS examples) parse,
  pass `ValidateSchema` and the OASIS schema (`capxsd`) and have no
  errors under the profiles they declare. The profiles warn on some (NWS alerts without EAS-ORG; a NAADS
  alert carrying MinorChange on an Alert; a Spanish wireless text of 91
  characters).
- xmlsec1 (Alpine 3.20, Docker): our RSA and ECDSA signatures verify
  there and alerts it signs from a template verify here; a changed alert
  fails both. This test found that ECDSA values were written in ASN.1
  form, which XML Signature does not allow; fixed in v0.3.0.
- xmlschema 3.4.3 (Docker): our EDXL-DE 2.0 envelopes (embedded, base64
  and linked alerts) pass the OASIS EDXL-DE 2.0 CS02 schema set, and an
  envelope missing a required element fails it.
- Live sources, with `SIGMA_CAP_LIVE=1` (`capnet/live_test.go`). On
  2026-10-12: 25 alerts of the US NWS active feed, 6 CAP files of
  Environment Canada's datamart and 25 alerts of SACHET's RSS feed read
  through `capnet.Poller` or the datamart listing all passed
  `ValidateSchema`, the OASIS schema and their declared profiles (SACHET
  after `RepairIndia`), and a NAADS heartbeat arrived on the TCP stream
  in 34 seconds.

## Related repositories

- [cap-sim](https://github.com/cB-Sigma/cap-sim): a simulated CAP feed
  server and receiver, as a Go package and a command.

## Status

v0.x: the API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam. This module is not affiliated with or endorsed by OASIS;
see NOTICE.
