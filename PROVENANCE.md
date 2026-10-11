# Provenance

## How the code was written

Written in Go for SigmaM2M, a oneM2M platform, from the CAP 1.2 standard
and its schema. No code was ported or copied from another implementation.
Element names, cardinalities, enumerations and the date-time pattern are
facts every implementation must use; the code around them (the Go types,
the lenient reader for CAP 1.1 and 1.0, the problem list, the feed reader
and writer, the geometry and the simulator) is our own design. No text of
the standard or the schema is reproduced; comments cite clauses in our own
words.

The code began in SigmaM2M's CAP integration and moved to this module on
2026-10-06: `cap.go`, `geo.go`, `feed.go`, `sign.go` and the simulator
(now in the separate cap-sim module). Additive changes made in the move:
`NewVerifierSkipping` (formerly unexported), `Signer.Certificates`,
`Verifier.Trusted`, `Verifier.Required`, and `NewFeedAt` and
`NewReceiverAt` in the simulator. The tests of the codec, geometry, feeds
and signatures moved with it.

Before publication, error texts that named the integration's settings
were made generic where SigmaM2M does not depend on them. The signing
errors still name the settings `sign.key` and `sign.certificate`, which
are the JSON names of `SignSettings` under a `sign` object.

v0.2.0 (2026-10-11) added chain.go, ocsp.go, history.go, profile.go,
capcp.go, ipaws.go, india.go, schema.go, edxl.go and json.go with their
tests, written for
this module. The profile rules are restated in our own words from the
documents below; rule references cite their numbers or element names.
Lists of values (the CAP-CP event codes, the IPAWS media types, the
EAS-ORG originator codes) are facts copied as values, not prose.

## Sources

| Area (files) | Followed | Licence of the source | Taken |
|---|---|---|---|
| Message model, validation (cap.go) | OASIS CAP 1.2 (2010) and its XML schema | OASIS IPR policy (copyright OASIS Open) | facts only |
| Schema check (schema.go) | the content model of the CAP 1.2 schema (docs.oasis-open.org/emergency/cap/v1.2/CAP-v1.2.xsd), read 2026-10-11 | copyright OASIS Open; the file may be copied unmodified with its notice | facts only: element names, order, occurrences and types; the file is not shipped |
| Feeds (feed.go) | RFC 4287 (Atom), RSS 2.0 | IETF Trust, RSS Advisory Board | facts only |
| EDXL-DE (edxl.go) | OASIS EDXL-DE 1.0 (OASIS Standard, 1 May 2006) and EDXL-DE 2.0 (Committee Specification 02, 19 September 2013) | OASIS IPR policy | facts only: namespaces, element names and paths |
| Geometry (geo.go) | CAP 1.2 polygon and circle forms, RFC 7946 | as above | facts only |
| Signatures (sign.go, chain.go, ocsp.go) | W3C XML Signature, CAP 1.2's signature clause; RFC 5280 path validation and CRLs as done by Go's crypto/x509; RFC 6960 OCSP as done by golang.org/x/crypto/ocsp | W3C document licence, IETF Trust | facts only; the work is done by goxmldsig, crypto/x509 and x/crypto/ocsp |
| Reference chains (history.go) | CAP-CP 0.4 rule 12 and 1.0 rule 9, the IPAWS profile's references rule | as below | rule restated in our own words |
| CAP-CP (capcp.go) | Public Safety Canada, "CAP-CP Introduction and Rule Set Beta 0.4" (publicsafety.gc.ca/cnt/rsrcs/pblctns/capcp-ntro-rl-st/index2-en.aspx, page modified 2022-08-16), "Introduction and Rule Set 1.0" (…/index5-en.aspx, marked as a draft), "CAP-CP Event References 0.4" (…/capcp-vnt-rfrncs/index2-en.aspx, 2018-01-31; the event code list was checked against the page's table on 2026-10-11) and 1.0 (…/index4-en.aspx), "Location References" 0.4 and 1.0 Draft 2 | Crown copyright (Government of Canada) | rules restated in our own words; event codes as values |
| IPAWS (ipaws.go) | "Common Alerting Protocol, v. 1.2 USA Integrated Public Alert and Warning System Profile Version 1.0", OASIS Committee Specification 01, 13 October 2009 (docs.oasis-open.org/emergency/cap/v1.2/ipaws-profile/v1.0/cs01/) | OASIS IPR policy | rules restated in our own words |
| IPAWS warnings from outside the profile (ipaws.go) | 47 CFR 11.31 (EAS-ORG originator codes); US National Weather Service CAP v1.2 documentation, 2017-03-07 (BLOCKCHANNEL values); FEMA IPAWS-OPEN workshop slides, 2018 (CMAMlongtext 360 characters, WEAHandling values) | US government works | facts only; checks are warnings and name their source |
| India (india.go) | no published profile found (NDMA, C-DOT, TEC, TSDSI, TRAI searched 2026-10-11; ITU-T X.1303 is CAP 1.2); conventions observed in 50 alerts of the SACHET RSS feed (sachet.ndma.gov.in/cap_public_website/rss/rss_india.xml) read on 2026-10-11 | the alerts are public warnings; none is kept in this repository | facts only: language codes, the LGD geocode name, the "Polygon URL" parameter, points in altitude and ceiling; the TL to Telugu and PN to Punjabi mapping comes from the script of those blocks |

## v0.3.0

v0.3.0 (2026-10-12) added, written for this module: package `capxsd`
(the OASIS schema file on github.com/cB-Sigma/xsd, the same author's XSD
engine), package `capnet` (feed poller, feed server, push receiver and
sender, NAADS stream client), `WriteEDXLDE2` and `EDXLContent`
(edxl.go), `CirclePolygonN` and `GeoJSONWith` (geo.go), CAP 1.2 clause
numbers on base problems (cap.go), and the ECDSA signature value form of
XML Signature (ecdsa_xmldsig.go). Sources used for them:

| Part | Source | Use |
|---|---|---|
| capxsd | OASIS CAP-v1.2.xsd (docs.oasis-open.org/emergency/cap/v1.2/CAP-v1.2.xsd, fetched 2026-10-12) | shipped unmodified, see NOTICE |
| WriteEDXLDE2 | OASIS EDXL-DE 2.0 Committee Specification 02, its schema edxl-de-v2.0-wd11.xsd and supporting schemas (docs.oasis-open.org/emergency/edxl-de/v2.0/cs02/) | element names, order and required elements as facts; the schemas are interop test data |
| ECDSA signature values | RFC 6931 2.3.6 and W3C XML Signature 1.1 (the r and s integers side by side) | the form written by default; found by the xmlsec1 test, which refused the ASN.1 form goxmldsig writes |
| NAADS stream | the stream hosts and port Pelmorex gives NAAD System users (streaming1 and streaming2.naad-adna.pelmorex.com, 8080), and the stream itself as read on 2026-10-12 (documents back to back, heartbeats from "NAADS-Heartbeat" about once a minute) | facts |
| Poller paging | RFC 5005 (feed paging, rel="next") | facts |
| Live sources | api.weather.gov (US NWS), dd.weather.gc.ca (Environment Canada datamart), sachet.ndma.gov.in (India's SACHET RSS), the NAADS stream | read by the opt-in live tests; nothing kept |

## Other implementations

github.com/tannerryan/cap (BSD-2-Clause) was not read for the v0.1
code; it was found on 2026-10-06 during a search for existing CAP
libraries and is used in the test-only `interop` module to cross-check
output in both directions, signatures, chained signatures and CAP-CP 1.0
results, and to run the sample alerts it ships in its testing directory
(read from the Go module cache; not copied here). For v0.2.0 its README
and capcp.go (v1.1.1) were read on 2026-10-11 to compare which CAP-CP
rules each library checks and which features it offers; the CAP-CP rules
here were written from Public Safety Canada's pages, not from its code,
and no code was taken. Differences: this module also checks CAP-CP 0.4,
the event list (as a warning) and location code form, and compares
language variants block by block rather than as sets.

For v0.3.0, xmlsec1 (Alpine 3.20 package) and xmlschema 3.4.3 run in
Docker in the interop module as independent checkers of signatures and
schemas; neither was read for code.
## Test data

Every alert, sender, identifier, area, key, certificate and CRL in the
tests and examples is made up or generated at run time. Place names
(Pune district) and coordinates are used as ordinary sample content. The
India tests imitate the shape of SACHET alerts with made-up values; the
real SACHET alerts read on 2026-10-11 were checked by hand and are not
in the repository. The interop module reads tannerryan/cap's own sample
alerts from the Go module cache at test time.
