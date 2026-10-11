# Changelog

## v0.3.0 (2026-10-12)

Backwards compatible except for the ECDSA signature value form (see
Fixed), which has an option to keep the old form.

### Added

- Package `capxsd`: validation against the OASIS CAP-v1.2.xsd schema
  itself, shipped unmodified, on github.com/cB-Sigma/xsd (`Validate`,
  `Validator` as a `SchemaValidator`, `Schema`). It agrees with
  `ValidateSchema` case by case in the tests, and the 33 real alerts of
  the interop corpus pass it.
- Package `capnet`, the network roles: `Poller` (conditional GETs, linked
  documents with `MaxLinked`, RFC 5005 paging with `MaxPages`,
  de-duplication by sender, identifier and sent, `History` fed, `Run`,
  `Forget`); `FeedHandler` (an http.Handler serving Atom embedded or
  linked, RSS 2.0, EDXL-DE 1.0 or 2.0, with ETag, Last-Modified and 304,
  documents byte for byte, `Publish`, `Remove`, `Prune`); `Receiver` (an
  http.Handler for pushed alerts: bearer token, signature, schema,
  validation and profiles, then `Deliver`); `Pusher` (POST with retries
  and Retry-After); `NAADSStream` and `SplitStream` for the TCP stream of
  Canada's NAAD System, with heartbeats and reconnection.
- `WriteEDXLDE2` and `EDXLContent`: EDXL-DE 2.0 envelopes with embedded,
  base64 or linked alerts, accepted by the OASIS 2.0 schema;
  `Distribution.Expires` (read from either version too).
- `CirclePolygonN` and `Alert.GeoJSONWith`: circles with any number of
  sides.
- Base validation problems carry their CAP 1.2 clause in `Problem.Rule`
  ("CAP 1.2 3.2.1" to "3.2.4"); `Problem.String` is unchanged.
- `SignSettings.ECDSAEncoding`: "raw" (default) or "der".
- Opt-in live tests (`SIGMA_CAP_LIVE=1`) against the US NWS feed,
  Environment Canada's datamart, India's SACHET feed and the NAADS
  stream; Docker interop tests (`SIGMA_CAP_INTEROP=1`) with xmlsec1 and
  xmlschema.

### Fixed

- ECDSA signatures are now written with the r and s integers side by
  side, as XML Signature requires, instead of the ASN.1 sequence Go
  produces; xmlsec1 refused the old form. Both forms verify here. Set
  `ECDSAEncoding: "der"` for receivers built on goxmldsig (such as
  tannerryan/cap), which read only the ASN.1 form. RSA is unaffected.
- `ParseEDXLDE` reads an EDXL-DE 2.0 envelope's combinedConfidentiality,
  which 2.0 keeps inside the descriptor.

## v0.2.0 (2026-10-11)

Added, all backwards compatible: existing functions keep their
signatures, and alerts, feeds and signatures that were accepted are
still accepted.

- Certificate chains: `VerifySettings.Roots`, `Intermediates` and
  `SystemRoots` accept a signature whose KeyInfo certificate chains to a
  trusted CA (intermediates from KeyInfo or the settings), besides the
  pinned `Trusted` certificates. `Verifier.VerifyChain` returns the chain;
  `Verifier.Roots`. A chained signing certificate must allow digital
  signatures when it states key usages; `Verifier.KeyUsages` can require
  extended key usages.
- Revocation: `Verifier.Revoked`, a hook asked about every accepted chain
  (pinned certificates as a chain of one); `CRLCheck` and `ParseCRLs`
  build one from certificate revocation lists checked against their
  issuer; `OCSPCheck` and `OCSPOptions` ask each certificate's OCSP
  responder (soft or strict, leaf only or the whole chain); `ErrRevoked`.
  New dependency: golang.org/x/crypto (for OCSP).
- `History`: whether an Update or Cancel references every message of its
  chain still in effect (the CAP-CP and IPAWS rule a single message
  cannot show), with a `Profile` wrapper.
- `CAPCPWithLocations`: CAP-CP with location codes checked against a
  list the application loads.
- `WriteEDXLDE`: EDXL-DE 1.0 envelopes out, embedding documents byte for
  byte so signatures survive; `Distribution.Confidentiality`.
- `ParseStrict`: refuse documents that fail `ValidateSchema`.
- Warnings (not errors, so accepted alerts stay accepted) for a derefUri
  that is not base64, a digest that is not a SHA-1 hash, a size that is
  not a number and a ceiling below the altitude.
- Profiles: the `Profile` interface, `NewProfile`, `RegisterProfile`,
  `ProfileByName`, `ProfileNames`, `DetectProfiles`, and
  `Options.Profiles`. Built in: `CAPCP` (Canadian profile, 0.4 and 1.0,
  with the event list `CAPCPEvents`), `IPAWS` (US IPAWS profile 1.0,
  `IPAWSMediaTypes`) and `India` (the conventions of NDMA's SACHET feed,
  as warnings; no official Indian profile is published), with
  `RepairIndia`, `IndianLanguageTag`, `PolygonURL` and `LGDDistrictCode`.
- `Problem` gains `Profile`, `Rule` and `Warning`; `Alert.Check` lists
  warnings as well as errors, and `Validate` fails only on errors.
  `Problem.String` names the profile and rule when set.
- Schema check: `ValidateSchema` checks a document against the CAP 1.2
  schema's content model (order, occurrence, unknown elements,
  attributes, simple types, signature placement), with
  `SchemaValidator`/`SchemaValidatorFunc` to add a full XSD engine.
- EDXL-DE: `ParseEDXLDE` and `Distribution` read EDXL-DE 1.0 and 2.0
  envelopes (embedded, base64 and linked CAP content);
  `EDXLDE10Namespace`, `EDXLDE20Namespace`. `ParseFeed` accepts an
  envelope.
- JSON with CAP element names: `Alert.MarshalJSONCAP` and `ParseJSON`.
- A fuzz test over every reader; interop tests for chained signatures
  and CAP-CP 1.0 against github.com/tannerryan/cap.

Changed: `ParseFeed`'s error for an unknown root names EDXL-DE among the
accepted forms.

## v0.1.0, v0.1.1 (2026-10-11)

First releases: CAP 1.2 alerts (CAP 1.1 and 1.0 read as 1.2), validation, Atom and RSS
feeds, GeoJSON areas, enveloped XML signatures against pinned
certificates; moved from SigmaM2M (see PROVENANCE.md).
