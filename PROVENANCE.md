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

## Sources

| Area (files) | Followed | Licence of the source | Taken |
|---|---|---|---|
| Message model, validation (cap.go) | OASIS CAP 1.2 (2010) and its XML schema | OASIS IPR policy (copyright OASIS Open) | facts only |
| Feeds (feed.go) | RFC 4287 (Atom), RSS 2.0 | IETF Trust, RSS Advisory Board | facts only |
| Geometry (geo.go) | CAP 1.2 polygon and circle forms, RFC 7946 | as above | facts only |
| Signatures (sign.go) | W3C XML Signature, CAP 1.2's signature clause | W3C document licence | facts only; the work is done by goxmldsig |

## Other implementations

github.com/tannerryan/cap (BSD-2-Clause) was not read for this code; it
was found on 2026-10-06 during a search for existing CAP libraries and is
used only in the test-only `interop` module to cross-check output in both
directions and signatures.

## Test data

Every alert, sender, identifier, area, key and certificate in the tests
and examples is made up or generated at run time. Place names (Pune
district) and coordinates are used as ordinary sample content.
