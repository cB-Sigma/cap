# cap

OASIS Common Alerting Protocol 1.2 in pure Go: the alert model, reading and validation, XML signatures, area geometry and alert feeds.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/cap.svg)](https://pkg.go.dev/github.com/cB-Sigma/cap) [![test](https://github.com/cB-Sigma/cap/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/cap/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.27.1-00ADD8.svg)](go.mod)

It reads CAP 1.2 and also takes CAP 1.1 and 1.0, lists every validation
problem instead of stopping at the first, signs and verifies enveloped XML
signatures against pinned certificates, converts areas to GeoJSON, and
reads and writes the Atom and RSS feeds that carry or link alerts. It was
written for SigmaM2M, a oneM2M platform, as the protocol half of its CAP
feed ingest, publishing and public warning integrations.

## Features

| Feature | Status |
|---|---|
| CAP 1.2 read and write | yes |
| CAP 1.1, 1.0, no namespace | read as 1.2; `Alert.Version` records the original |
| Validation | required elements, enumerations, date-time form (strict or lenient), references, identifier characters, scope conditions, polygon, circle, altitude and ceiling; `Problem.Essential` tells which problems leave an alert unusable |
| XML signatures | enveloped, exclusive C14N, SHA-256, RSA or ECDSA; verification pins the KeyInfo certificate (no chain building) |
| Feeds | Atom (RFC 4287) with embedded or linked alerts, RSS 2.0, a bare alert in; Atom out |
| GeoJSON (RFC 7946) | areas as a FeatureCollection; circles as 32-segment polygons |
| CAP-CP and other national profiles | no |

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

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/cap

| Package | What it does |
|---|---|
| `cap` (module root) | `Alert` and its parts, `Parse` (CAP 1.2, 1.1, 1.0, no namespace), `Marshal`, `Validate` with `Options.LenientTime` and `Problem.Essential`, references, date-times, `MostSevere`, `Expires`; `ParsePolygon`, `ParseCircle`, `CirclePolygon`, `Alert.GeoJSON`; `ParseFeed` and `WriteAtom`; `Signer` and `Verifier` |
| `interop` (nested module, tests only) | cross-checks against github.com/tannerryan/cap |

## Testing

```
go test -race ./...
```

Tests carry `// Covers: SIG-...` comments: these are requirement IDs of
the SigmaM2M project's compliance report and have no meaning outside it.

`interop/` is a nested module with its own go.mod, so its dependency stays
out of this one. It runs with `go test ./...` inside it:

```
cd interop && go test ./...
```

### Interop tested against

- github.com/tannerryan/cap v1.1.1 (`interop/`): our alerts parse and
  validate there without errors, its output parses and validates here, and
  our RSA and ECDSA signatures verify there.
- No national alerting authority's live feed has been read by these tests.

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
