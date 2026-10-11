// Test-only module: checks github.com/cB-Sigma/cap against github.com/tannerryan/cap, an
// independent CAP 1.2 implementation. Nothing imports it.
module github.com/cB-Sigma/cap/interop

go 1.27.1

replace github.com/cB-Sigma/cap => ../

require (
	github.com/cB-Sigma/cap v0.0.0-00010101000000-000000000000
	github.com/tannerryan/cap v1.1.1
)

require (
	github.com/beevik/etree v1.8.1 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/russellhaering/goxmldsig v1.6.1 // indirect
)
