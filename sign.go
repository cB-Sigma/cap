package cap

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// XML signatures on CAP messages. CAP 1.2 (clause 3.3.2.1 of the
// standard, and its schema's closing wildcard in the XMLDSig namespace)
// lets an alert carry an enveloped XML Signature as the last child of the
// alert element. We sign the whole alert (Reference URI ""), with the
// enveloped-signature transform, exclusive canonicalisation and SHA-256,
// and put the signer's certificate in KeyInfo. RSA and ECDSA keys work.
//
// Signing uses github.com/russellhaering/goxmldsig (Apache-2.0) over
// github.com/beevik/etree (BSD-2-Clause).

// XMLDSigNamespace is the XML Signature namespace.
const XMLDSigNamespace = "http://www.w3.org/2000/09/xmldsig#"

// SignSettings configures signing of published messages.
type SignSettings struct {
	// Key is the PEM private key (PKCS #8, PKCS #1 RSA or SEC 1 EC).
	Key string `json:"key"`
	// Certificate is the PEM certificate of the key, followed by any
	// intermediates; the first goes in each signature's KeyInfo.
	Certificate string `json:"certificate"`
}

// VerifySettings configures checking of received signatures.
type VerifySettings struct {
	// Trusted are PEM certificates whose signatures are accepted; a
	// signature is valid only when its KeyInfo certificate is one of them
	// (and within its validity period).
	Trusted []string `json:"trusted"`
	// Require refuses alerts without a valid signature. Without it an
	// unsigned alert is accepted and marked "signature": "none"; a
	// signature that does not verify is refused unless acceptInvalid.
	Require bool `json:"require,omitempty"`
	// AcceptInvalid stores an alert whose signature does not verify,
	// marked "signature": "invalid", instead of refusing it (default
	// false). Risk: a forged or tampered alert is stored and can raise
	// alarms. Every such alert is also reported as a warning.
	AcceptInvalid bool `json:"acceptInvalid,omitempty"`
}

// Signer signs CAP documents.
type Signer struct {
	ctx   *dsig.SigningContext
	certs []*x509.Certificate // the signing certificate, then intermediates
}

// NewSigner reads a key and certificate chain.
func NewSigner(s SignSettings) (*Signer, error) {
	key, err := parseKey(s.Key)
	if err != nil {
		return nil, err
	}
	certs, err := parseCerts(s.Certificate)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("sign.certificate has no PEM CERTIFICATE block")
	}
	if !samePublicKey(key.Public(), certs[0].PublicKey) {
		return nil, errors.New("sign.key does not belong to the first certificate of sign.certificate")
	}
	der := make([][]byte, len(certs))
	for i, c := range certs {
		der[i] = c.Raw
	}
	ctx, err := dsig.NewSigningContext(key, der)
	if err != nil {
		return nil, err
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	return &Signer{ctx: ctx, certs: certs}, nil
}

// Sign returns the document with an enveloped signature appended to its
// alert element.
func (s *Signer) Sign(doc []byte) ([]byte, error) {
	d := etree.NewDocument()
	if err := d.ReadFromBytes(doc); err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	root := d.Root()
	if root == nil || root.Tag != "alert" || root.NamespaceURI() != Namespace {
		return nil, errors.New("signing: the document is not a CAP 1.2 alert")
	}
	if hasSignature(root) {
		return nil, errors.New("signing: the alert is already signed")
	}
	signed, err := s.ctx.SignEnveloped(root)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	d.SetRoot(signed)
	return d.WriteToBytes()
}

// Certificates is the signing certificate followed by its intermediates.
func (s *Signer) Certificates() []*x509.Certificate { return s.certs }

// Verifier checks CAP signatures against trusted certificates.
type Verifier struct {
	certs   []*x509.Certificate
	require bool
	// Now is the clock for certificate validity (tests); nil is time.Now.
	Now func() time.Time
}

// Trusted is the certificates whose signatures are accepted.
func (v *Verifier) Trusted() []*x509.Certificate { return v.certs }

// Required tells whether unsigned alerts are refused.
func (v *Verifier) Required() bool { return v.require }

// NewVerifier reads the trusted certificates.
func NewVerifier(s VerifySettings) (*Verifier, error) {
	var first error
	v := NewVerifierSkipping(s, func(_ int, err error) {
		if first == nil {
			first = err
		}
	})
	if first != nil {
		return nil, first
	}
	if len(v.certs) == 0 {
		return nil, errors.New("no trusted certificate is given")
	}
	return v, nil
}

// NewVerifierSkipping reads the trusted certificates, passing each entry
// that cannot be used to skip and leaving it out. With none left, every
// signed alert fails verification (it stays refused).
func NewVerifierSkipping(s VerifySettings, skip func(i int, err error)) *Verifier {
	v := &Verifier{require: s.Require}
	for i, p := range s.Trusted {
		cs, err := parseCerts(p)
		if err == nil && len(cs) == 0 {
			err = errors.New("no PEM CERTIFICATE block")
		}
		if err != nil {
			skip(i, fmt.Errorf("trusted certificate %d: %w", i, err))
			continue
		}
		v.certs = append(v.certs, cs...)
	}
	return v
}

// Signature states.
const (
	SignatureValid = "valid"
	SignatureNone  = "none"
)

// ErrUnsigned is an unsigned alert where signatures are required.
var ErrUnsigned = errors.New("the alert is not signed and signatures are required")

// Verify checks the document's signature. It returns the verified alert
// element as a document of its own (signature removed): callers parse
// that, never the original bytes, so content outside the signed element
// cannot be slipped in. An unsigned document is returned as it is with
// state "none" unless signatures are required.
func (v *Verifier) Verify(doc []byte) (verified []byte, state string, err error) {
	d := etree.NewDocument()
	if err := d.ReadFromBytes(doc); err != nil {
		return nil, "", fmt.Errorf("the CAP document is not well-formed XML: %w", err)
	}
	root := d.Root()
	if _, isCAP := Version(rootSpace(root)); root == nil || root.Tag != "alert" || !isCAP {
		return nil, "", fmt.Errorf("not a CAP alert (root element must be alert in a CAP namespace such as %s)", Namespace)
	}
	if !hasSignature(root) {
		if v.require {
			return nil, "", ErrUnsigned
		}
		return doc, SignatureNone, nil
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: v.certs})
	vc.Clock = dsig.NewFakeClockAt(now())
	el, err := vc.Validate(root)
	if err != nil {
		return nil, "", fmt.Errorf("the alert's signature does not verify: %w", err)
	}
	out := etree.NewDocument()
	out.SetRoot(el)
	b, err := out.WriteToBytes()
	if err != nil {
		return nil, "", err
	}
	return append([]byte(xmlHeader), b...), SignatureValid, nil
}

const xmlHeader = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"

func rootSpace(root *etree.Element) string {
	if root == nil {
		return ""
	}
	return root.NamespaceURI()
}

func hasSignature(root *etree.Element) bool {
	for _, c := range root.ChildElements() {
		if c.Tag == "Signature" && c.NamespaceURI() == XMLDSigNamespace {
			return true
		}
	}
	return false
}

func parseKey(p string) (crypto.Signer, error) {
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return nil, errors.New("sign.key is not a PEM private key")
	}
	var k any
	var err error
	switch b.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(b.Bytes)
	default:
		return nil, fmt.Errorf("sign.key: PEM block %q is not a private key", b.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("sign.key: %w", err)
	}
	switch k := k.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	default:
		return nil, errors.New("sign.key must be an RSA or ECDSA key")
	}
}

func parseCerts(p string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(p)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out, nil
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
}

func samePublicKey(a, b crypto.PublicKey) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(eq)
	return ok && e.Equal(b)
}
