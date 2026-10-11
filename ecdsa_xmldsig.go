// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/base64"
	"io"
	"math/big"
	"strings"

	"github.com/beevik/etree"
)

// ECDSA signature values in XML Signature are the integers r and s, each
// as wide as the curve's order, side by side (RFC 6931 2.3.6; XML
// Signature 1.1 6.4.3). Go's crypto.Signer, and so goxmldsig, produce and
// expect an ASN.1 sequence instead. rawECDSA signs in the XML form;
// ecdsaRawToDER turns a received XML-form value into the ASN.1 form
// before goxmldsig checks it, so both forms verify.

type rawECDSA struct{ k *ecdsa.PrivateKey }

func (r rawECDSA) Public() crypto.PublicKey { return r.k.Public() }

func (r rawECDSA) Sign(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	R, S, err := ecdsa.Sign(rand, r.k, digest)
	if err != nil {
		return nil, err
	}
	size := (r.k.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*size)
	R.FillBytes(out[:size])
	S.FillBytes(out[size:])
	return out, nil
}

// ecdsaRawToDER rewrites, in place, the SignatureValue of an ECDSA XML
// signature under root from r||s to ASN.1 when it is not ASN.1 already.
// The SignatureValue is outside what the signature covers, so this changes
// nothing that is checked.
func ecdsaRawToDER(root *etree.Element) {
	for _, sig := range root.ChildElements() {
		if sig.Tag != "Signature" {
			continue
		}
		si := sig.SelectElement("SignedInfo")
		sv := sig.SelectElement("SignatureValue")
		if si == nil || sv == nil {
			continue
		}
		sm := si.SelectElement("SignatureMethod")
		if sm == nil || !strings.Contains(strings.ToLower(sm.SelectAttrValue("Algorithm", "")), "ecdsa") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(sv.Text()), ""))
		if err != nil || len(raw) == 0 || len(raw)%2 != 0 {
			continue
		}
		var probe struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(raw, &probe); err == nil && len(rest) == 0 {
			continue // already ASN.1
		}
		h := len(raw) / 2
		der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:h]), new(big.Int).SetBytes(raw[h:])})
		if err != nil {
			continue
		}
		sv.SetText(base64.StdEncoding.EncodeToString(der))
	}
}
