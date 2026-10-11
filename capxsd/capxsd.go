// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package capxsd validates CAP 1.2 documents against the OASIS schema
// itself, CAP-v1.2.xsd, shipped unmodified in this package with its OASIS
// copyright notice, on the pure-Go XSD engine github.com/cB-Sigma/xsd.
//
// It complements cap.ValidateSchema, which checks the schema's content
// model encoded as facts: this one applies every rule of the schema
// file, the sent pattern and the xs:dateTime value space included. Pass it
// as an extra validator:
//
//	v, err := capxsd.Validator()
//	...
//	err = cap.ValidateSchema(doc, v)
//
// The XML signature element is allowed by the schema with lax processing,
// so a signed alert validates without the XML Signature schema.
package capxsd

import (
	"embed"
	"errors"
	"fmt"
	"sync"

	"github.com/cB-Sigma/cap"
	"github.com/cB-Sigma/xsd"
)

// SchemaFile is the name of the embedded OASIS schema.
const SchemaFile = "CAP-v1.2.xsd"

// SchemaSHA256 is the SHA-256 of the embedded file as OASIS publishes it at
// https://docs.oasis-open.org/emergency/cap/v1.2/CAP-v1.2.xsd.
const SchemaSHA256 = "b7798ef25868b068c97b268bda02d067c7d4ba9373adc5638bf37105804ee723"

//go:embed CAP-v1.2.xsd
var files embed.FS

var (
	once   sync.Once
	schema *xsd.Schema
	errLd  error
)

// Schema is the loaded OASIS schema (loaded once; safe for concurrent use).
func Schema() (*xsd.Schema, error) {
	once.Do(func() { schema, errLd = xsd.Load(files, SchemaFile) })
	return schema, errLd
}

// Validate checks doc against the OASIS schema and returns every issue as
// a cap.ValidationError (rule "XSD (CAP-v1.2.xsd)"), or nil.
func Validate(doc []byte) error {
	s, err := Schema()
	if err != nil {
		return fmt.Errorf("capxsd: loading %s: %w", SchemaFile, err)
	}
	err = s.Validate(doc)
	if err == nil {
		return nil
	}
	var xe *xsd.Errors
	if !errors.As(err, &xe) {
		return cap.ValidationError{{Field: "document", Issue: err.Error(), Rule: "XSD (" + SchemaFile + ")"}}
	}
	var ps cap.ValidationError
	for _, is := range *xe {
		field := is.Path
		if field == "" {
			field = "document"
		}
		msg := is.Msg
		if is.Line > 0 {
			msg = fmt.Sprintf("line %d: %s", is.Line, msg)
		}
		ps = append(ps, cap.Problem{Field: field, Issue: msg, Rule: "XSD (" + SchemaFile + ")"})
	}
	return ps
}

// Validator is Validate as a cap.SchemaValidator, after loading the schema
// once so that a broken build fails here rather than per document.
func Validator() (cap.SchemaValidator, error) {
	if _, err := Schema(); err != nil {
		return nil, err
	}
	return cap.SchemaValidatorFunc(Validate), nil
}
