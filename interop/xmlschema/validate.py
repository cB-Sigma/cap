# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# Validates the XML document on standard input against a schema with
# xmlschema (https://github.com/sissaschool/xmlschema, MIT): the
# independent XSD processor of the cap interop tests. Prints "valid" or
# the reasons, one per line.
import sys

import xmlschema

schema_path = sys.argv[1]
locations = {"http://www.w3.org/XML/1998/namespace": "/schemas/w3c/xml.xsd",
             "urn:oasis:names:tc:emergency:cap:1.2": "/cap/CAP-v1.2.xsd"}
schema = xmlschema.XMLSchema10(schema_path, locations=locations, allow="local")
doc = sys.stdin.buffer.read()
errors = list(schema.iter_errors(doc.decode("utf-8")))
if not errors:
    print("valid")
for e in errors:
    print("invalid:", str(e.reason).replace("\n", " "), "at", e.path)
