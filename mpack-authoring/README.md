<!-- Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements. See the NOTICE file distributed with this work for additional information regarding copyright ownership. The ASF licenses this file under the Apache License, Version 2.0. -->

# Mpack Authoring Validator

This local improvement module validates and compiles the working
`mpack.ambari.apache.org/v2alpha1` manifest contract before legacy projection or
registration. It accepts JSON and YAML, checks package identity,
service/component uniqueness, artifact source kinds, package-boundary paths,
runtime capabilities and deterministic canonical content digests. It does not
deploy, register, execute hooks, or grant a cluster target.

Run validation with `PYTHONPATH=src/main/python python3
src/main/python/mpack_authoring/validate_manifest.py path/to/manifest.yaml`.
Use `--compile` for the normalized model and `--export output.zip` for a
deterministic offline package. Supplying `--signing-key key-file` writes an
external HMAC-SHA256 signature beside the package; the key is never archived.

`mpack_authoring.build.build_lock()` emits a deterministic file inventory with
the manifest digest and sorted content hashes. The compiler additionally emits
artifact and dependency locks, provenance, and a legacy service metadata
projection. It does not fetch remote sources or execute package hooks.

The machine-readable schema is under `schema/manifest-v2alpha1.json`, with a
minimal offline fixture under `fixtures/minimal/manifest.json`.

The conformance fixtures under `fixtures/conformance/` can be validated with
`mpack_authoring.conformance.validate_fixture_directory`; they never contact a
cluster or execute an adapter.
