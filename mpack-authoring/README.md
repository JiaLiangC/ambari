<!-- Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements. See the NOTICE file distributed with this work for additional information regarding copyright ownership. The ASF licenses this file under the Apache License, Version 2.0. -->

# Mpack Authoring Validator

This local improvement module validates the working `mpack.ambari.apache.org/v2alpha1`
manifest contract before legacy projection or registration. It checks package
identity, service/component uniqueness, artifact source kinds, package-boundary
paths and deterministic canonical content digests. It does not deploy, register,
execute hooks, or grant a cluster target.

Run the CLI with `PYTHONPATH=src/main/python python3
src/main/python/mpack_authoring/validate_manifest.py path/to/manifest.json`.

`mpack_authoring.build.build_lock()` emits a deterministic offline lock with
the manifest digest and sorted file inventory. It records content hashes; it
does not fetch remote sources or execute package hooks.
