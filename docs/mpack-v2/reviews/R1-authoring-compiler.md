<!--
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements. See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to you under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# R1 Authoring Compiler

The authoring module now has a deterministic compiler boundary in
`mpack-authoring/src/main/python/mpack_authoring/compiler.py`.

Implemented behavior:

- JSON and YAML source loading with the same v2alpha1 canonical digest.
- Semantic package reference checks for configuration files, profile artifact
  references, known adapter capabilities, and ServiceGroup identity rejection.
- Sorted local artifact lock entries and named dependency lock entries.
- A compatibility projection containing existing service/component names only;
  it does not create package or ServiceGroup identities.
- Reproducible offline ZIP export with fixed timestamps, normalized metadata,
  payload files, and provenance. Remote URLs are recorded as references and
  are never fetched by the compiler.
- Optional external HMAC-SHA256 package signatures. Secret key material is read
  from the caller and is not included in the package or compiler output.
- Structured diagnostics for schema, capability, dependency, target and package
  content failures.

Focused coverage is in `test_compiler.py` and covers YAML compilation,
deterministic export/signature bytes, semantic capability failure and explicit
ServiceGroup rejection. Runtime adapter execution, server operation persistence,
and live platform conformance remain outside this offline compiler boundary.

Validation evidence from this worktree: the complete `mpack-authoring` Python
suite passes 24 tests, and `py_compile` succeeds for every authoring module.
