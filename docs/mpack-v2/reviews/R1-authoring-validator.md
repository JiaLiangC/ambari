<!-- Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements. See the NOTICE file distributed with this work for additional information regarding copyright ownership. The ASF licenses this file under the Apache License, Version 2.0. -->

# R1 Local Improvement: Authoring Validator

Base: local M2 candidate `b72ade8fcfd553ff182f3d34fe63c0903616005a`.

The new `mpack-authoring` module implements the first machine-readable authoring
boundary from `manifest-spec.md`: v2alpha1/kind detection, package and runtime
identity validation, artifact source/path containment, duplicate service and
component rejection, runtime adapter/version and capability declarations,
cardinality checks, and deterministic canonical SHA-256 content identity. A
small CLI emits a machine-readable validity/digest result and performs no
deployment or registration.

The module also emits a deterministic offline file lock containing the
manifest digest, sorted inventory, sizes and SHA-256 content hashes. Remote
sources are not fetched and package hooks are never executed.

The runtime module defines additive `ServiceRef`, `PackageRef` and
`RuntimeContext` values. Effective capabilities are the intersection of package,
adapter, target and policy declarations; unsupported requests fail explicitly.
The context keeps numeric cluster and service-name identity as the authority.

Validation failures are also exposed as structured diagnostics with stable
category, severity, path, retryability and correction fields. The current
authoring categories begin with `SCHEMA_INVALID`; later adapter and dependency
layers can add the categories defined by `contracts.md` without changing the
manifest reader API.

The operation module adds a non-mutating plan layer. It validates each requested
capability against the scoped runtime context and emits ordered steps with
preconditions and effects; it does not execute commands or claim readiness.

The same local module now includes configuration provenance and redacted
`SecretRef` values, a versioned dependency adapter boundary using the existing
`ServiceRef`, explicit operation recovery transitions including `UNKNOWN`, and
runtime profile capability declarations. These are additive contracts and do
not create a second cluster, service, host-ownership, or dependency authority.

Focused tests are included under `mpack-authoring/src/test/python`. Validation
will be run with the rest of the local improvement batch after the current
implementation topics are complete.

## Final R1 validation

After the implementation batches, the authoring suite passed 13 tests, the
instance-manager suite passed 23 tests, and Python syntax compilation passed
for the changed authoring, instance-manager and common helper modules. The
validator fix allowing numeric dotted package versions is included in the
completion commit following this report.
