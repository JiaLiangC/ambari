<!-- Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements. See the NOTICE file distributed with this work for additional information regarding copyright ownership. The ASF licenses this file under the Apache License, Version 2.0. -->

# R1 Local Improvement Status

This matrix maps the requirements in `architecture.md`, `contracts.md`,
`manifest-spec.md`, and `reference-examples.md` to the current local worktree.
It distinguishes contract/tooling work from a real Ambari runtime integration.

| Requirement | Status | Evidence or remaining work |
| --- | --- | --- |
| Community V2 registry, package metadata, Blueprint projection, Agent context and administration UI | Complete | W1 batch reports and M2 candidate |
| Manifest v2alpha1 identity, package-boundary and profile validation | Complete for local tooling | `mpack-authoring` validator, schema and fixtures |
| Deterministic content lock and package digest | Complete for local tooling | `mpack_authoring.build` lock output |
| Structured authoring diagnostics | Partial | `SCHEMA_INVALID` exists; runtime/dependency/authorization categories still need server integration |
| Scoped runtime context and capability intersection | Complete for local contract | `RuntimeContext`; no real adapter execution yet |
| Non-mutating operation planning | Complete for local contract | `plan_operation`; no persisted Ambari operation yet |
| Configuration provenance and secret references | Partial | Local `ConfigValue`/`SecretRef`; server persistence and effective-generation flow remain |
| Dependency adapter and binding snapshots | Partial | Local protocol boundary; shared platform UUID/revision/authorization/fencing integration remains |
| Operation recovery and UNKNOWN outcomes | Partial | Local transition model; request/task/workflow persistence and replay remain |
| Host/systemd runtime adapter | Not implemented | Requires real target execution, observation and fencing |
| OCI/container runtime adapter | Not implemented | Requires isolated runtime implementation and evidence |
| Kubernetes workload adapter | Not implemented | Requires Kubernetes client/runtime and conformance fixtures |
| External database observation adapter | Not implemented | Requires credential-scoped connection/observation implementation |
| Generic schema/capability/plan/operation UI and CLI | Not implemented | Current UI covers legacy package administration only |
| Health, metrics, logs and alerts observation model | Not implemented | Requires server telemetry and scoped projections |
| Adoption, ownership, detach, delete and retained-data lifecycle | Partial | Existing package deletion guards exist; full R1 lifecycle protocol remains |
| Upgrade, migration and durable package deployment history | Partial | Current catalog/upgrade wiring exists; full package deployment history remains |
| Authoring compiler, YAML input and offline artifact export | Partial | JSON validation/lock exists; compiler/export pipeline remains |
| HTTP, OCI, Kubernetes, external DB, cross-cluster and AI repair fixtures | Not implemented | Listed in `reference-examples.md`; executable conformance fixtures remain |
| RPM/DEB package and runtime acceptance | Partial | Source and Python coverage exists; RPM builder and live runtime evidence remain |

Remote publication is intentionally absent from this matrix and the active plan;
the local M2 candidate is the current improvement baseline.

