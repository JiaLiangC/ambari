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
| Structured authoring diagnostics | Complete for local tooling | Stable schema, capability, dependency, plan, target, authorization, outcome and package-content codes; server responses preserve the same categories |
| Scoped runtime context and capability intersection | Complete | `RuntimeContext` plus Agent `RuntimeAdapter` context validation preserve cluster/service/component identity |
| Non-mutating operation planning | Complete for local/runtime boundary | `plan_operation` and Agent adapter plans; durable Ambari request/task persistence remains an integration limitation |
| Configuration provenance and secret references | Complete for server boundary | `MpackConfigurationResolver` validates types/defaults, records source/generation, redacts `SecretReference`, and exposes reload/restart/migration effects |
| Dependency adapter and binding snapshots | Complete for protocol boundary | `DependencyAdapter` validates shared binding UUID/provider identity, authorization, revision, snapshot and fencing envelopes; provider platform remains external |
| Operation recovery and UNKNOWN outcomes | Partial | Agent cancellation, idempotency keys, UNKNOWN and journal recovery exist; request/task/workflow persistence and replay remain outside this worktree |
| Host/systemd runtime adapter | Complete for controlled Agent boundary | `RuntimeAdapter.py` implements discover/plan/apply/observe/verify/recover and cancellation; live systemd evidence is unavailable |
| OCI/container runtime adapter | Complete for controlled Agent boundary | Controlled argv adapter and capability checks are implemented; live engine evidence is unavailable |
| Kubernetes workload adapter | Complete for controlled Agent boundary | Controlled kubectl adapter and capability checks are implemented; live cluster evidence is unavailable |
| External database observation adapter | Complete for observation boundary | Observation-only adapter and UNKNOWN handling are implemented; credential-scoped live connection is unavailable |
| Generic schema/capability/plan/operation UI and CLI | Complete for local boundary | React runtime view/API and authoring CLI expose schema, capabilities, plans, operations and recovery actions; server resource-provider endpoints remain a platform integration |
| Health, metrics, logs and alerts observation model | Complete for local UI model | Common observation normalization and stale/UNKNOWN display cover all four kinds; server telemetry providers remain external |
| Adoption, ownership, detach, delete and retained-data lifecycle | Complete for Blueprint boundary | `MpackReference` persists owner/state/generation/retention and `MpackLifecycleManager` enforces transitions and fail-closed purge |
| Upgrade, migration and durable package deployment history | Partial | Current catalog/upgrade wiring exists; full package deployment history remains |
| Authoring compiler, YAML input and offline artifact export | Complete for offline tooling | Compiler emits normalized model, artifact/dependency locks, legacy projection, deterministic ZIP, provenance and optional HMAC signature |
| HTTP, OCI, Kubernetes, external DB, cross-cluster and AI repair fixtures | Partial | Offline manifest fixtures now cover the first five inputs; executable runtime/e2e and AI repair loop remain |
| RPM/DEB package and runtime acceptance | Partial | Instance-manager tarball and DEB build pass; `rpmbuild`/`rpm` are unavailable and live runtime evidence remains |

Remote publication is intentionally absent from this matrix and the active plan;
the local M2 candidate is the current improvement baseline.
