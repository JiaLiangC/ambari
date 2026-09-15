<!---
   Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements. See the NOTICE file distributed with
   this work for additional information regarding copyright ownership.
   The ASF licenses this file to You under the Apache License, Version 2.0
   (the "License"); you may not use this file except in compliance with
   the License. You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
--->

# Mpack V2 implementation status

## Current delivery - 2026-09-15

This branch is an implementation candidate, not a production-readiness claim. The
architecture review and current product boundary are recorded in
[architecture](architecture.md); executable API and evidence rules are in
[contracts](contracts.md). The original line-by-line audit remains in the
[independent review](reviews/independent-architecture-review-2026-09-10.md).

The current change set converges the design around supported host software:

| Area | Current state |
| --- | --- |
| Runtime scope | OCI and Kubernetes adapters, schema entries, fixtures and tests removed. |
| Lifecycle scope | Core lifecycle plus separately authorized purge; upgrade/reload/handoff/data-procedure/abandon APIs removed. |
| Removal evidence | Typed, profile-independent management/runtime/data/ownership dispositions implemented and consumed by Server. |
| Installation UX | React dialog submits a stable UUID install plan; Server validates and coordinates service/component/host/config/install writes. |
| Cohesion | Artifact fetching, install coordination and removal evidence extracted; file/external profiles no longer initialize systemd units; readiness is polymorphic. |
| Store | Independent future system; Ambari retains signed registry/file/approved-URL import and cluster authority. |

## Runtime matrix

| Profile | Provision and configure | Process actions | Removal | Evidence |
| --- | --- | --- | --- | --- |
| `host.systemd/v1` | OS prerequisite, user/group, directories, immutable artifacts and typed config generation | start, stop, restart, local health | uninstall retains data; purge exact retained paths | unit/load/fragment, PID/invocation, job, health and common dispositions |
| `host.files/v1` | CLIENT artifacts, modes and config pointer | none | uninstall withdraws publication; purge exact retained paths | file hashes/modes, pointer readiness and common dispositions |
| `external.database/v1` | local registration after signed non-root identity probe | none | unregister only; no remote mutation | provider identity digest and external dispositions |

Unsupported lifecycle declarations fail authoring or Agent capability checks. Missing,
wrongly typed or inconsistent release evidence remains `PENDING` and cannot authorize
host component, service or catalog deletion.

## Local verification

Executed in this workspace after the convergence changes:

| Layer | Command scope | Result |
| --- | --- | --- |
| Authoring | `unittest discover` for `mpack-authoring/src/test/python` | 47 passed |
| Agent/common | host, files, external and handler unit/integration fixtures | 45 passed, 2 skipped environment-dependent cases |
| React | package lifecycle and install dialog target tests | 12 passed |
| React build | TypeScript project build and Vite production bundle | passed; existing Sass and bundle-size warnings remain |
| Server target tests | fetch/import, install coordination, removal evidence, Mpack DAO, task binding, cluster API and request/service authorization | 111 passed, 3 fixture-dependent tests skipped; RAT/checkstyle passed |

The skipped Agent/Server cases require root/non-root process, Java-generated secrets or
an externally generated signed package fixture. An unfiltered Maven lifecycle also ran
1,194 Server Python tests and stopped on one pre-existing Python 3.12 import error:
`VICTORIAMETRICS/service_advisor.py` imports the removed standard-library `imp` module.
No live browser, Store, Redis, PostgreSQL, systemd Agent deployment, multi-server setup
or production DB migration was used for these local results.

## Implemented safety properties

- Deterministic authoring inventory and closed source schema.
- Signed package verification before catalog publication.
- Approved URL origins/path prefixes, no redirects/query credentials and bounded
  transfer/archive expansion.
- Package-row locking, DB constraints and startup reconciliation for catalog changes.
- Server-owned target incarnation and task-bound package/config/host identity.
- Agent-local serialization, atomic receipt/config publication and fail-closed UNKNOWN.
- Native readiness/inactivity checks rather than command exit-code success.
- Data retention by default; purge requires separate permission and exact inode evidence.
- Browser performs no partial installation writes.

## Open gates

1. Exercise `MpackInstallCoordinator` with real resource providers and injected failure
   after each intermediate record, including concurrent multi-server submission.
2. Execute a signed HTTP and Redis golden path on disposable Ambari Server/Agent/systemd
   hosts with authorization denial and lost-response cases.
3. Verify fresh and upgraded supported production database schemas and catalog/resource
   reference behavior.
4. Deliver installed authoring commands and a clean-environment CI example.
5. Design and implement publisher governance and the signed registry index in the
   independent Store repository.

No Store availability, AI output, manifest field or operator confirmation can replace
Ambari authorization, Server task identity or Agent-observed native evidence.
