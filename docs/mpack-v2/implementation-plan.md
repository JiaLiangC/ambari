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

# Mpack V2 implementation plan

## Goal and guardrails

Deliver a maintainable Ambari extension path for signed software packages, using one
existing control plane from import through removal. Software inside a supported host
profile should be package-local. Runtime semantics, authorization, request history and
native ownership remain platform code.

The plan excludes OCI, Kubernetes, rolling package upgrade, reload, ownership handoff,
package data procedures and force-abandon. They are removed, not placeholders for the
next milestone. Do not add another workflow, deployment, identity, binding or
authorization database.

## Convergence work

| Order | Work | Status / exit criterion |
| --- | --- | --- |
| C0 | Remove OCI/Kubernetes code and stale schema/docs. | Implemented; no active profile, adapter, fixture or contract remains. |
| C1 | Replace ambiguous removal evidence with typed common dispositions. | Implemented in Agent adapters and Server parser/DAO; malformed or mixed evidence fails closed. |
| C2 | Reduce lifecycle to install/configure/start/stop/restart/observe/uninstall plus controlled purge. | Implemented across authoring, Agent, Server and UI; advanced actions and recovery states removed. |
| C3 | Move service/component/host/config install orchestration from browser to Server. | Implemented as the UUID-addressed install-plan endpoint; targeted API/UI tests pass. |
| C4 | Split high-change responsibilities. | Implemented initial split: artifact fetch policy, install coordination, removal parsing and profile readiness/runtime initialization have separate owners. Continue only when changes demonstrate another concrete coupling. |
| C5 | Prove the signed host golden path in a disposable environment. | Open: file and approved URL import, HTTP/Redis install, config restart, observe, retained uninstall, purge and catalog removal. |
| C6 | Ship clean authoring commands and CI template. | Open: installed `init`, `validate`, `build`, `sign`, `publish`; no repository-specific `PYTHONPATH`. |
| C7 | Deliver official discovery in the independent Store repository. | Open: signed/versioned read-only index, publisher governance, key rotation/revocation; offline import remains available. |

## Server install plan

The single operation is:

```text
POST /clusters/{cluster}/mpack_install_plans/{planId}
```

Implementation sequence:

1. Parse a closed request containing imported repository ID, service, complete
   component-to-host assignments, declared configs and `validateOnly`.
2. Validate UUID, permissions, selected Mpack definition, service conflict, component
   coverage, host membership, uniqueness, cardinality and bounded config schema before
   mutation.
3. On execute, resume or create the service and missing component/host/config records
   through existing Ambari resource providers.
4. Use a deterministic config tag derived from release and plan identity.
5. Submit the existing service install transition and persist its normal Ambari
   request/stages.
6. On repeated plan submission after request persistence, return the existing request
   ID and state.

The endpoint is synchronized within one Server process. Multi-server filesystem and
cross-process plan serialization remain outside this milestone, matching current Mpack
catalog ownership. The existing DB constraints and resource-provider checks remain
authoritative at every write.

## Evidence and removal

Agent adapters own the meaning of native absence or external ownership. They emit one
common envelope. Server's `MpackRemovalEvidence` accepts only:

```text
absent + retained + released -> UNINSTALLED_RETAINED
absent + purged   + released -> PURGED
external + external + external -> UNREGISTERED
```

Uninstall and purge reports also require task/package/cluster/service/component/host/
incarnation identity equality. Purge additionally requires the exact retained and
purged device/inode inventories. No success exit code or profile name substitutes for
these postconditions.

## Cohesion boundaries

| Component | Owns | Must not own |
| --- | --- | --- |
| `MpackArtifactFetcher` | URI parsing, source policy, credentials, bounded transfer | Registration transactions or Stack projection |
| `MpackManager` | Package verification, registration/reconciliation, catalog projection | HTTP transport details or service install workflow |
| `MpackInstallCoordinator` | Whole-plan validation and use of existing resource providers/request history | Native execution or a second operation store |
| `MpackRemovalEvidence` | Typed release-envelope validation and state mapping | Profile-specific systemd/file/database interpretation |
| `ManifestService` | Existing Script entry points and profile dispatch | Cross-profile readiness conditionals |
| Profile deployments | Native discovery, mutation, postcondition and receipt evidence | User authorization or global workflow state |
| Management Packs UI | Collect one plan, display state, invoke public actions | Multi-resource mutation sequencing or inferred recovery |

The split is intentionally shallow. Shared task identity, receipt journal and catalog
transaction logic are not duplicated behind interfaces merely to reduce file length.

## Acceptance

Every change runs the smallest affected tests first, then the consolidated suites:

- Authoring unit tests and example validation/export reproducibility.
- Agent host/files/external lifecycle, task binding and process-boundary tests.
- Server Mpack manager, target DAO, task binding, request authorization, API and install
  coordinator tests with RAT/checkstyle.
- Management Packs model/lifecycle/dialog tests and production TypeScript build.
- `git diff --check` and stale-contract searches.

Local fixtures do not close production gates. C5 requires real Server-Agent/systemd and
production database fresh/upgrade environments, authorization denial, response loss,
partial failure and retained-data inspection. Results belong in [status](status.md),
not in design prose.
