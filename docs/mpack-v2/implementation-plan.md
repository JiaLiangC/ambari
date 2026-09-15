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
existing control plane from import through removal. Product definitions, lifecycle
scripts and binary handling are package-local; no product RPM or product-name branch in
Ambari is required. Authorization, host assignment and request history remain Ambari
platform responsibilities.

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
| C5 | Prove the signed host golden path in a disposable environment. | Open: build/install Ambari RPMs, then import and operate Kyuubi through the Mpack V2 UI using its official binary. |
| C6 | Ship clean authoring commands and CI template. | Open: installed `init`, `validate`, `build`, `sign`, `publish`; no repository-specific `PYTHONPATH`. |
| C7 | Build independent source repository and all-package offline distribution. | Local source repository, pinned compiler build scripts and bounded Ambari collection file importer implemented with target tests. A real signed cross-repository import, release approval and native acceptance remain open. No hosted Store or curated subset. |

## Next milestone: Ambari RPM and Kyuubi

This is the handoff sequence for the next implementation session. Kyuubi is the first
golden-path consumer because it exercises a large upstream binary, custom installation,
configuration, a long-running process and real health checks.

| Order | Deliverable | Exit criterion |
| --- | --- | --- |
| K0 | Reproducible Ambari lab | Build separate `ambari-server` and `ambari-agent` RPMs from this branch in the supported Rocky build environment. Install one Server and Agents on disposable systemd hosts, initialize the database, register hosts and create the validation cluster. |
| K1 | General package source path | Extend the independent repository builder to package complete Ambari service definitions and package-owned Python lifecycle scripts. Signing covers definitions, scripts, artifact locks and any embedded blobs. No Kyuubi logic is added to Ambari core. |
| K2 | Artifact delivery | Represent each software artifact by version, size and digest. Support embedded content, an approved HTTP(S) URL and an absolute target-host `file` path. All transports must produce the same verified bytes before the install script runs. |
| K3 | Kyuubi Mpack | Add Kyuubi metadata, configuration, service/component definitions and install/configure/start/stop/status scripts. Pin an Apache Kyuubi binary release and checksum; do not build a Kyuubi RPM. Preserve logs and work data on ordinary uninstall. |
| K4 | UI acceptance | Build/sign the Kyuubi Mpack, trust its publisher, upload it in Management Packs, select the Kyuubi service, hosts, configuration and binary source, and submit the Server-owned install plan. Verify task history and service state in the normal Ambari UI. |
| K5 | Native acceptance | Verify installed version, process identity, configured ports, health, restart after config change, stop/start, uninstall retention and reinstall. Run one Kyuubi JDBC/SQL smoke query against the test cluster; a listening port alone is insufficient. |
| K6 | Failure acceptance | Reject wrong digests, untrusted signatures, disallowed URLs, invalid local paths and corrupt archives. Preserve actionable Ambari request/task failure output without recording credentials. |

### Binary transport rules

"Full collection" means every package source is built; it does not mean every upstream
binary is embedded. The builder must support thin and offline outputs from one artifact
lock:

- Embedded: the Mpack carrier includes the verified content-addressed blob.
- Network: the install plan selects an administrator-approved URL; mutable location
  does not change the pinned digest.
- Local: the install plan selects an absolute path present on every assigned Agent host,
  typically shared storage or pre-staged content; the Agent rejects symlinks, non-files
  and paths outside approved roots.

If embedded and thin carriers produce different bytes, they must have explicit delivery
variants and must not reuse one publisher/package/version identity with different
digests. Package lifecycle scripts receive only the verified local artifact path; they
do not implement credentials, URL policy or checksum bypasses themselves.

### Kyuubi scope

Use an official Apache Kyuubi binary and its published checksum. The Mpack source may
download it during an embedded build or leave it external for thin builds. Runtime
configuration supplies Java and the test cluster's Spark/Hadoop client paths. Keep the
first milestone to one Kyuubi server component and one supported OS/JDK/Spark matrix;
HA, rolling upgrade, Kerberos and cross-cluster dependency brokering are follow-up work.

The resulting evidence must record source commit, RPM digests, Mpack digest, Kyuubi
artifact digest, host topology, commands and observed results. Do not mark C5 complete
until the browser-to-Agent flow and SQL smoke query have run successfully.

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
| Package command scripts | Product-specific install, configuration, process and health logic | Publisher trust, artifact source policy or Ambari workflow state |
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
