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

# Integration, Publication and Improvement Plan

Status: authorized for remote execution. Read [execution-runbook.md](execution-runbook.md)
and [work-orders.md](work-orders.md) for current paths and phase gates. This
replaces the old local conflict-resolution plan. Prior results remain in
[execution-log.md](execution-log.md).

## Pinned Inputs

| Input | Commit | Use |
| --- | --- | --- |
| Apache trunk | `8051a841cf03673260fd025d6b9eeee68d98e0c4` | Initial remote implementation base |
| Community V2 | `05ffef5b6640a4adcc7af7fff1bec774539a55ae` | Source integration input |
| Community dependency branch | `c28908f77a032b1bdcebd6d71fc3dac9d98efd32` | Two additional commits to evaluate individually |
| Generic multi-cluster reference | `8bf556b6ce94b350b3c3b12e15a7882d07bd19f7` | Required design/contract compatibility input |

The old local merge had 635 initial unmerged paths and 620 at its pause. It is
not transferred as a dirty tree. The remote worker starts from a clean trunk
worktree and recreates an integration after recording its capability mapping.

## M0: Baseline and Capability Mapping

Record actual Git state, runtime/tool availability, source paths, and whether
each shared multi-cluster contract exists in the selected trunk. Read the
reference's status document and do not import that incomplete branch wholesale.

Create a capability ledger covering package registration, modules, registry,
advisors, service grouping, Blueprint, commands, instance manager, upgrade,
frontend flows and the dependency-branch delta. Each row records current trunk
equivalent, community source, compatibility decision and focused verification.

Use these decision classes: REUSE, ADAPT, ALREADY_PRESENT, PLATFORM_DEPENDENCY,
and INCOMPATIBLE_WITH_CONFIRMED_SCOPE. Every excluded or superseded behavior
requires evidence and a replacement or explicit capability limit. A merge parent
with all incoming behavior discarded is not integration.

The reference's service identity remains `(cluster_id, service_name)`. Do not
import the old generated service-ID/ServiceGroup primary-key migration. Grouping
metadata may project onto current identities; it must not change authority,
dependency foreign keys or advertise unsupported same-cluster same-type instances.

Exit: a written source/contract map and a coherent integration strategy. Ordinary
compatible choices are authorized; report material contract contradictions and
continue independent work instead of inventing a competing foundation.

## M1: Integrate Community Source and Required Adaptations

Use an explicit community merge if it preserves a coherent dependency history.
If a different history strategy is necessary, record why and preserve upstream
provenance for every ported topic. Resolve actual semantic differences, not just
conflict markers. Review auto-merged changes and deletions as well.

Work in coherent batches:

1. Build/module layout and packaging: retain JDK 17, Python 3, current plugin and
   dependency versions, server-spi/utility modules, current catalog and supported
   packaging. Map old frontend paths to `ambari-web/classic`.
2. Metadata/registration/registry/advisors: integrate community behavior against
   current state types, Jakarta APIs and authorization. Correct required runtime
   failures and ensure imported definitions are actually consumable.
3. Domain/API/Blueprint: preserve current service identities, routes and config
   relationships. Carry pack/version metadata through existing service/task
   contracts using explicit adapters. No placeholder success or empty stubs.
4. Agent/instance manager: port Python syntax/imports, payloads, directories,
   package installation and actual version/state reporting. Preserve legacy
   stack execution paths where still supported.
5. Lifecycle/upgrades: integrate needed version/change information and command
   behavior without deleting historical upgrade/install APIs. Preserve consumer
   and provider ownership; do not relax shared readiness/security requirements.
6. UI: retain current scoped frontend structure. New metadata flows use actual
   supported APIs. Read relevant Ember baselines and current source before changes.

Do not restore retired distributions/modules as a rename-resolution side effect.
If a function requires a shared multi-cluster extension absent in trunk, isolate
that integration point and document capability availability. Do not manufacture
an alternate shared binding database or silently drop a required feature.

## M2: Verify and Prepare a Reviewable Integration

Required checks:

- No unmerged entries, no conflict markers, clean whitespace checks on changes.
- Relevant reactor compilation and focused Java/Python tests using real current
  implementations. Preserve tests with their behavior and disclose failures.
- Registration, metadata reload, first installation and legacy mpack behavior.
- Cluster/service identity, routes, RBAC, host ownership and config isolation.
- Command producer/consumer compatibility, state reporting and upgrade behavior.
- Fresh schema and supported upgrade paths for every actual persistence change.
- Packaging contents, CLI entry points and frontend compilation/focused flows.

Use available isolated environments for representative runtime checks. Missing
runtime infrastructure is a recorded gap, not a synthetic pass. Reproduce an
obstructing baseline failure on the pinned baseline before labeling it pre-existing.

Keep focused tests with implementation. Large changes need coherent topic commits;
an atomic merge boundary may be necessary for cross-contract adaptations and must
be explained. Subsequent fixes/refactors must remain independently reviewable.

Exit: exact candidate commit, complete capability ledger, change summary, commands
and results, limitations and reviewer findings. Prepare this before requesting
the parent's publication review.

## M3: Local Improvement Baseline

Remote trunk publication is removed from the active plan. Keep the exact M2
candidate locally as the integration baseline and continue development in this
worktree. Do not push, modify remote branches, or make remote state a required
dependency for the next phase.

Exit: record the local candidate SHA, preserve the passing M2 evidence, and
start the improvement topics from that immutable local commit.

## M4: Local Improvement Worktree

Create a local improvement branch/worktree from the verified M2 candidate when
the implementation scope needs isolation. If the current dedicated worktree is
the authorized improvement location, continue there and record the exact base
SHA. Carry the architecture, decisions, tests and work orders into it; no
remote publication is required.

## R1+: Architecture and Authoring Improvements

Implement coherent topics following [contracts.md](contracts.md) and the
[manifest specification](manifest-spec.md):

1. Registration isolation, archive integrity, typed errors and interruption/retry
   recovery, with focused failure tests.
2. Canonical package model, additive deployment metadata and compatibility
   translation with explicit unsupported capabilities.
3. Runtime adapter/context contracts and configurable instance resources.
4. Versioned dependency-adapter interfaces consuming the shared protocol.
5. Configuration provenance, secret references, observations and generic UI.
6. Authoring CLI, schemas, template generation, offline validation/build/tests.
7. Host, OCI, Kubernetes and external reference profiles with honest capability
   maturity and runtime evidence.

A later topic can refine a working contract compatibly when evidence warrants it.
Record the rationale and tests. Changing the confirmed multi-cluster foundation
requires a separate agreed platform change, not an implementation shortcut.

## Known Source/Previous Review Traps

- Old V2 deletes historical upgrade catalogs and install/stack-select actions.
- Old SCM, Java/Python and dependency settings can reappear without conflict.
- Some classes moved to server-spi; avoid duplicate definitions.
- Imported instance-manager RPM postinstall/preremove hooks are necessary;
  the previous local POM rewrite accidentally dropped them. Do not reuse that
  rewrite unchecked. Postinstall supplies the command symlink.
- A namespace import rewrite does not resolve semantic service identity changes.
- Registry compatibility, runtime dependencies, readiness and placement are
  different mechanisms; do not collapse them into a name-only lookup.
- An operation epoch or coordinator lease does not itself fence a remote process.

Every checkpoint includes exact paths, decisions, validation and remaining gaps.
Implementation completion statements alone are not reviewer evidence.
