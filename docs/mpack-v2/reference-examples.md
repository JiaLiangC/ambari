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

# Reference Flows and Acceptance Scenarios

These examples define required design/runtime evidence. They are not reports of
tests already run. Implement executable fixtures in the improvement phase using
the agreed contract and available isolated environments.

## A. Host HTTP Service

Author inputs: the manifest example, a small Python HTTP server, a typed port
configuration schema, a config template and a lifecycle test fixture.

Flow: init template -> validate references/config -> run isolated tests -> build
with hashes -> register -> select existing Cluster/host -> inspect plan -> apply
through the Agent -> verify HTTP readiness. UI is generated from metadata.

Plan effects: install declared runtime dependency if needed, create owned service
resources, render configuration, start the unit and verify its endpoint. Artifact
publication is separate from this host operation.

Failure cases: occupied port, invalid config, absent artifact, start timeout,
lost task response and restart after server interruption. Retry observes owned
resources and actual state; it does not register duplicate services or delete
another deployment's files.

Compatibility: deploying the same service type in Cluster B preserves Cluster A.
A host already owned by A cannot be borrowed by B. Same-type independent services
inside one Cluster remain outside the current identity contract.

## B. OCI and Kubernetes Profiles

Reuse the HTTP service's conceptual configuration, health and capability model.
An OCI profile supplies an immutable image and engine binding. A Kubernetes
profile supplies a supported release/resource definition and authorized namespace.
Profile-specific metadata is explicit; a host script is not assumed portable.

Ambari manages the top-level container/release resource and verifies its state.
The runtime owns subordinate scheduling and replacement. Existing Cluster scope
still authorizes the operation; a target profile cannot create new authority.

Failure cases: image pull failure, unavailable engine/API, rollout timeout, stale
resource revision, lost apply result and persistent-volume retention. Avoid a
second mutation when the platform may already have completed the first one.

Acceptance distinguishes schema/adapter conformance from real engine/Kubernetes
execution. Mark unavailable platforms explicitly; do not advertise tested support
without actual execution evidence.

## C. Stateful PostgreSQL Service

Author inputs: binary/distribution profile, data resource declaration, configuration,
secret references, health query, backup/restore and supported upgrade capabilities.

Flow: validate version/data compatibility -> plan owned resources -> initialize
only a new owned data directory -> configure -> start -> perform readiness query.
Existing data is imported/adopted through an explicit operation, not overwritten.

Upgrade distinguishes management definition, binary version and database format.
Backup verification and migration compatibility are preconditions where required.
Failure enters a documented recovery state; changing a version link is not
represented as reversing every database migration.

Uninstall defaults to data retention. Deleting retained data is separately
declared, authorized and target-specific. Secret values never enter package,
plan, task summary or test logs.

## D. Existing External Database

Author inputs: endpoint profile, credential references, supported health/metrics
and optional remote maintenance operations. No host install capability is required.

Flow: bind within an existing authorized management scope -> validate connectivity
and credentials -> observe -> expose only supported actions. Removing observation
does not delete the database or its provider infrastructure.

Failure cases: expired credentials, unreachable endpoint, stale observation,
unsupported operation and provider identity mismatch. Unknown is not healthy.
Adoption of greater authority requires an explicit supported contract.

## E. Cross-Cluster Managed Dependency

Use the generic multi-cluster reference's initial HBase/HDFS/ZooKeeper integration
as an existing software-specific example of the common binding protocol.

Flow: authorized provider discovery -> preview immutable binding identity and
snapshot -> approve -> prepare provider-local namespace -> install/render consumer
clients -> verify every required consumer target -> allow start.

Preserve the provider's lifecycle and data. Export only client configuration and
permitted credential references. Provider updates invalidate affected snapshot
evidence. Retry retains the same binding incarnation and correct operation epoch.

The reference explicitly lacks some final security/workflow/runtime acceptance.
Tests or capabilities in the new work must not convert those gaps into successful
results through bypasses or trust flags.

For a later generic application with `primary` and `audit` SQL requirements,
negotiate named slots with the same binding platform. An unsupported protocol
reports that limitation instead of replacing the existing uniqueness constraint.

## F. AI Author Repair Loop

The AI reads schema and capability metadata, generates the HTTP source package,
and receives a diagnostic identifying a deliberately missing file or bad config
field. It corrects the source, reruns validation/tests, builds and inspects a plan.
The same public API and permissions apply to humans, CLI and AI.

Required outputs are stable diagnostic codes/paths, actual test results, immutable
artifact identity, a specific target plan, and an observable operation. Human
terminal output stays readable; machine-readable validation is an optional CLI
mode, unrelated to the interactive Codex session used to implement this project.
