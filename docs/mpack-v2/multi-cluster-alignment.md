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

# Alignment with the Generic Multi-Cluster Architecture

Status: source/design assessment and proposed alignment. The multi-cluster
architecture is generic. Its first managed-dependency software integrations
must not be mistaken for the scope of the overall multi-cluster platform.
The user has confirmed non-conflict with this architecture as a hard mpack
constraint. Detailed additive extension contracts remain proposals and require
agreement before implementation.

## Reference and Review Scope

- Repository: `JiaLiangC/ambari`.
- Reference branch: `AMBARI-26654-multicluster-reference`.
- Pinned commit: `8bf556b6ce94b350b3c3b12e15a7882d07bd19f7`.
- Reference's documented base: `a62fe4959dc948210d844295a097a3311321dea6`.
- Local detached review worktree:
  `/Users/jialiang/PRJS/ambari-multicluster-reference`.

The fixed commit was fetched and checked out without changing implementation
worktrees. The assessment covers design documents and representative server,
persistence, lifecycle, event, metrics and frontend source. It is not a complete
code audit or an executed runtime acceptance test.

The reference explicitly records pending compilation, focused tests and
runtime/browser acceptance. Its intended contracts and present source are useful
design inputs; neither establishes production readiness by itself.

## 1. The Reference's Actual Architecture

One Ambari server and database manage multiple independent Cluster records.
The server/database remain a shared failure domain. This is not a federation
of separate Ambari servers.

Generic platform responsibilities include:

- Cluster identity, exclusive Host/Agent membership and scoped authorization.
- Non-destructive cluster and repository creation.
- Explicit cluster URLs, authorized cluster/service directories and tab-local
  runtime identity.
- User/draft/cluster-scoped workflow persistence, revisions and lost-response
  recovery.
- Server-side event authorization and cluster-aware metrics access.
- Cross-cluster consumer/provider ownership and dependency-management contracts.

The platform handles service deployments generally. HBase consuming HDFS and
ZooKeeper is the first concrete managed-dependency integration in this source
checkpoint. Generality of the platform and maturity of each software adapter
are separate dimensions.

## 2. Source Evidence

All paths in this table are relative to the pinned reference worktree.

| Contract | Evidence |
| --- | --- |
| Generic Cluster/service identity and scope | `docs/design/multi-cluster-management.md`, Product and identity / Frozen foundation contracts |
| One Host belongs to at most one Cluster | `ambari-server/src/main/java/org/apache/ambari/server/upgrade/HostMembershipSchemaUpgrade.java`; ordinary membership paths in `state/cluster/ClustersImpl.java` |
| Stable draft ownership for creation recovery | `upgrade/ClusterCreationSchemaUpgrade.java`; cluster creator/draft columns and uniqueness |
| Composite current service reference | `controller/dependencies/ManagedDependencyServiceKey.java`: `(long clusterId, String serviceName)` |
| Binding incarnation and optimistic versioning | `orm/entities/ServiceDependencyBindingEntity.java`: UUID key, immutable endpoints, row version, operation epoch and snapshot versions |
| Binding persistence and service foreign keys | `upgrade/ServiceDependencySchemaUpgrade.java`: binding, snapshot, operation, host-result and fence tables |
| Separate preparation from start readiness | `controller/dependencies/ManagedDependencyReadinessPolicy.java` |
| Provider lifecycle ownership | `controller/dependencies/ManagedDependencyLifecyclePolicy.java` |
| Scoped event delivery | `api/stomp/ApiStompAuthorizationService.java` and event projection/interceptor classes |
| Stable numeric metric scope | `agent/stomp/PrometheusTargetDiscovery.java`; `service/metrics/PrometheusQueryClient.java` |
| Generic service directory with optional dependency enrichment | `ambari-web/latest/src/screens/Directories/ServiceDirectory.tsx` |
| Principal/cluster/generation-aware client runtime | `ambari-web/latest/src/Utils/runtimeIdentity.ts`; `AppLoader.tsx` |
| Initial managed software adapters | `ManagedDependencyType.java`, `ManagedDependencyDescriptorResolver.java` and HBase client/provider integration |
| Remaining verification and integration work | `docs/design/multi-cluster-reference-status.md` |

The service directory loads all services from authorized clusters. Its HBase
dependency-summary enrichment is an additional software-specific behavior, not
a restriction that the directory or multi-cluster design supports only HBase.

## 3. Responsibility Split with Mpack

| Area | Generic multi-cluster foundation | Mpack responsibility |
| --- | --- | --- |
| Ownership and authorization | Cluster identity, host ownership, user/resource boundaries | Carry and enforce the owning scope through every software capability |
| Software definitions | Existing service/Stack metadata consumers | Versioned packages, schemas, components, profiles and capability declarations |
| Target execution | Existing Agent/task infrastructure and scoped dispatch | Runtime/distribution adapters for supported software forms |
| Dependencies | Durable binding, snapshot, operation and lifecycle contracts | Requirements/provided interfaces and software-specific resolution/preparation/probes |
| Recovery | Owned drafts, revisions and actual operation checkpoints | Package deployment workflow consuming that protocol |
| UI | Scoped shell, navigation, authorized unified directories | Metadata-driven forms, operations and instance presentation within that shell |
| Observability | Authorized delivery and cluster metric boundaries | Software metrics/health/log metadata with instance identity |

Mpack should extend these contracts through explicit interfaces. It should not
create parallel cluster directories, a separate authority system, or an
independent dependency-operation history for the same relationship.

## 4. Retain Cluster Authority and Separate Runtime Targets

The earlier mpack draft proposed Environment as a generic target and
authorization context. The reference makes a second ownership root unnecessary
for existing Ambari-managed deployments and creates a concrete coordination
requirement for that proposal.

Confirmed compatibility boundary:

- Retain Cluster as the ownership/authorization anchor for existing managed
  deployments and preserve numeric cluster identity in durable references.
- Use a typed runtime target/profile to identify a host, container engine,
  Kubernetes namespace/release or external API resource.
- A generic scope reference initially resolves to existing Cluster/server
  authority; it does not grant new authority merely by changing its kind.
- If Environment is retained, initially use it as organization, selection or
  composition metadata rather than independently assigning the same Host/Agent.
- Truly non-cluster-owned targets need an explicit ownership and authorization
  contract before implementation. Do not assign all of them implicit global
  administrator scope or fabricate a Hadoop Stack as a workaround.

This preserves broad software coverage. The mechanism used to run software and
the resource boundary authorizing its management are different concepts.

## 5. Preserve Service Identity in the Mpack Baseline

The reference's live service identity is `(cluster_id, service_name)`, with the
service name representing the service type in this deliverable. Its dependency
foreign keys intentionally preserve that model without migrating every service
to a new numeric ID.

Community mpack V2 introduces service groups, service instances and generated
service IDs. That identity migration is not adopted by the mpack architecture.
Additive package-deployment IDs refer to existing services and must not redefine
the same service relationships.

Two capabilities must be distinguished:

- Multiple clusters can each deploy the same service type using the reference
  identity model.
- Multiple independent instances of that service type inside one Cluster need
  an agreed additional instance-addressing and persistence model.

Required compatible design:

1. Introduce a logical deployment-reference contract that can represent current
   cluster/service identity without changing its meaning.
2. Keep package IDs and adapter-native replica IDs separate from existing Ambari
   service identity. Existing service routes remain authoritative.
3. Do not perform a service-ID/ServiceGroup migration within the current mpack
   scope. If same-cluster same-type instances are later required, agree on a
   separate platform change covering all service and dependency consumers.
4. Preserve binding UUIDs and incarnation/fence history through any later change.
   A service recreated with the same name must not inherit another binding's
   retained data or old in-flight operation.
5. Do not emulate same-cluster multi-instance support by assigning one Agent to
   multiple runtime clusters; that contradicts exclusive membership.

Same-cluster same-type multi-instance identity is deferred from this baseline.
It is not a hidden requirement to change the multi-cluster reference. Platform
replicas within a supported service remain possible through native adapters.

## 6. Generalize Dependency Adapters on the Existing Protocol

The reference has generic concepts worth reusing: binding identity, immutable
endpoints, approved versioned snapshots, optimistic revisions, operation epochs,
provider preparation, per-host evidence and safe detach/fencing.

Current concrete integration includes HBase consumer descriptors, HDFS/ZooKeeper
provider types and namespace fields appropriate to that first scenario. The
mpack extension should make software knowledge pluggable while preserving the
coordination guarantees.

Proposed decomposition:

- Binding coordinator: identity, authorization, revision checks, persistence,
  lifecycle ordering, cancellation and recovery.
- Dependency contract: named requirement slot, provided interface, version and
  capability constraints, snapshot schema and required evidence kinds.
- Software adapter: compatibility logic, exported client configuration,
  namespace/resource preparation, credential requirements and real probes.

Named slots are important. The current uniqueness rule uses consumer identity
plus dependency type, which fits one HDFS and one ZooKeeper dependency for HBase.
A generic application may require two PostgreSQL dependencies, such as `primary`
and `audit`. The eventual uniqueness rule should use a declared requirement slot,
while protocol/type describes compatibility. This is a proposed compatible
extension, not permission to change the reference's uniqueness rule in place.
Until the platform exposes the agreed versioned contract, unsupported slot/type
combinations return an explicit capability result. Existing bindings, clients,
validation and foreign keys retain their current meaning.

Common identity/state columns should stay queryable and constrained. A generic
extension must not degrade the entire binding to unvalidated JSON. Adapter payloads
can be typed/versioned without losing core foreign keys, ownership and state.

## 7. Strengthen Mpack Lifecycle Using the Reference's Boundaries

### Preparation and Readiness

Provider preparation does not establish complete consumer readiness. A fresh
consumer may need client packages, rendered configuration and credentials before
it can run its real connectivity checks.

The general mpack operation model should therefore represent preparation,
consumer installation, verification and start as distinct prerequisites.
Each adapter defines evidence appropriate to its runtime. Host-level HDFS
read/write checks must not become mandatory checks for unrelated external or
Kubernetes software.

### Fencing and Uncertain Execution

The reference explicitly explains why an operation epoch or terminal task status
does not by itself stop an old remote process. Its first preparation path uses a
pinned action host and protected local journal/lock, with uncertain states
blocking unsafe reassignment.

The mpack adapter contract must declare how it fences mutation and reconciles
unknown outcomes. Different platforms can use native resource revisions,
provider-side idempotency or an appropriate journal/lock protocol. A coordinator
lease expiry alone cannot justify replaying a non-idempotent remote action.

### Ownership

Consumer removal does not stop or delete its provider, and does not implicitly
remove retained provider data. Apply this to all package compositions and
dependency adapters. A multi-scope change requires explicit authorization and
an operation plan at the affected ownership boundaries.

## 8. Reuse Frontend, Workflow and Observation Scoping

The mpack UI should use the reference's explicit cluster routes and runtime
lifetime. Include instance/deployment identity as additional scope where needed.
Do not introduce a package-global selected-cluster variable.

Package installation drafts should extend the existing owned/revisioned workflow
protocol. Keep lost-response reconciliation and stable creation identity; a
same-name resource lookup does not prove draft ownership.

Software metadata can extend the generic service directory and detail views.
Dependency rendering becomes capability/contract-based as more adapters arrive.
That is a software extension to a generic directory, not a replacement directory.

Package events and metrics must retain server-side scope authorization. Browser
filtering is only state isolation. Preserve numeric cluster identity and add
instance/binding identity where necessary; cluster names can be renamed or reused.

## 9. Maturity and Compatibility Limits

The pinned reference is explicitly an incomplete source checkpoint. Its status
document lists remaining advisor integration, complete same-realm security
production/delivery, lifecycle guard integration, retry/update/detach UX,
deletion publication/locking review and final executed validation.

Do not replace those unfinished paths with assumptions that generic mpack support
automatically makes them complete. Reuse the intended contracts, audit the actual
integration, and retain explicit unsupported/incomplete outcomes until evidence
establishes the new behavior.

The design documents also contain historical execution instructions. For this
review, the pinned source and reference-status document determine observed scope;
the current execution authorization is defined by the mpack runbook. Historical
worker instructions in the reference are not work orders for this session.

## 10. Compatibility Acceptance and Remaining Extension Decisions

The following matrix is a mandatory design/implementation review gate. Test
names here describe required scenarios, not checks executed in this assessment.

| Scenario | Required compatible behavior |
| --- | --- |
| Package deployment in Cluster B while A exists | A's services, repositories, configuration and operations remain intact |
| Host already owned by A targeted by B | Existing exclusive membership rules reject reassignment |
| Same service type deployed in A and B | Numeric Cluster/service identity scopes every action and result |
| Caller supplies a different target scope | Server resolves ownership and enforces RBAC before reads or mutation |
| Cross-cluster dependency selection | Existing consumer/provider authorization and binding protocol apply |
| Consumer uninstall or detach | Provider lifecycle and retained data remain independently owned |
| Provider changes during deployment | Existing snapshot revisions and readiness checks detect stale intent |
| Lost create/apply response | Owned workflow and operation identity reconcile the exact target |
| UI tab switches, delayed REST and websocket messages | Existing route/runtime generation and server delivery boundaries hold |
| Metrics and events from a package | Numeric cluster scope is preserved; no browser-only confidentiality boundary |
| Unsupported generic adapter extension | Explicit unsupported result; no parallel binding or permission bypass |
| Software definitions loaded from legacy V2 | No implicit ServiceGroup/service-ID migration into the multi-cluster schema |

Remaining additive extension decisions:

1. Versioned runtime-target adapter contracts inheriting existing authority.
2. Package-deployment metadata referencing existing service identities.
3. A shared binding/operation protocol with named dependency slots and versioned
   software-adapter contracts.
4. Common readiness/evidence/fencing semantics with platform-specific mechanisms.
5. Shared UI/workflow/event contracts and representative cross-cluster acceptance
   examples beyond the first concrete dependency integration.

Recommended overall layering: generic multi-cluster platform, shared software
instance/dependency contracts, and mpack-provided software/runtime knowledge.
The compatibility boundary is confirmed. Detailed additive extensions follow
the mpack runbook and checkpoint review; the reference branch remains read-only.
