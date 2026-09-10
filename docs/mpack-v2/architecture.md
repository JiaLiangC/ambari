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

# Mpack architecture

## Independent conclusion and support boundary

The design can support a bounded family of software through existing Ambari
services, configuration and tasks. It does not yet constitute a general production
platform for every runtime. The reviewed R1 unsafe dispatcher and disconnected UI
were prototypes; the repair adds an actual compiler-to-legacy-import-to-shared-Script
host path. Native production acceptance remains separate from local code completion.
See [status](status.md) for implementation and verification evidence, and the
[independent report](reviews/independent-architecture-review-2026-09-10.md) for the
original line-specific findings and Redis/Kyuubi walkthroughs.

Architecture is reasonable where it reuses Ambari authority and isolates native
execution. Maintainability improves by having one compiler and one host Script,
without package-specific Java/Python dispatch. Extensibility is currently strongest
for foreground host services with scalar configuration. Stability requires bounded
commands, durable task identity, observed postconditions and conservative UNKNOWN
handling; these mechanisms are implemented but require native acceptance. Complexity
is limited by removing unused simulators/facades instead of operating a second
workflow, binding store or authorization system.

Current executable contract: `host-service/v1` with one `host.systemd/v1` profile
per server component; install/configure/start/stop/restart/status/local service check;
OS packages, users/groups, isolated directories, declared file artifacts, scalar
multi-file configuration, foreground executable arguments and loopback TCP/HTTP
health. A package can contain several services/components. Client-only components,
secrets at execution, reload, automatic upgrade/migration, adoption, detach/delete/
purge, OCI, Kubernetes and external database execution are not implemented by this
contract. Authoring accepts broader profile declarations without promising execution.

A cluster still has its existing Stack/service model. Multiple independent services
of the same type inside one cluster cannot be invented through aliases. Multiple
clusters can use the same package; native units include the existing cluster,
service, component and server-allocated service-row incarnation. Hosts retain their
existing Agent membership. Same-host ports/users/OS packages are shared host resources:
there is no private OS package namespace or port allocator. Manifest authors must
choose compatible packages and distinct ports; a bind/start failure remains a failed
or unknown operation requiring observation, never proof of success.

## Responsibilities, stores and trust boundaries

```mermaid
flowchart TD
  A[Human or AI author: untrusted source] --> C[Compiler: schema, references, inventory, deterministic exports]
  C --> B[Signed legacy definition archive]
  R[Registry: source discovery] --> I
  B --> I[Server MpackManager: authenticated catalog import and signature verification]
  U[Existing UI / API: authenticated actor] --> S[Existing Ambari service controller and RBAC]
  I --> DB[(Ambari DB: package / Stack / service / config / request / task)]
  S --> DB
  DB --> T[Existing task and metadata delivery; assigned Agent only]
  T --> AG[Existing Agent ActionQueue / Script execution boundary]
  AG --> H[Shared ManifestService / HostDeployment]
  H --> N[systemd and existing Package / User / Directory resources]
  H --> L[(Agent receipt: materialization evidence only)]
  N --> O[Observed native identity, invocation and health]
  O --> AG
  AG --> DB
  D[External shared dependency authority: bindings / approval / snapshots] -. integration prerequisite .-> S
```

The compiler performs no runtime calls or authorization. The server owns package
trust, existing permissions and task scheduling; it does not generate arbitrary
native argv from request parameters. The Agent interprets an installed authenticated
definition and protects its local target; it does not authorize users or decide
cross-cluster ownership. Adapters must return runtime-specific evidence and may
reject unsupported capabilities. UI and AI consume the same contracts and cannot
supply approval, fencing or execution trust markers.

| State | Authority / persistence | Writer and readers | Concurrency and lifecycle |
| --- | --- | --- | --- |
| Cluster/service/RBAC/host membership | Existing Ambari DB | Existing controllers; Agent receives scoped projection | Existing PK/FK and authorization; no replacement identities |
| Package release | `mpacks`, `content_digest`; immutable definition files | MpackManager/DAO; metadata/task generation reads | Catalog lock plus DB constraints; registration marker reconciles crashes |
| Service package selection | Existing desired repository/Stack relationship | Existing service controller; topology metadata | Blueprint selections constrained to actual Stack; independent package composition deferred |
| Native binding incarnation | `clusterservices.mpack_target_incarnation` | ClusterServiceDAO; task/service metadata reads | Row lock and conditional initialization; new service row gets a new incarnation |
| Desired configuration | Existing Ambari configurations and tags | Existing configuration API; tasks/Agent consume | Existing versioned publication; typed host validation before local staging |
| Operation intent/result | Existing request/stage/task and command persistence | Existing scheduler; Agent reports | Existing task IDs; no second operation DB or autonomous recovery loop |
| Applied configuration/native evidence | Root-owned Agent deployment `receipt.json`, config generations | Shared host Script; subsequent tasks/status read | Atomic fsync/rename, local flock, task ordering and expected receipt hash |
| Native process state | systemd unit/InvocationID/health | Native runtime; Agent observes | Exact owned unit and path, timestamped observation; exit code is insufficient |
| Dependency binding | External shared platform | Shared coordinator; future Mpack client consumes | Platform UUID/incarnation/snapshot/revision/authorization/fence; no fabricated readiness |
| Catalog staging/quarantine | Filesystem projection, not authority | MpackManager startup/registration/removal | DB decides availability; quarantine retained for operator inspection |

The service incarnation is native-target metadata, not a service ID. It prevents a
recreated name from silently inheriting old units/data. One local receipt per bound
component is necessary to distinguish previous invocation/configuration from desired
state after a lost response; it contains no permission decisions or competing task
history. Losing this receipt requires explicit investigation rather than adoption
by name. Server DB loss requires existing Ambari database recovery.

## Reliability and failure ownership

Registration prepares outside the publication lock, authenticates content, writes a
pending marker, publishes definitions/Stack link and persists catalog/Stack rows.
Startup completes a DB-backed publication or quarantines an uncommitted one. If DB
rollback fails, definitions remain available for reconciliation. Removal commits
catalog/repository/Stack deletion in one DB transaction before moving definitions
out of availability. Reference writers (Blueprint, cluster, repository and Stack DAOs) take the existing
package-row lock in the same transaction as the reference write, serializing with
catalog deletion. Foreign keys remain the final integrity guard. H2 concurrency
tests demonstrated that foreign keys alone were insufficient for uncommitted
reference creation. Historical Blueprint JSON references are checked, and new
settings cannot escape their Stack. Deleted Stack/repository JPA projections are
detached/evicted so a committed removal does not remain visible through cached IDs.
Filesystem cleanup failure after DB commit is retried at startup. Quarantine is
operator-retained catalog evidence, never native application data. Multi-server
filesystem HA is outside this milestone; a message bus or distributed transaction
manager would not repair the existing filesystem ownership boundary.

ActionDBAccessorImpl binds service/package/host/action and scoped configuration
snapshots immediately before existing execution_command persistence. Agent metadata
can invalidate that task but cannot retarget it. The native plan is computed on the
Agent using current runtime facts; there is no additional server discovery endpoint.

The host Script requires an existing server execution task for mutation; automatic
Agent-local recovery is disabled for generated components. Plans bind task, package
digest, ServiceRef/incarnation, configuration hash/tags, actual observation, expected
receipt and a 30-second discovery/plan lifetime. The driver serializes one target,
rejects stale tasks/plans and writes APPLYING before effects. Configuration is typed,
rendered into an unpublished generation and atomically switched; running generation
only advances after verified start. Configuration changes restart an active service.
Host export requires restart semantics; none/reload/migration are unsupported.
Explicit RESTART is one task intent,
not inherited STOP+START with the same task ID. STOP is independent of invalid desired
configuration. Status probes the verified running port/config, with desired/published/
running generations kept separate.

A repeated completed task only observes/verifies. A lost start response can be
reconciled from a new native InvocationID and matching intent without another start.
Pending native jobs and interrupted starts without surviving invocation evidence
stay UNKNOWN without a second start. An explicit server STOP can establish a
known inactive state before another START. Package replacement is not silently
called upgrade. Cancellation is a request to stop work, not proof that native
side effects stopped; native timeout/cancellation remains UNKNOWN and disables
automatic Agent retry. Late old tasks cannot overwrite a newer local receipt.

Listener preflight rejects occupied declared IPv4 TCP/UDP ports before provisioning
or publication. It is an availability check, not a distributed port reservation;
a subsequent race still requires native postcondition verification. HTTP health
never follows redirects away from the declared probe.

Native subprocess stdout is capped at 64 KiB, stderr is drained without persistence,
process groups have deadlines/cancellation, discovery/show/probes are bounded, and
configuration history keeps ten recent plus current/running generations. Existing
Ambari request/task/log retention remains the platform policy. OS package resource
execution retains its existing Ambari timeout semantics. Persistent resource
directories are never pruned; there is no generic purge authorization in this slice.

## Minimal abstractions, migration and cost

| Decision | Benefit | Implementation / migration cost | Ongoing cost and simpler alternative |
| --- | --- | --- | --- |
| Keep existing service/Stack/task/config authority | Preserves RBAC, routing and audit | Add package digest and native incarnation metadata; nullable DDL migration | Two fields and one shared Script; a parallel Deployment/Operation DB is unnecessary |
| Keep compiler + small profile-specific executor | New Redis/HTTP-like software changes source files only | Strict schema/inventory may reject previously ignored source fields | One schema and scalar runtime projection; copied lifecycle scripts multiply fixes |
| Emit actual legacy modules and authenticate import | Reuses existing registration/Agent resource delivery | Explicit external HMAC key on builder and Server; rebuild old alpha bundles | One versioned export format; source ZIP remains separate; asymmetric trust can wait |
| Remove parameter dispatcher and simulation execution models | Closes root-command authority hole and duplicate recovery | Queued alpha runtime commands fail; external alpha library consumers must migrate | No command forwarding facades; retain only static capability declarations and ServiceRef |
| Remove unconsumed Java lifecycle/config facades | Blueprint stops pretending to be live state | Old fields ignored when read; new assertions rejected | Existing task/config models suffice until a concrete new consumer exists |
| Keep registry/catalog; transactional deletion + reconciliation | Recoverable file/DB ordering | Existing reference constraints and two pending markers | Bounded publication critical section; operator quarantine retention remains necessary |
| Remove disconnected runtime UI/API client | No nonexistent endpoints or package-scoped execution permission | Existing catalog and real service screens remain | A generic runtime console waits for an implemented service-scoped API |
| Delegate shared binding authority | No fake approvals or duplicate fencing | Real client integration and provider contract extension required | No second binding DB, authorization layer or global retry coordinator |

New software under this host contract adds manifest, config schemas/templates and
vendored artifacts (or declared OS package prerequisites), then uses the same
validation/export/import/service workflow. A new config scalar touches those source
files. A new lifecycle semantic or bottom-level runtime requires a versioned contract,
its own evidence/recovery implementation and focused tests; adding method names to
all runtimes would not establish equivalent behavior. No arbitrary plugin JS,
plugin sandbox or generic hook runner is required by the present consumers.

## External prerequisites and deferred product scope

The shared reference commit `8bf556b6ce94b350b3c3b12e15a7882d07bd19f7` is read-only and
not integrated here. Its managed dependency type enumeration has HDFS and ZOOKEEPER;
it does not implement Spark/Hadoop/Hive contracts for Kyuubi. The authoring client
boundary delegates to an injected real client and fails when absent. Expanding that
platform and accepting cross-cluster approval/config propagation is prerequisite to
Kyuubi deployment, not something a local UUID or mock can replace.

OCI needs engine/resource identity and volume/postcondition handling; Kubernetes
needs API-server/namespace/UID/revision and rollout evidence; external databases need
scoped credentials/connections and observation contracts. These implementations,
secret resolution, generic metrics/log routing, service-scoped runtime UI, data
migration/upgrade/adoption/uninstall/purge and multi-package composition are explicit
roadmap gaps. They are not all current M2 blockers, and are not marked completed by
retiring unsafe prototypes. Real systemd/Redis, production DB migration and live
server-Agent acceptance still require appropriate environments.
