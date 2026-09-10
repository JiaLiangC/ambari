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

# Working Mpack Contracts

Status: implementation specification for the authorized work. Shared-platform
invariants are mandatory. Names of new additive fields/interfaces are working
choices that can be refined compatibly with tests. New contracts are implemented
in the improvement phase unless required for the integration to function safely.

## 1. Identity and Ownership

| Reference | Required content | Rule |
| --- | --- | --- |
| ServiceRef | clusterId, serviceName | Existing authoritative service identity |
| ComponentRef | ServiceRef, componentName, hostId where relevant | Preserve current Agent membership and host/component identity |
| PackageRef | name, version, verified digest | Immutable published content |
| PackageDeploymentRef | additive deployment ID, owning clusterId, ServiceRef list | Groups package metadata without replacing service primary keys |
| NativeResourceRef | adapter kind, target binding, provider-native ID | Not a new Ambari Cluster/service identity |
| BindingRef | existing binding UUID and applicable snapshot version | Preserve incarnation, provider identity and detach/fence history |
| OperationRef | operation ID, expected generation, associated Ambari request/tasks | One actual execution history, not parallel competing state |

Names are presentation/routing data where the platform allows renaming. Durable
cluster ownership uses its numeric ID. A recreated resource with the same name
does not inherit an old binding's data or in-flight task authority.

New package-deployment persistence is additive. Do not migrate `clusterservices`
keys or the shared dependency foreign keys. Same-cluster same-type independent
services remain unsupported until separately agreed by the multi-cluster platform.
Native replicas inside one supported service remain adapter-owned resources.

## 2. Package Import and Availability

Import input: a local package or a supported source reference, expected identity
and digest where supplied, and the authenticated actor. Legacy V2 registration
still resolves its manifest and definition archive through a compatibility reader.

Stages: acquire -> validate contents -> resolve metadata -> stage -> publish
availability -> reconcile durable metadata. Registration does not deploy services.

Required results: package identity, supported services/profiles, validation issues,
availability state and operation/reference identifiers. A repeated identical
request is deterministic. Same name/version with different content is a conflict.

Validation covers missing files, unknown schema versions, archive containment,
duplicate/conflicting paths, links, module references, identity mismatch and
supported resource limits. Request-isolated staging owns its cleanup. A failure
must not remove another active or previously published package.

## 3. Runtime Adapter

An adapter receives a context with the authoritative Cluster/service/component
reference, actor/policy context, package digest, resolved profile, effective config
generation, approved dependency references, artifact handles and operation ID.
It gets scoped credential handles rather than persisted plaintext secrets.

| Operation | Input | Output / behavior |
| --- | --- | --- |
| describe | Target facts and profile contract version | Supported capabilities and explicit limitations |
| validate | Desired spec plus context | Structured errors/warnings; no mutations |
| observe | Target binding and context | Timestamped actual resources, versions, health and freshness |
| plan | Desired spec plus observation/revisions | Ordered typed steps, effects, preconditions and recovery possibilities |
| apply | One accepted step and operation context | Actual resource references, progress and result |
| verify | Step result and current observations | Evidence of the required postcondition |
| cancel | Operation context | Cancellation progress; no false terminal result |
| recover | Persisted step/context and new observations | Resume, compensate or explicit uncertain/unsupported state |

Plan/observe/validate cannot mutate managed software. Shell execution uses explicit
arguments by default. Software-specific Python hooks use the same context/result
contract and do not share mutable process-global parameters between deployments.

Effective capabilities are the intersection of package, adapter, target and
policy. Unknown capability/version combinations fail explicitly before mutation.
An external database profile can expose observation without install/delete.

Adapter fencing is declared: native resource revision, durable provider-side
idempotency, protected journal/lock, or another reviewed mechanism. An expired
coordinator lease alone is insufficient proof that an old remote process stopped.

## 4. Dependency Adapter and Shared Binding Protocol

The multi-cluster platform owns binding UUID, service endpoints, authorization,
durable revisions, snapshot approval, operation/fence records and lifecycle guards.
The mpack extension owns software knowledge: required interfaces, compatible
versions, exported client fields, preparation actions and verification probes.

Authoring requirements have a name/slot, interface and version/capability range.
Runtime binding targets a specific authorized provider ServiceRef. Discovery
cannot expose unauthorized provider configuration. Snapshots export an allowlist
of client settings and credential references, not administrative secrets.

Named slots beyond the current shared protocol require a negotiated additive
version. Until available, reject unsupported combinations; do not change the
consumer-plus-type uniqueness rule or create a second binding system silently.

Sequence: preview -> approve current snapshot -> prepare provider resources ->
install/render consumer clients -> verify current targets -> permit start.
Provider preparation is not consumer readiness. Changed version, config, identity
or target coverage invalidates corresponding old evidence.

Consumer detach/uninstall preserves provider ownership and retained data. Provider
stop/delete follows shared impact and lifecycle policy. Unsafe or unfinished
security combinations remain unsupported; genericity does not bypass readiness.

## 5. Configuration

Every config field declares type, constraints, default, sensitivity, mutability
and effect: no action, reload, restart, or explicit migration. Effective values
retain provenance and desired/applied generations. Maps/lists follow declared
merge semantics; lists replace by default.

Dependency client profiles do not overwrite unrelated local service configuration.
Reserved snapshot/ownership fields remain server controlled. Secret references
resolve in execution context and are redacted from packages, plans and diagnostics.

Applying configuration validates and stages the result before publication.
Observations verify the actual generation. Restoring old config is distinct from
reversing an application data migration.

## 6. Operation and Workflow

Use existing owned/revisioned draft and task protocols for new deployment flows.
An operation includes request identity, ServiceRef, package digest, effective
config/dependency generations and exact target intent. Persist intent before
mutation and reconcile lost responses by identity, not by resource name alone.

Plan/apply validates relevant revisions again. Material drift requires replanning.
Retries use idempotency keys and real observation. Track UNKNOWN outcomes when
remote effects cannot yet be determined. Do not blindly replay non-idempotent work.

Operation status: PENDING, RUNNING, VERIFYING, SUCCEEDED, FAILED,
CANCEL_REQUESTED or CANCELLED, mapped to existing request/task status where possible.
Software health/presence/running state is separate. A completed command is not
proof that the requested software is ready.

Default automation reports drift. Automatic repair is opt-in, capability-scoped
and bounded. No implicit version upgrades or destructive state changes occur
because a background reconciler exists.

## 7. Public API, UI and CLI

Preserve existing cluster paths, authorizations and consumers. Additive endpoints
must use the established resource-provider/service architecture and versioning
conventions. Endpoint names are finalized after inspecting available contracts,
not invented by the frontend in advance.

Required public operations: discover schema/capabilities, validate a definition,
register/query packages, inspect a deployment plan, apply/query an operation,
observe a deployment, and inspect supported recovery actions.

UI and CLI consume the same results. UI metadata can declare labels, field groups,
operation forms and observation views. It cannot supply authority or execute
arbitrary plugin JavaScript in the main application implicitly.

Structured diagnostics include code, severity, source path, field path, affected
resource reference, message, retryability and actionable correction information.
Recommended stable categories include SCHEMA_INVALID, CAPABILITY_UNSUPPORTED,
PACKAGE_CONTENT_CONFLICT, DEPENDENCY_UNRESOLVED, PLAN_STALE, TARGET_CONFLICT,
AUTHORIZATION_DENIED and OUTCOME_UNKNOWN. Map to existing equivalent codes where
the shared platform already defines them.

## 8. Compatibility Verification

Tests must cover current legacy definitions, current service identity and routes,
two independent clusters, missing/forbidden/stale dependencies, replay after a
lost response, consumer/provider ownership, config provenance and real adapter
postconditions. Mark unavailable integration environments explicitly.

The reference branch remains read-only. Its incomplete implementation is not
an authorization to weaken these contracts or advertise untested runtime support.
