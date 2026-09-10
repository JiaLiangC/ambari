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

# Contracts and authority

The current executable subset is defined below. Future runtime contracts are
requirements, not implementation claims; see [status](status.md). Keep these rules
aligned with executable schema and actual consumers.

## Identity and ownership

Software-specific behavior belongs to the signed Mpack: manifests, configuration
schemas/templates, compatibility rules and any supported package adapters or lifecycle
handlers. Ambari supplies generic validation, authorization, scheduling, task evidence
and runtime execution. A new product on an existing runtime must not require a
product-name branch in Server, Agent or UI. A capability declaration is executable
only when the platform supports its versioned execution/verification/recovery contract;
otherwise compilation or admission must reject it. Package code must not create a
second service identity, workflow, authorization or dependency authority.

`ServiceRef = (cluster_id, service_name)` uses existing Ambari identity, permissions,
routes and host membership. Package name/version/content digest identifies immutable
published content, not a service or data version. The desired repository/Stack
relationship selects definitions for actual tasks. Blueprint package settings cannot
select an unrelated package or assert live ownership/generation/lifecycle state.

For host-service/v1 the server allocates `clusterservices.mpack_target_incarnation`
once under the existing service row lock. A native target is scoped by ServiceRef,
component, Agent host and incarnation. Service deletion/recreation produces a new
incarnation and does not adopt old unit/data paths. This metadata is not a generated
service ID. No PackageDeploymentRef database is needed by the current consumers.
Same-cluster service aliases remain unsupported. Independent packages now select
definitions through existing repository/service FKs in the active P1 implementation;
its consolidated acceptance is pending.

Managed native unit/config/artifact files belong to this target; persistent directories
are retained. Shared host users/packages/ports are declared prerequisites, not exclusive
per-service ownership. Shared dependency provider/consumer ownership is controlled by
the external platform, never by a manifest or local Agent receipt.

## Authoring, offline content and trust

All source entry points use the canonical compiler, JSON Schema and semantic checks.
Manifest digest identifies source; package digest also includes locked declared file
content and dependency requirements. Only declared artifacts/schema/templates enter
an export. Reject symlinks, traversal, input/output collision, credential-bearing URLs,
unknown fields and unsupported capability requests. URL sources require SHA-256 and
must be vendored before offline export. A dependency requirements lock is not an
approved binding snapshot. OS repositories, runtimes and provider assets are separate.

Source ZIPs have fixed archive metadata, exact inventory and digest verification;
optional HMAC sidecars are local tooling authentication. Deployable host exports use
`mpack.ambari.apache.org/host-service/v1`: deterministic nested legacy module tarballs
and metadata with definition SHA-256 and manifest/package digests. The explicit local
alpha mode uses HMAC-SHA256. Publisher packages use Ed25519 over the complete canonical
metadata except the signature itself (`mpack-publisher/v1`); public keys are scoped
to approved publishers in the administrator trust store. Verification of this new
implementation batch is pending.
The authenticated envelope is `mpack-legacy/v1`, name, version, definition digest,
manifest digest, package digest, each separated and terminated by LF. The Server
reads external `mpack.signing.key.file` (1..4096 bytes), verifies before import and
persists package digest. The signing key must never be an exported input. Neither
build nor registration performs native installation. Established legacy package
administration keeps its existing trust boundary; generated descriptor content cannot
silently downgrade to unsigned host-service import.

## Host execution and configuration

Generated XML selects one shared `ManifestService`, not package-specific lifecycle
scripts. Executable operations are install/configure/start/stop/restart plus status/local
service check. Native target discovery is runtime evidence with scope, time and TTL;
static profile capability declarations are authoring constraints only. A new runtime
must define its native identity, evidence, unsupported capabilities and recovery.

Configuration projects closed scalar schemas into existing Ambari config types.
Defaults/types/ranges/enums/lengths are enforced again before materialization. Templates
allow declared scalar substitutions only. `x-resource` fields inject private data
paths; users cannot override them. `configurationRef` and `directoryRef` are typed
arguments, not arbitrary request argv. Host-service/v1 now resolves scoped references
through existing credentials and Agent encryption; consolidated verification is pending.
General nested configuration remains unsupported. Configuration changes require restart semantics;
none/reload/migration effects are rejected. Secret source defaults use references,
and unsupported execution is rejected before mutation. No secrets or raw
native stderr should enter persisted plans, diagnostics or task output.

Desired configuration/tags remain authoritative in Ambari. The Agent stages a complete
local generation and atomically switches its current pointer; the receipt separately
records published and verified running generations. A new config START restarts an
active service. Failed/partly applied work remains observable and recoverable; there
is no cross-host atomic config transaction. Changing software digest is not ordinary
configuration and is rejected without a defined upgrade contract.

## Operation and recovery

Existing persisted request/stage/task is intent/audit authority. ActionDBAccessorImpl
pins ServiceRef, package digest, target incarnation, assigned host/role, actual operation,
service config values and tag/field hashes immediately before execution_command storage.
Only the service's own config types enter that task. Current Agent cache-derived
configuration and host/component assignment are checked separately from the persisted
payload; stale values cannot reinterpret the task. Reserved `runtime_*`
and `mpack_*` caller parameters are rejected. The old dispatcher is retired. Generated
Script mutation requires a server execution task and assigned Agent; it cannot grant
itself authorization or run an Agent-local business recovery loop.

The local plan binds task ID, ServiceRef/native incarnation, package digest,
configuration hash/tags, observation, expected receipt and expiry. The receipt is
materialization evidence protected by local flock and atomic fsync/rename, not a
parallel workflow database. Older tasks, changed intent under one task ID, stale plans
and unowned native units fail before mutation. Pending unit hash covers publication
crash windows. Uninstall/adoption cannot be inferred from a resource name.

States are scoped: Ambari task state remains unchanged; structured output/receipt
records APPLYING, SUCCEEDED, FAILED or UNKNOWN. Cancellation remains the existing
platform request; UNKNOWN means side effects cannot be disproved and automatic retry
is disabled. Do not map a cancellation request to proven native cancellation. A late
successful/UNKNOWN result retains that evidence. Replay of success verifies actual
state; interrupted start may reconcile a new InvocationID. An ambiguous invocation
requires an explicit stop/observation before restart. There is no generic recover=restart. Distinct newly created API requests remain
distinct intents; replay protection is tied to persisted task identity, not a new
client-supplied idempotency API. Explicit RESTART has one intent/checkpoint and
native invocation postcondition. STOP can run despite invalid desired configuration;
status uses a minimal probe from the verified running generation, not the next desired
port. A changed package digest cannot gain implicit upgrade permission through STOP.

Pending native jobs and interrupted starts without surviving invocation evidence
remain UNKNOWN; the driver cannot infer that repeating START is safe. Declared IPv4
listeners are checked before provisioning/publication, with no claim of atomic port
reservation. HTTP probes do not follow redirects.

Native commands drain bounded output under deadlines and process-group cancellation;
actual loaded/active-PID/health/inactive postconditions decide outcomes. Local receipt
loss, foreign target or unsupported migration requires explicit investigation. Keep
data unless a separately authorized purge explicitly targets the verified retained
incarnation. The active, unverified purge extension below does not authorize arbitrary
paths or promise data recovery.

For a profile declaring `purge`, stop the service through its normal workflow, run
and verify UNINSTALL, then submit existing custom command PURGE with
`RequestInfo.parameters.expected_target_incarnation` from `mpack_resources`.
SERVICE.PURGE_DATA is a distinct permission, granted to Ambari Administrator by
default in fresh DDL and upgrade. The expected incarnation is a request precondition;
it does not grant ownership. Server compares it under the existing service row lock
when persisting task intent. The service record must still exist. Historical resource
rows expose `currentServiceTarget=false`; UI offers no service mutation for them.

Once a purge intent is accepted, only explicit purge recovery can advance that
target. STOP/UNINSTALL cannot replace partial-purge recovery evidence. Agent requires
the saved retained device/inode inventory, native unit absence and bounded traversal
without following symlinks or crossing mounts. Successful purge retains the receipt
and operation lock. Server requires matching per-resource purge evidence before
releasing the catalog reference; immutable package/task identity remains in the audit
row. Restarting under that incarnation is forbidden. No orphan purge after service
record deletion, implicit data rollback or shared OS package/user deletion is provided.

### Active artifact upgrade and ownership extensions (unverified)

The selected service repository expresses desired software. The same-DB
`mpack_target_resource.mpack_id` references latest task intent;
`materialized_mpack_id` references the last verified installed release. Failed candidate
work must preserve both catalog references. Existing rows without confirmation remain
unknown. Service PUT selection uses the existing upgrade permission and an expected
incarnation under the service row lock; all targets must be stopped on one confirmed
release. A new candidate needs signed compatible/data-unchanged admission. UPGRADE then
pins the selected digest and incarnation in an ordinary custom task. Selecting the last
confirmed release after failure restores metadata only, not data. Reconcile partially
upgraded hosts with the current candidate before selecting a different release.

Optional paired DETACH/ADOPT capabilities use SERVICE.ADD_DELETE_SERVICES and the
expected existing incarnation. DETACH hands a stopped target to external ownership
without removing its unit, files or data. ADOPT reclaims only that same detached target
with unchanged unit/publication identity and no live secrets. Pending handoff permits
only the matching recovery command. Verified DETACHED evidence permits service removal
and catalog-reference release; native resources remain external. After removing the
service record or catalog definition, this adoption path ends. Foreign units and new
incarnations cannot be adopted by guessing their names.

`host.files/v1` is a CLIENT resource contract. It shares the host task journal and
staging flow, but emits file publication/readiness evidence without a PID, invocation
or unit. Install/configure verify file hashes/modes and the configuration pointer.
Uninstall withdraws that pointer while retaining files; purge requires the usual
separate permission and exact retained-path evidence. File clients support neither
process actions nor live-secret consumers. Server removal admission distinguishes
file-publication absence from native systemd absence.

The optional observability mapping projects to existing REST metrics and LogSearch
consumers. It adds no collector, raw-log task transport or authorization authority.
Metric mappings select numeric fields only from a dedicated non-sensitive endpoint;
logs require the existing LogSearch platform and its collector/redaction configuration.

## Catalog consistency

Catalog DB is authority; files/Stack links are required projections. Pending markers
only support reconciliation. Startup completes committed publication or quarantines
uncommitted definitions. Failed DB rollback retains required files. Removal atomically
deletes unreferenced catalog/repository/Stack rows before filesystem quarantine.
Reference writes in Blueprint/cluster/repository/Stack DAOs and catalog removal
share the existing package-row lock until transaction completion. Foreign keys and
Blueprint scope validation provide the remaining guard; historical JSON references
are checked. Deleted Stack/repository identity caches are invalidated. Catalog removal does not uninstall native software.
Single-server filesystem ownership is the current integration boundary.

## Shared dependency and consumer boundaries

A BindingRef uses the shared UUID, incarnation, immutable endpoints, snapshot revision,
authorization and lifecycle/fence evidence. `DependencyAdapter` requires an injected
`binding/v1` client and delegates; it cannot manufacture approval, lease, readiness or
binding identity. Missing support fails `DEPENDENCY_UNRESOLVED`. No Mpack binding DB,
second authorization layer or host ownership map is introduced. Available reference
APIs/types are described in status; they must not be guessed. Historical
software-specific walkthroughs do not add requirements to the active delivery plan.

UI/CLI/AI have no execution authority. AI output follows the same source validation,
diff/review, trusted export and authenticated server import as human output. No AI
provider or arbitrary plugin JavaScript executes in this repository's runtime UI.
The disconnected runtime route is removed; catalog and existing service APIs remain.

Stable diagnostic categories include SCHEMA_INVALID, CAPABILITY_UNSUPPORTED,
PACKAGE_CONTENT_CONFLICT, DEPENDENCY_UNRESOLVED, PLAN_STALE, TARGET_CONFLICT,
AUTHORIZATION_DENIED and OUTCOME_UNKNOWN. Error text must not echo input secrets.
Unsupported features and external acceptance limits must stay visible in status.
