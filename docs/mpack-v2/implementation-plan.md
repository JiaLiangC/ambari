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

# Mpack implementation plan

This is the single active Ambari implementation plan. The audit remediation below is
completed; package import/lifecycle P0-P6 and P8 is authorized but paused at the user-requested
unverified progress checkpoint. Resume only when requested; see the final checkpoint
section in [status.md](status.md).
The user removed the Kyuubi example on 2026-09-10; this is not a postponement.
Its dedicated P7 integration and Kyuubi-specific P8 work are removed from the
current plan. Preserve generic dependency rejection and historical audit evidence.
The independent review was recorded before source
changes. Finish the implementation/documentation batch before the consolidated
compilation, validation and test phase, as requested. The subsequent user request
authorizes one consolidated commit and publication to origin/AMBARI-14714-mpack-v2-remote.
That authorization describes the completed audit delivery, not automatic publication
of the new Store proposal or implementation.
Do not deploy a live cluster, modify another worktree or overwrite unrelated changes.

## Ordered work and local acceptance

| Order / findings | Required outcome and modules | Prerequisite | Local acceptance |
| --- | --- | --- | --- |
| D0 / F15 | Consolidate architecture, contract, manifest, examples, plan and status; preserve original review and exact Git provenance | Baseline audit | No obsolete active work orders, dangling document links or contradictory completion claims |
| S1 / F01 | Reject reserved runtime/mpack request parameters; retire arbitrary Agent dispatcher; disable retry of rejected/UNKNOWN work | Existing request RBAC and Agent task path | Request parameter tests and queued-command guard; no subprocess for untrusted commands |
| A2 / F06,F07,F11 | One validator, explicit inventory, consumer-scoped requirements, scalar/secret constraints, deterministic source export and verified signed legacy modules | S1 | Source validation, tampering/secret/symlink/offline tests; compiler-produced archive imported by actual MpackManager |
| C3 / F08 | Recover catalog publication; preserve files on failed DB rollback; atomic reference-protected deletion and restart cleanup | Existing package row lock and Stack/Blueprint FK model | Crash-window/mock-DAO tests and in-memory DB rollback/reference tests |
| I4 / F09,F12 | Bind package digest and service incarnation through existing DB/task/metadata; reject unsupported Blueprint composition/lifecycle authority | A2,C3 | Metadata serialization/change detection, persistence boundary and identity tests; fresh DDL/migration review |
| H5 / F02-F05,F12 | Shared host Script using installed signed descriptors, existing task intent, typed staged config, native identity/health, bounded execution and conservative recovery | A2,I4 | Fake-native lifecycle/config/lost-response/stale-task cases; real local subprocess timeout/output cases; no mock reported as systemd acceptance |
| P6 / F10 | Remove fabricated dependency authority; retain injected client contract and explicit Kyuubi rejection without shared implementation | Real shared contract reference | Delegation/denial/missing-client and source fixture tests; no fabricated binding endpoint/approval |
| U7 / F13 | Remove nonexistent runtime API/UI route; keep actual catalog registration/removal and service workflows | C3 | Catalog/route model tests and React production build; update relevant frontend baseline/gap notes |
| V8 / F14 | Run consolidated local checks after D0-U7 edits, correct failures, record exact results and limits | Entire implementation batch | Authoring, Agent/common, server tests/compile, RAT, React tests/build, doc/conflict/secret-location checks |

D0-V8 and the three requested follow-up inspections are complete for the local
repair scope; exact results, defects found during verification and open product
gates are recorded in [status.md](status.md).
A passing fixture does not close native/platform acceptance. During V8, fixes for
observed failures may be followed by the affected checks; do not rerun unrelated
successful suites without a new reason.

## Original-review completion gate

The follow-up reconciliation in status.md covers F01-F15, both software walkthroughs
and all original repair-order rows. It found omissions in durable task binding,
configuration/host snapshot handling, inherited restart, registration replay and
failure coverage. These were added to the implementation batch. The previous
completion announcement is superseded. Preserve a disposition and verification evidence for each original requirement:
implemented and locally checked, removed unsafe consumer, or explicit
still-unimplemented product/external prerequisite. A gate/removal is not
completion of the missing platform feature.

Consolidated producer/consumer execution must generate an HTTP signed export outside
the repository, pass `-Dmpack.host.fixture=<directory>` and
`-Dmpack.task.fixture=<output-json>` to the Java tests, then run the Python consumer
case with `MPACK_TASK_FIXTURE=<output-json>`. Without these inputs the optional cases
skip and must not be counted as passed integration. Include TestCustomServiceOrchestrator
and MpackTaskBindingTest in addition to the suites listed above.

## Three follow-up inspections

After the planned implementation batch and initial consolidated checks, independently
inspect (1) identity/authorization/data integrity, (2) operation/fault recovery, and
(3) compiler/runtime/document consistency. Correct issues and run the affected checks.
The completed record in status.md includes reference/delete locking and JPA eviction,
redirect/listener boundaries, conservative interrupted-start handling, immutable build
inputs and early rejection of unsupported schema semantics. Reconcile every F01-F15
item and original repair-order row; missing platform features remain explicit gates.

## Explicit product and environment gates

The current repair scope is a safe, connected host alpha plus existing catalog;
it is not the entire future general-software platform. The following are real gaps,
not silently completed tasks or missing-tests-only explanations:

- OCI, Kubernetes and external database execution: implement runtime-specific native
  identity, apply/postconditions, cancellation and recovery against real runtimes.
- Secret runtime resolution, generic observability API, client-only host profiles,
  same-cluster independent service aliases and multi-package selection require
  concrete consumers and minimal extensions of existing Ambari contracts.
- Upgrade/data migration/rollback/adoption/detach/uninstall/purge require explicit
  compatibility/ownership/retention semantics and separate destructive authorization.
  The current host contract must reject these rather than guess or delete data.
- Native Redis/systemd and live server-Agent acceptance, production database fresh/
  upgrade execution and cross-cluster provider acceptance need environments outside
  this task's authorized local checks. No live target is deployed here.

Do not introduce another identity system, workflow database, binding database,
authorization service, message bus or distributed transaction manager to hide these
gaps. Next implementation should extend one proven vertical path at a time.

## Documentation consolidation

`architecture-decisions.md` and `multi-cluster-alignment.md` are merged into
architecture/contracts. Runbook, work orders and integration/design plans are merged
here. Execution logs and W0/W1/M2/R1 checkpoint documents are replaced by the single
status ledger and the preserved independent review. Their historical contents remain
at `c7dc663f7c68f58656be22b5ec19f9a9c4499412`; no original evidence needs duplicated
active instructions. Earlier per-worker/tmux/model/publication directions are obsolete.

## Package import and lifecycle delivery plan

### Requested authoring usability delivery

Before the broader platform work, complete the user's requested examples,
English development instructions and user-run validation scripts. Keep one canonical
set of examples under `mpack-authoring/fixtures`: HTTP, Redis and a multi-service
YAML package. Expand the existing authoring README into the development guide instead
of creating duplicate guides. Reuse compiler/export/verification code for a portable
validation command, plus an example-suite entry point. Checks must distinguish source,
host-export and bundle verification, produce meaningful exit codes/diagnostics, leave
source files unchanged and execute no runtime commands. Generic dependency rejection
remains covered by a focused contract test, without a dedicated software example.

Complete this source/documentation batch before consolidated authoring tests, script
acceptance and document checks. Record actual results in status.md; Store implementation
remains reserved for its future repository.

The earlier authoring usability delivery completed four documented examples, the English
guide, `validate.py` and seven focused regression tests. Consolidated authoring tests
(35), example expectations (5), guide command checks and root RAT passed for that
earlier delivery; exact environment and evidence are recorded in status.md. The current
three-example revision is unverified until the consolidated run. This does not complete
the active platform work below.

### Authorized platform delivery

#### Software behavior belongs to the package

The user's clarification is a binding implementation constraint: Redis and every
other software product are package consumers, not Ambari core features. Product
installation recipes, configuration templates, health semantics, compatibility,
backup/migration/restore procedures and declared capabilities belong to the signed
Mpack. Ambari owns generic validation, service identity, authorization, persisted
requests/tasks, configuration delivery and runtime-specific execution/recovery.
Adding software under an existing runtime must not introduce software-name branches
in Java, Agent Python or UI, nor copy a platform lifecycle.

Assess the remaining P6 work as a package extension-contract gap, not a request for
Redis-specific core upgrade or database-recovery code. A package declaration cannot
make a missing executor or an unsafe migration safe: unsupported behavior must be
rejected until its generic execution, verification and recovery contract exists.
Shared OS packages remain host prerequisites; a package cannot claim exclusive
ownership or silently upgrade another deployment's binaries. Package-specific
examples and acceptance fixtures are the appropriate place to demonstrate these
constraints. No special Redis adapter, UI or Server lifecycle is to be added.

P6 reload uses an explicit systemd signal and HTTP generation acknowledgement.
The process must return the rendered `mpack_config_generation` token in the
`X-Ambari-Config-Generation` response header at its declared local health endpoint.
Unchanged process invocation, matching generation and healthy state are required;
signal delivery alone is never success. Profiles with process environment secrets,
restart-only configuration, or a changed unit command must restart. After response
loss, query the generation before considering success; never blindly repeat reload.

This plan covers Ambari package import and software lifecycle only. The independent
[Store design](store-design.md) owns its S0-S4 plan for later implementation in a new
repository. Store pages, backend, publisher accounts and publication jobs are not
Ambari deliverables. The [architecture extension](architecture.md#package-import-and-lifecycle-extension-proposed)
owns Ambari design decisions. The user authorized completing every row sequentially,
then running consolidated compilation, tests and validation. The subsequent
2026-09-10 scope change removes Kyuubi/P7; all other rows remain active
implementation work, separate from the completed audit remediation and its evidence.
Implement P0-P4 first, prepare the P5 acceptance harness, then P6-P8; execute P5 and
other consolidated checks only after the implementation batch is complete. External
provider/runtime acceptance requires the corresponding actual contract/environment;
do not substitute mocks or mark an unavailable external capability complete.

| Order | Result and modules | Dependencies | Acceptance |
| --- | --- | --- | --- |
| P0: contracts and trust | Versioned registry/release envelope; publisher namespace and packaging/software versions; asymmetric verification; explicit legacy policy; immutable digests and prerequisite inventory. Authoring, catalog metadata, importer. | Current deterministic export and actual import path | Locally build/import one package; reject modified bytes, unknown key, incompatible format, changed bytes at the same release identity, unsafe archive/redirect and false offline closure. Preserve explicit alpha HMAC mode without downgrade. |
| P1: existing-cluster composition | One service-scoped package resolver across metadata/config/script/task/Agent delivery; multiple installed package versions; conflict checks. Existing repository/service/catalog state. | P0 | Local integration selects HTTP and Redis from independent packages in one existing cluster, preserves original Stack/service/RBAC/host identity, rejects duplicate service/config conflicts and stale package selection. Verify separate clusters can pin different versions; do not claim same-cluster aliases. |
| P2: reliable uninstall and retention | Owned-resource inventory; existing uninstall tasks; partial failure/recovery; durable retained-resource evidence; safe catalog reference checks. Server, shared host Script, DAO/audit. | P1 and existing task/incarnation protection | Fault-injection checks before/after stop/delete and lost response; exact resource absence, retained data/shared users/packages unchanged, wrong-incarnation cleanup denied, concurrent removal blocked. Retention evidence survives service deletion and task-log expiry; referenced packages cannot disappear. |
| P3: file/URL importer | One staged importer for local uploads and approved artifact URLs; bounded transfers/extraction, signature checks, private-source credential references and idempotent registration. Ambari API and MpackManager. | P0; no running Store or discovery API required | Import identical compiler exports from a file and local artifact server; reject tampering, untrusted signatures, unsafe redirects and partial uploads; interrupted import leaves no available incomplete definition. |
| P4: Ambari user flow | File/URL import, imported-package version/compatibility/trust details, install wizard, service status/config/log links, uninstall and remove-definition actions. MpackManager, Classic baseline and React UI; no Store pages. | P0-P3 | Browser/API integration imports two publishers' HTTP/Redis packages from files or a local artifact server, installs into an existing cluster, changes config, observes, uninstalls retaining data, inspects retained-data evidence and removes only unreferenced definitions. Authorization denial and failure/refresh recovery remain visible. |
| P5: host production acceptance | Native identity/provisioning/health/uninstall, live Server-Agent failure recovery, production DB fresh/upgrade and distributable packaging. | P0-P4 implementation batch | Consolidated local suites/builds first; then an explicitly provided integration environment verifies real HTTP/Redis/systemd, Agent/Server restart, repeated submission, response loss and artifact-source outage. Fixtures alone do not open the product gate. |
| P6: full host lifecycle and observability | Scoped secret resolution, metrics/log access, client components where needed, capability-gated reload, upgrade compatibility, explicit migration/recovery, adoption/detach and separate purge. Existing config/RBAC/workflows and host adapter. | P5; appropriate secret/observability platform integration | Locally verify secret-reference-only persistence, authorization/redaction, lifecycle fault paths, compatibility denial and retained-resource ownership. Real runtime acceptance proves upgrade behavior and any promised backup/restore; irreversibility is explicit. |
| P8: further runtimes and authoring assistance | OCI, Kubernetes, external database adapters; schema-driven UI/CLI and AI validation/repair with reviewable diffs. | Stable release/service contracts; per-runtime native access and dependency support | Each profile independently proves identity, supported actions, postconditions, data ownership and recovery in its real runtime. AI-generated Redis/HTTP sources validate/build offline without bypassing trust, approvals or service authorization. |

P0-P5 constitute the first usable Ambari import-to-management release. Store
implementation is independent and not a prerequisite. P6 and P8 remain required
roadmap capabilities, outside the explicitly bounded first host release. The removed
P7 identifier is not reused, so historical audit and progress references remain stable. Runtime support is added independently;
do not advertise unsupported OCI/Kubernetes/database execution or automatic rollback.
For an external database, install/uninstall can be unsupported while connection,
configuration and observation are supported; capability names do not erase ownership.

Implement the agreed batch before consolidated compilation/verification/testing, as
requested. Do not run an entire build after each small change. Fix issues found by the
consolidated run and rerun affected checks. Separate executed local checks from browser,
native runtime, production DB and external-platform acceptance; never infer results.
Before React edits inspect the relevant Classic source and frontend baseline.

### Effort and migration tradeoffs

| Change | Benefit | Cost / migration impact | Ongoing maintenance |
| --- | --- | --- | --- |
| Extend deterministic export with publisher trust | Multi-author distribution without sharing Ambari's signing secret | Versioned envelope, trusted-key administration and explicit compatibility import path | Key rotation/revocation policy and one verifier; avoid separate file/URL verification stacks |
| Resolve package definitions per existing service | Add software to current clusters without replacing Stack/service identity | Highest Ambari integration cost: metadata/config/tasks/upgrades and cache invalidation must agree | One resolver and conflict policy instead of per-software branches or copied Stacks |
| Add exact uninstall and durable retention evidence | Recoverable cleanup and safe later purge | Resource inventory plus existing operation integration; a small same-DB tombstone only if existing audit retention is insufficient | One ownership contract shared by uninstall/recovery/purge; no new lifecycle engine |
| Reuse local package and service screens | Consistent permissions, config and operation history | Extend file/URL import and existing management UI/API; update parity evidence | No Store pages or publisher portal in Ambari; schema/capability-driven management |
| Gate advanced runtime/data semantics separately | A usable host release without false universal promises | Explicit adapters and native fixtures per runtime; shared dependencies require real platform contracts | Pay for concrete native differences; defer plugin sandbox, generic workflow DSL and second authority services |

The authorized Ambari execution scope is P0-P8. The Store will be implemented later
in a new independent repository according to store-design.md. File fixtures and a local
artifact server suffice for Ambari integration work; no Store infrastructure is needed.


### Active implementation ledger (verification deferred)

The user requested completing the implementation batch before any consolidated
compilation, validation or tests. No new passing result is claimed for this batch.

| Work | Source changes in progress | Remaining work before acceptance |
| --- | --- | --- |
| P0 | Publisher Ed25519 export/public-key verification, complete metadata signature, durable release metadata, compatibility comparisons | Final trust/import regression execution; wheel/distribution acceptance |
| P1 | Existing repository selection, service config mapping and credential metadata cache scope, package conflict checks | Reconcile every Stack/config/UI consumer, regression coverage and consolidated integration |
| P2 | Shared host uninstall, native absence postcondition, retained path/inode evidence, task-linked same-DB retention records, service/component/catalog removal guards, seven DDL variants and upgrade path | Fault-path/upgrade coverage, lifecycle permission and stale-report review, consolidated checks |
| P3 | Deterministic `.mpack` transport, binary upload, shared staged importer, approved origin/path policy, no redirects, credential-store references, byte/time bounds | Local artifact server/API fixtures, documentation and consolidated execution |
| P4 | Upload and release details; package-specific service/host/config install dialog; existing request actions; scoped retained-resource view | Existing-service configuration/observation integration, UI/API failure-recovery tests and consolidated build |
| P5 | Opt-in disposable Server-Agent import/install/start/stop/uninstall/retention harness added under dev-support/mpack; not executed | Native fault injection and production DB environments remain required; no external acceptance result claimed |
| P6 | Scoped secrets/reload/purge; compatible artifact upgrade and confirmed-release protection; file-only CLIENT; existing metrics/log projections; bounded DETACH/ADOPT source and regression cases | Finish integration/test-source/documentation closure; generic package-owned data-operation execution/recovery and shared-prerequisite compatibility remain open; no software-specific core lifecycle; consolidated verification deferred |
| P8 | Shared source review/diff, schema-driven authoring UI/CLI and English guide; local OCI source, shared Script routing and native-result fixture cases | OCI/Kubernetes source closure; external database implementation remains open; consolidated verification deferred |

A concrete P1 defect was found during source tracing: StackId splits its string at
the first hyphen, so authoring package names cannot safely be reused as Stack names.
Authored packages now derive a hyphen-free `MPACK_<sha256(catalog-name)>` compatibility
projection. The package name, publisher, version and ServiceRef are unchanged. Existing
repository/config/service foreign keys remain tied to their existing Stack row; migration
and projection cleanup must be reconciled before acceptance. This is not a new service
identity or deployment database.

The user removed the Kyuubi example and its dedicated integration work on
2026-09-10. Delete its source fixture and example-suite cases, update the English
guide, and retain generic unresolved-dependency rejection coverage using a temporary
HTTP-based contract fixture. This is a scope removal, not a deferred P7 task. The
earlier request for Spark/Hadoop/Hive contract locations no longer needs an answer.
Historical review evidence is retained and does not reintroduce that work.


### P6 secret execution boundary

Use the existing cluster credential store and Agent AES-GCM capability/key distribution.
Persist only scoped `secret://mpack.<SERVICE>.<alias>` references and keyed generation
fingerprints in the existing task binding. Resolve and encrypt on a detached command
copy at dispatch, after checking the existing host/service assignment; never write
plaintext into the DB execution command, catalog, source bundle or unit. A changed
credential between intent and dispatch invalidates the plan. Agent materialization uses
short-lived runtime files with restrictive ownership; command arguments cannot contain
secret values. This adds no credential database, authorization service or key exchange.
Tests must prove original command immutability, scope denial, rotation/stale binding,
Agent encrypted transport, reference-only receipts and cleanup after stop/uninstall.


The secret implementation uses a distinct `SECRET_REFERENCE` property type so ordinary
Ambari password substitution never resolves these references into persisted config.
Sensitive schema fields are closed `{secretRef: string}` objects; the legacy scalar
projection exposes only the reference URI. Environment references use a private runtime
EnvironmentFile; process arguments reject secret values. Secret-bearing rendered config
lives under `/run/ambari-mpack`, while receipt/config generation records contain references
and keyed versions only. Original DB commands remain unchanged by dispatch encryption.
Consolidated verification must generate `-Dmpack.secret.fixture=<external-json>` in
MpackSecretsTest and consume it using `MPACK_SECRET_FIXTURE` in TestMpackHost; otherwise
that interoperability case skips and cannot be counted as passed.


### Active batch integration findings

Source tracing corrected these issues before consolidated execution:

- Preserve the service cache if retention protection rejects removal; preserve complete
  task/identity/generation evidence when Agent recovery resolves a lost response.
- Reuse the previous Stack row during migration/reimport, before publishing the renamed
  compatibility link; keep existing foreign keys.
- Keep the legacy string-valued `prerequisites` field intact. Publisher inventory uses
  signed `installationPrerequisites` and API `MpackInfo/prerequisites`; mixing the two
  would break Gson deserialization and the legacy Java getter contract.
- Validate the signed host schema before configuration persistence and again against
  the effective host config before task persistence. The Agent still validates the
  persisted snapshot before side effects. Controlled directory values cannot be
  supplied by a UI caller. Values never enter schema error messages.
- Accept existing REST-created PrincipalKeyCredential as well as GenericKeyCredential
  in scoped execution/download resolution. Requiring only the internal generic type
  would leave the public credentials API unable to supply these consumers.
- A failed registry query no longer hides locally imported definitions. Refreshes bind
  resource data and actions to the originating cluster; retained orphan resources have
  no active-service mutation buttons. Repeated install cannot silently stop a running
  service. Native uninstall requires an explicit existing stop workflow first.
- Reuse generic service/config pages and existing Host Logs rather than adding package
  name branches. Host Logs must consume the actual ServiceContext dictionary shape.
  Full package application-log collection still requires its collector integration;
  a navigation link is not collection evidence.
- Add an independently distributable authoring wheel definition; copy the single schema
  only into build output. The Store implementation remains outside Ambari.

All new source and regression cases above are unexecuted. The final batch must include
MpackConfigurationTest, MpackSecretsTest, MpackTrustTest, the updated encryption fixture,
HTTP generation/reload cases, Management Packs/Host Logs cases, wheel installation in
an isolated environment, and Java-to-Python fixtures generated from these current sources.
Do not reuse the previous HTTP digest or previous passing counts as current evidence.


### P6 purge boundary

A separately authorized PURGE task uses SERVICE.PURGE_DATA (Ambari Administrator by
default), the existing request/task path and the existing incarnation/receipt lock.
The first implementation requires the service record still to exist and a verified
UNINSTALL receipt; operators purge before removing that record. Purge after record
removal needs a separate retained-target task entry and is not silently supported.
No package can declare arbitrary cleanup paths. Match retained device/inode evidence,
require the native unit absent, reject nested mounts, and bound FD-relative traversal.
Retain a root-owned receipt tombstone and operation audit; reject future starts under
that purged incarnation. Retry only the remaining matching owned paths after a partial
purge. Verified PURGED rows may release their catalog FK while keeping immutable
package identity/digest in their task binding. No backup or data rollback is implied.

Additional source fixes (not test results): fresh DDL explicitly grants the new purge
permission only to Ambari Administrator. Accepted purge intents cannot be overwritten
by ordinary lifecycle tasks. Purge requests carry the selected retained incarnation
as an expectation checked under the service row lock, and UI separates historical
rows from current targets and offers explicit partial-purge recovery. Empty or
incomplete purge evidence cannot release catalog references. Managed JPA retention
rows are updated before catalog deletion so a held entity cannot restore a stale FK.

Secret dispatch checks current service incarnation and selected component package
before reading credentials. Upload tests cover denial before reading bytes, exact
temporary staging/cleanup and interrupted or empty input; local transport imports
retain the verified installed metadata URI. All these tests are written but unexecuted.

### P8 shared authoring and configuration UI

Reuse the existing StackConfigurations property/value-attributes projection for
installation controls: scalar types/ranges, boolean choices, enum entries and
SECRET_REFERENCE. Compiler derives it from the same schema used by Server/Agent;
the UI does not become schema authority or run package JavaScript. String length
constraints remain enforced by Server/Agent and are shown as generated help text.
No second schema endpoint or parallel model in release metadata is needed.

The shared `mpack-review` / `validate.py review` entry validates baseline and candidate
sources, then emits changed JSON-pointer fields and payload digests, omitting values.
It writes nothing, runs no software, and grants no signing, import or execution
authority. Human and AI edits use this same path. Invalid repairs fail without echoing
input values; valid source review still needs host export validation and a local human
source diff before signing. This is an authoring aid, not an AI provider or autonomous
migration engine. CLI/UI source and focused regression cases are added; execution
remains deferred to the consolidated run. P8 runtime implementations remain open.

### P6 compatible artifact update

Extend the existing host profile with an explicit UPGRADE custom command for stopped
targets. A signed `upgradePolicy` names accepted previous package digests and declares
`configuration=compatible`, `data=unchanged`. Only vendored artifact updates under the
same package identity and unchanged resource layout are eligible; OS package upgrades,
directory/user changes and data migrations do not fit this contract. No migration hook
or automatic rollback is added. Existing configuration validation applies before
staging, and unit loading/config publication must be verified before completion.

Use the existing cluster upgrade authorization, service/repository selection, task
intent and target receipt. Preserve previous release identity/digest in a bounded
receipt history and retain normal server request/task audit. An interrupted stopped
update can repeat staging only for the same declared transition; starting requires
completion first. Pre-existing receipts without layout/release evidence fail closed.
This scoped artifact update is not evidence of a Redis OS package upgrade, data
migration, adoption/detach or production upgrade acceptance. Those gates stay explicit.

The existing service desired repository records selection. The existing
`mpack_target_resource` projection separately stores `mpack_id` for latest task intent
and nullable `materialized_mpack_id` for the last identity-verified Agent receipt.
Both reference the catalog so a failed candidate cannot release the old definition.
No new deployment identity, scheduler or authorization store is introduced. Existing
records without confirmed-release evidence must pass a successful task before changing
selection; the DDL upgrade never guesses the installed release.

Changing selection uses the existing service PUT, cluster upgrade permission and
`expected_target_incarnation`, under the service row lock. All targets must have
stopped native evidence on one confirmed release. Selecting that confirmed release
restores metadata after a failed attempt; it does not restore data or start processes.
Other candidates require signed compatibility admission. The subsequent existing
UPGRADE request pins both target incarnation and candidate digest. A selected candidate
with partially upgraded hosts is recovered by another UPGRADE request, without changing
selection. Page-limited UI evidence cannot establish whole-service completion.

Source regression cases cover failed upgrades retaining the old catalog reference,
late reports, mixed target versions, lost selection responses, interrupted unit
publication and explicit STOP recovery. Successful cleanup retains the current and
running artifacts plus at most ten previous release records. These cases have been
written but not executed; all batch verification remains deferred.


### P6 client resource boundary

Add `host.files/v1` for CLIENT components that install vendored files and publish
validated non-secret configuration under their existing Agent target directory.
It shares task pinning, the target lock/receipt, staging, retention and purge with
host execution. It creates no systemd unit or process and has no start/stop/reload,
OS-package upgrade, data migration or live-secret lifetime promise. Observation proves
exact staged file hashes and the published configuration link; absence means the
client publication has been withdrawn, while retained files remain protected.

The compiler rejects process resources, unknown executable artifact references and
secret values for this profile. Existing Ambari CLIENT semantics supply installation
state and omit service start/stop tasks. Native uninstallation is a capability-gated
custom task; it unpublishes configuration and preserves retained data until separately
authorized purge. Agent results explicitly identify the files profile so the Server
checks file absence instead of pretending that a client is an inactive systemd service.


### P6 observability integration boundary

Use the existing `StackDefinedPropertyProvider`/`RestMetricsPropertyProvider` and
`LoggingSearchPropertyProvider` consumers. Both already resolve definitions through
the selected service Stack. Add a bounded declarative `service.observability` mapping:
per-component REST metric paths with a schema-validated port reference, and existing
LogSearch log IDs. The compiler emits only the built-in REST metric provider and
metainfo log definitions; package authors cannot select arbitrary Java provider classes.
Metrics remain subject to existing metric-view RBAC; logs remain subject to
SERVICE.VIEW_OPERATIONAL_LOGS and the existing LogSearch endpoint/caches.

This is metadata/API integration, not a bundled collector. The supported metric
endpoint must expose non-sensitive numeric JSON reachable from the Server on the
assigned component host. Loopback demonstration servers are not remotely reachable.
LogSearch/collector installation, transport, indexing and redaction are external
prerequisites; task output/receipt never becomes a raw application-log transport.


### P6 ownership handoff and adoption scope

DETACH hands a stopped, verified `host.systemd/v1` target to external management
without deleting its unit, files or data. ADOPT reclaims that same detached target
only while the existing service incarnation and package remain available. Both use
SERVICE.ADD_DELETE_SERVICES, existing custom tasks, an expected incarnation, native
unit identity/hash and published artifact/config evidence. No arbitrary path, process
name, foreign unit or replacement service incarnation can be adopted. Both require
unchanged configuration and no live secrets. This is a deliberately bounded adoption
contract, not automatic discovery and takeover of pre-existing software.

A pending ownership handoff must be reconciled with the same command. Verified
DETACHED evidence permits service-record removal and releases catalog references when
otherwise unreferenced; native resources stay on the host for their external owner.
After the service record or package is removed, adoption through this contract is no
longer available. While the service remains, ADOPT must complete before any managed
start, update, uninstall or purge. The ordinary task history and independent retained
resource projection record the handoff; no new ownership database is created.


### P8 local OCI execution boundary

Implement `oci.container/v1` through the existing signed package Script and host task
receipt. The runtime is a local rootful Docker or Podman engine, with a preloaded
immutable image digest; this slice does not pull from a registry, configure daemon
credentials or execute arbitrary engine flags. Install creates a stopped container;
start/restart/stop inspect its bound full container ID and actual readiness. Configure
publishes mounted config files, with a separate restart required to apply them.
Uninstall removes only the bound container and retains declared host directories;
no image, shared user/package, anonymous volume or external resource is purged.

Persist engine identity, image ID, creation intent and full container ID. Recovery of
lost create responses requires the persisted intent label, package/incarnation labels
and engine identity together, never a matching name alone. A vanished confirmed ID
requires explicit uninstall/reinstall. Directory binds stay under the target root;
configuration is read-only in the container. No privileged/host-network/socket mounts
or live secrets are accepted in this slice. Bound process/memory/CPU and log limits
are part of the declaration. Existing task cancellation and UNKNOWN behavior apply.

CLI contracts were checked against the primary
[Docker create documentation](https://docs.docker.com/reference/cli/docker/container/create/),
[Podman inspect documentation](https://docs.podman.io/en/latest/markdown/podman-container-inspect.1.html)
and [Podman info documentation](https://docs.podman.io/en/latest/markdown/podman-info.1.html).
This source/reference check is not runtime execution evidence.


### P8 Kubernetes execution boundary

Use `kubernetes.workload/v1` for one namespaced apps/v1 Deployment per existing
service/component/Agent target. Software image, command, environment and readiness
probe remain package declarations. A root-owned Agent connection reference supplies
HTTPS CA/client-certificate credentials and an allowed namespace; it is configured
by the operator, outside packages and task payloads. It is a transport credential,
not another Ambari identity or authorization store. Native Kubernetes RBAC remains
a prerequisite. Do not accept arbitrary kubeconfig exec plugins, raw YAML, remote
kubectl commands, cluster-scoped resources, host paths or privileged workloads.

The initial slice manages stateless workloads with scalar environment configuration,
non-root containers, resource limits and HTTP/TCP readiness. It does not provision
Services/Ingress/PVCs, store application secrets or promise database migrations.
Install creates a zero-replica Deployment; start/stop set declared/zero replicas.
Configure is allowed only after verified stop and changes the package-declared pod
configuration. No implicit rolling-update or restart semantics are promised.

Persist endpoint/CA identity, namespace UID, Deployment UID, creation intent and
configuration generation in the existing receipt. Use resourceVersion conditions
on updates and UID/resourceVersion delete preconditions. Lost create responses can
recover only the exact intent-tagged Deployment. Stopping/deleting must also observe
owned ReplicaSets/Pods, including terminating Pods; controller request acceptance
alone cannot establish completion. Bounded API reads/polling and UNKNOWN preserve
Ambari task recovery without a new reconciliation controller. A cancelled network
mutation can complete remotely and must be observed before retry.

The API concurrency/deletion and Deployment controller semantics are referenced from
[Kubernetes API concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/)
and [Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/).
Source fixtures and real Kubernetes acceptance must be reported separately.
