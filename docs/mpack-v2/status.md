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

# Implementation status and provenance

Updated 2026-09-10 UTC. This is the only current execution/status ledger.
The local D0-V8 repair plan, original-review reconciliation and three follow-up
inspections are complete. Consolidated validation and targeted failure corrections
are recorded below. This is a locally verified, bounded host alpha; external runtime
and full product acceptance gates remain open.

## Exact review scope

- Worktree: `/jialiangc/bigdata/prjs/ambari-mpack-v2`; branch `AMBARI-14714-mpack-v2-remote`.
- Initial trunk: `8051a841cf03673260fd025d6b9eeee68d98e0c4`.
- Community input: `05ffef5b6640a4adcc7af7fff1bec774539a55ae`.
- Provenance merge: `a34f92f1ac78feb22ce6de792d7175fae27ea4f0`.
- M2 candidate: `b72ade8fcfd553ff182f3d34fe63c0903616005a`.
- Reviewed R1 tip: `c7dc663f7c68f58656be22b5ec19f9a9c4499412`.
- Shared reference, read-only and not integrated: `8bf556b6ce94b350b3c3b12e15a7882d07bd19f7`.

M2 topics: `5c534fd6ae` server, `cf346698cc` Agent/common lifecycle, `d612c51395` UI,
`20845fca01` evidence, `b72ade8fcf` candidate record. Review included all 21 commits
following M2 (59 paths, +3540/-69) and initial working-tree state. The initial worktree
was clean apart from the subsequently created review report. After local repair
and verification, the user explicitly authorized committing and pushing the work
to origin/AMBARI-14714-mpack-v2-remote. Live-cluster deployment remains out of scope.
Original documents/checkpoints remain available with `git show c7dc663f7c:<path>`.

## Independent judgment and finding dispositions

The baseline report contains 1 BLOCKER, 8 HIGH, 5 MEDIUM and 1 LOW finding with
line-specific evidence, impacts, minimum fixes and regression requirements. The
architecture is viable as an Ambari extension; R1 was not a production general
runtime platform. Current repairs add a connected host implementation and remove
unsafe/unused alpha paths. Product and external acceptance gaps remain explicit.

| Finding | Current code disposition | Evidence entry points |
| --- | --- | --- |
| F01 BLOCKER execution authority | Reserved request inputs rejected; old arbitrary runtime dispatch retired; existing authorized Script workflow reused | RequestResourceProvider, RuntimeAdapter, ActionQueue, ManifestService |
| F02 HIGH process execution | Continuous bounded pipe draining, deadlines and process-group cancellation in shared host runner | mpack_host.NativeRunner; TestMpackHost |
| F03 HIGH replay/recovery | Persisted task binding plus local fsynced receipt, intent/config tags, task ordering, UNKNOWN no-auto-retry, observed invocation recovery | ActionDBAccessorImpl.pinMpackTask; HostDeployment.apply; ActionQueue; MpackTaskBindingTest |
| F04 HIGH postconditions | Exact native unit/fragment/invocation, active PID and application probe; stop requires inactive | HostDeployment.observe/verify; explicit native-output fixture |
| F05 HIGH discovery/target | Live systemctl discovery with scope/TTL; server-owned service incarnation, digest and stale-plan checks | ClusterServiceDAO, MetadataServiceInfo, controller, HostDeployment.plan |
| F06 HIGH secrets/content | Declared file inventory only, SecretRef defaults, credential URI rejection; host secret execution rejected | compiler/schema/config; authoring safety tests |
| F07 HIGH build/import | Deterministic source ZIP and distinct signed legacy export; exact import HMAC/digest verification; requirement slots consumer-scoped | compiler/legacy, MpackManager.verifyAuthoringArchive |
| F08 HIGH catalog consistency | Publication crash reconciliation, retained files on failed rollback; DB-atomic reference-protected deletion before filesystem cleanup | MpackManager/MpackDAO/BlueprintSettingEntity; Java tests |
| F09 HIGH task selection | Reject unsupported cross-package Blueprint selections; actual generated legacy modules select real service scripts | BlueprintResourceProvider, legacy exporter, task metadata |
| F10 MEDIUM shared authority | Remove synthetic binding readiness/approval/fence; explicit injected client; missing integration fails | dependency.py; shared reference type/API evidence |
| F11 MEDIUM contract divergence | Shared schema/semantic validation for CLI/compiler/fixtures; reject unsupported scalar projections early | schema.py/manifest.py/legacy.py |
| F12 MEDIUM false lifecycle/config authority | Remove unused Java/local workflow models; Blueprint metadata only; real host config generations and native binding receipt | MpackReference; ManifestService; existing DB config/task |
| F13 MEDIUM UI authority/API | Remove disconnected runtime route/client; preserve real catalog registration/deletion and service screens | RoutesList, ManagementPacks; route/model tests |
| F14 MEDIUM evidence/build | Full notices, fresh Server compilation and consolidated local checks passed | Command ledger below |
| F15 LOW documentation | One architecture/contract/manifest/examples/plan/status, preserved historical audit | README reading order; historical Git provenance |

A repaired defect is not evidence that every related future feature is implemented.
In particular no Kyuubi shared deployment, OCI/Kubernetes/database driver, generic
purge or generic runtime UI is declared complete by this table.

## Reconciliation against the original review (requested follow-up)

The original report remains unchanged baseline evidence. This pass compared all
F01-F15 minimum fixes/tests, the Redis/Kyuubi walkthroughs, the architecture adjustments
and all eight rows of its final repair-order table. The earlier statement that the
implementation batch was complete was premature. The following concrete omissions
were found and addressed in source/test edits before any consolidated execution:

1. F03/F05: topology/service metadata was not a durable task binding. The existing
   ActionDBAccessorImpl now pins package digest, service incarnation, host, role,
   operation and scoped config tags/hashes immediately before execution_command
   persistence. A service-row lock protects concurrent replacement, and the existing
   wrapper JSON cache is invalidated before persistence. No new operation table.
2. F03/F05/F12: latest Agent config/host metadata could reinterpret an older task.
   Existing command configuration is scoped and pinned; the Agent rejects hash,
   incarnation, package, action or current host/component membership mismatch.
   CustomServiceOrchestrator takes current membership from its cache after merging
   the header, never from a caller-supplied current-state assertion.
3. F03/F04/F12: inherited Script.restart invokes STOP then START under one task ID.
   The generated host Script now has one explicit RESTART operation and observed
   invocation recovery; it cannot silently become two incompatible intents.
4. F08: a repeated authenticated registration still conflicted after a successful
   lost response. Matching persisted content now returns the existing catalog identity
   and reconciles its Stack projection/markers; different content still conflicts.
   This applies to digest-bearing authored packages. Unsigned legacy duplicate
   registration retains its explicit conflict behavior; legacy crash reconciliation
   still uses existing catalog identity and pending markers.
5. F02-F05/F08/F11/F12/F14: missing regression cases were added for child-group
   timeout, cancellation during verification, late success/UNKNOWN, stage failure
   preserving current config, explicit restart recovery, current host assignment,
   service recreation, Redis through the shared driver, concurrent Blueprint commit
   versus deletion, registration replay, and actual Java-produced task serialization
   consumed by the Python driver. Their executed results are recorded below; native/platform acceptance remains separate.
6. F04/F12: STOP was unnecessarily coupled to desired configuration validation,
   and status health used the next desired port instead of the verified running
   configuration. STOP now validates target/content without requiring usable new
   config. Successful start/restart records a minimal running probe; status uses
   that probe and reports published/running generations separately. Tests cover
   invalid desired config, stale current cache, running-port selection and no
   implicit package upgrade through STOP.

| Original finding | Minimum fix coverage after follow-up | Original acceptance disposition |
| --- | --- | --- |
| F01 | Reserved runtime/mpack fields rejected; arbitrary executor retired; typed installed Script and persisted action/identity | Request/Agent guard and task-payload tests passed; no live HTTP/RBAC acceptance claim |
| F02 | Bounded runner/output/group termination; timeout/cancel retain UNKNOWN | Large stdout/stderr, hanging parent/child, cancel-before and verify cancellation cases added; native cancellation acceptance pending |
| F03 | Existing durable task pins intent; local fsynced checkpoint and ordering; retry suppressed for UNKNOWN; explicit restart intent | Duplicate/changed intent, reconstructed driver, lost response, late result tests added; actual server/Agent network restart remains pending |
| F04 | Runtime-specific postconditions; exact native identity/PID/health/inactive state; recover observed saved intent | Host stop/start/restart/UNKNOWN fixtures added; OCI/K8s postconditions deferred with those unimplemented drivers |
| F05 | Service-row incarnation, persisted host/package/config binding, cache-derived assignment, fresh discovery/observation and plan expiry | Target/config/host/recreation/two-cluster identity fixtures added; real port/user/runtime environment acceptance not claimed |
| F06 | Explicit inventory, external key, SecretRef defaults, bounded allowlisted native output; unsupported secret execution rejected | Authoring synthetic secret/key/diagnostic tests added; execution credential resolution deferred, no plaintext feature claim |
| F07 | Exact deterministic source content plus signed consumable legacy export; DB/task digest; consumer-slot locks | Tamper/offline/lock/import tests and Java-to-Python task fixture added; disconnected native OS package installation not claimed |
| F08 | Recoverable publication/deletion ordering, FK/reference transaction, same-digest authored retry | Crash windows, rollback and concurrent reference/delete cases added; production DB dialect/upgrade acceptance pending |
| F09 | Actual host package selects generated legacy service scripts; unsupported cross-package Blueprint composition rejected | Current one-stack boundary explicit; A+B independent package provisioning is still not implemented and not called closed functionality |
| F10 | No fabricated UUID/approval/fence/READY; injected platform boundary fails absent support | Delegation/denial local tests only; real provider-loss/stale/detach/recreate/Kyuubi client config fixtures need shared integration and remain open |
| F11 | One schema/semantic compiler; strict host projection; executable/profile capability correspondence | Schema/reference fixtures and cross-language producer/consumer fixture added; no TS runtime corpus because runtime API/UI is removed |
| F12 | Blueprint no live authority; actual target metadata and host config receipt; data retained; unsupported upgrade/purge rejected | Config-stage/running-probe/invalid-config STOP/recreation/retain-on-stop tests added; native detach/delete/purge audit/migration are not implemented |
| F13 | Nonexistent runtime page/client removed; catalog remains on actual API | Catalog/route tests added; runtime-page late-response tests are inapplicable to removed code; service-scoped runtime UI remains absent |
| F14 | Full headers; fresh current-source compilation and consolidated local checks passed | Root/Server RAT, Checkstyle, full Server source compilation, focused suites, Java-to-Python fixture and React build passed |
| F15 | Exact baselines, one current ledger/plan, historical report and Git preservation | Eight active documents have valid local links; changed-file conflict/credential-pattern checks and diff whitespace checks passed; no historical result relabeled |

The original final repair-order rows 1-4 have implementation and passing local
regression evidence. Row 5 has Redis/HTTP controlled host flows,
not live installation or native removal acceptance. Row 6 still depends on actual
shared provider contracts; row 7 is deferred runtime implementation, not a passed
matrix. Row 8 removes invalid UI scope and passes local verification; generic runtime
UI is not complete. No item disappeared, but this is deliberately not an assertion
that every future capability or original acceptance scenario has passed.

## Three completed follow-up inspections

The inspections were separate source/call-path analyses, not three repeats of the
same test command. All new defects below were repaired and covered by the subsequent
checks. Original F01-F15 findings, the two walkthroughs and all eight repair-order
rows have a disposition above; removing unsafe code is not completion of its absent
platform feature.

| Pass | Scope and actual finding | Minimum repair / evidence |
| --- | --- | --- |
| 1: identity, permissions, data integrity | Reserved request fields, task/current-Agent identity, package import, native ownership and catalog reference writers. H2 reproduced delete succeeding while a Blueprint reference remained uncommitted; FK-only protection was insufficient. HTTP health followed redirects. | StackDAO.lockMpackReference serializes Blueprint/cluster/repository/Stack writes with MpackDAO.removeCatalog on the existing package row. No new lock service. MpackDAOTest proves concurrent reference commit blocks deletion and stale references cannot revive a removed package. Local HTTP test proves redirects are not followed. |
| 2: operation and fault recovery | Receipt/intent ordering, cancellation, native job state, invocation recovery, config staging and listeners. Interrupted START with no surviving process could be repeated, and a pending native job could receive new work. Port declarations lacked an execution preflight. | Missing invocation evidence/pending jobs remain UNKNOWN until observed or explicitly stopped. Occupied declared IPv4 TCP/UDP listeners fail before provisioning/publication. TestMpackHost covers no duplicate start, explicit STOP recovery, pending job, occupied port and read-only observation separation. Port preflight is not an atomic reservation. |
| 3: contract, implementation and documentation | Compiler/export byte identity, schema-to-runtime semantics, JPA projections and active docs. Legacy export reread inputs after compile without tying every byte to that compiled lock; network health could omit portRef; host accepted changeEffect=none although changed config restarts. Bulk catalog deletes left JPA projections cached. | Both exports use compiled file inventory and reject changed bytes; legacy rendering uses one payload snapshot. Network health/listener fields validate early; unsupported host change effects reject export. Catalog delete detaches/evicts affected Stack/repository projections. Authoring regressions and H2 removed-ID/stale-write tests pass. Current contracts/status replace obsolete claims; historical review remains unchanged. |

Validation also exposed eager metadata/config dependencies in ActionDBAccessorImpl;
they now use existing Guice Providers and resolve only for applicable tasks. The
initial DAO test bootstrapped the entire controller and failed during static injection
before persistence initialization; its final harness exercises real JPA/transactions
without starting unrelated controllers. This does not claim full Server startup
acceptance. Import ordering/wildcard/unused-import errors were corrected; final
Checkstyle has zero violations.

## Runtime capability matrix

Legend: implemented means source code exists; partial denotes explicit subset or
integration boundary; unsupported means the current executable contract rejects it.
None of these entries by itself claims real-runtime verification.

| Runtime | discover | plan | apply | observe | verify | recover | Actual integration |
| --- | --- | --- | --- | --- | --- | --- | --- |
| host.systemd / host-service v1 | Implemented systemctl version, target scope, 30s TTL | Implemented package/config/task/receipt/observation | Implemented install/configure/start/stop/restart subset | Implemented exact unit/native identity and health | Implemented active PID/health or inactive/loaded postconditions | Partial: replay, new InvocationID, explicit stop; ambiguous state UNKNOWN | Compiler -> signed legacy import -> existing server metadata/task -> shared Agent Script; live acceptance pending |
| OCI | Static declaration only | Not implemented | Unsupported by exporter | Not implemented | Not implemented | Not implemented | Authoring only; old argv dispatcher retired |
| Kubernetes | Static declaration only | Not implemented | Unsupported by exporter | Not implemented | Not implemented | Not implemented | Authoring only; requires API-server/namespace/UID/rollout contract |
| External database | Static observe declaration | Not implemented | Explicitly unsupported | Not implemented connection/probe | Not implemented | Not implemented | Authoring only; credentials and connection authority absent |

## Implementation, integration and evidence matrix

| Capability | Implementation state | Integration scope | Available evidence / this verification phase |
| --- | --- | --- | --- |
| Manifest/config validation + deterministic source ZIP | Implemented | Local contract/tooling | Authoring suite: 28 passed; unit/offline fixtures |
| Signed legacy export and consuming import | Implemented subset | Ambari server import + generated Agent definitions | Signed compiler export consumed by actual MpackManager test: passed; local filesystem + mocked catalog DAOs |
| Catalog crash/delete recovery | Implemented within one server-owned filesystem | Ambari server + existing DB | Filesystem/mock-DAO crash cases and real H2 DAO transactions/locking: passed; no production DB claim |
| Service identity/digest/incarnation | Implemented additive metadata | Existing server/task/Agent metadata | Task/metadata serialization, H2 service incarnation and mocked upgrade-DDL tests: passed |
| Host lifecycle/config/recovery | Partial general software scope | Existing Script integration and controlled native boundary | Agent suite: 83 passed, including native-output fixtures and real local subprocess/socket checks; no real systemd |
| Redis/HTTP source authoring | Implemented | Local compiler, deployable host export subset | Deterministic build and shared-driver fixtures: passed; native installation not executed |
| Kyuubi source authoring | Implemented source model, deployment unsupported | Local tooling / external shared platform required | Source build and unsupported-deployment rejection tests: passed |
| Shared dependency authority | Partial delegated contract | Depends on external shared platform | Mock client delegation/denial only; no provider execution |
| React catalog | Implemented existing catalog | Real catalog API | 21 model/route tests and production build: passed; no browser/live acceptance |
| Upgrade/migration/adoption/detach/uninstall/purge | Not implemented generically | Explicit executable boundary | Rejection/data-retention fixture only; no destructive/live acceptance |

## Redis walkthrough after repairs

1. `mpack-authoring/fixtures/redis/manifest.json`, `config.schema.json`,
   `config.conf.j2` declare OS package `redis`, user, private data directory, port,
   executable and config-file argument. Compiler validates source and locks declared
   files; source ZIP is reproducible. OS package repos/binaries are prerequisites,
   not bundled offline distributions.
2. `legacy.export_legacy` emits signed `mpack.json`/`definition.tar.gz`, generated
   service/component XML, Ambari config XML and a shared Script wrapper.
   MpackManager authenticates the archive, imports modules and persists package
   digest; Stack/service selection remains the existing Ambari model.
3. Existing controller/RBAC creates install/start tasks; ActionDBAccessorImpl persists
   exact package/service/host/action/config binding with each task before delivery. ManifestService uses
   installed descriptor/payload; Package/User/Directory and HostDeployment stage
   config/resources/unit under a bound target. Unit names are generated from the
   binding, never adopted from a manifest name.
4. Ambari desired config and tags enter the same Script. Scalar validation precedes
   local generation publication; successful START/restart records running generation.
   Reload is unsupported. Health uses native state and declared loopback probe;
   normal task output/status are available. Generic metrics/log API and delegated
   observability permissions are not implemented.
5. Duplicate tasks verify without repeating a successful mutation. A reconstructed
   HostDeployment reads the receipt after process/Agent restart. Lost start response
   uses InvocationID evidence; stale/ambiguous outcomes stay UNKNOWN and automatic
   retry is disabled. Real server/Agent restart delivery remains acceptance pending.
6. Upgrade, adoption, detach, native delete and purge are unsupported; stop retains
   data. Catalog deletion is a separate operation blocked by service/Stack references,
   and never touches native data. There is no pretend reversible data migration.

Evidence: authoring tests, `TestMpackHost`, `TestRuntimeAdapter`, `TestActionQueue`,
`MpackManagerTest`, `MpackDAOTest`, metadata/Blueprint tests. These are local fixtures
and integration components, not proof that Redis was installed on a live host.

## Kyuubi walkthrough and exact breakpoints

1. `mpack-authoring/fixtures/kyuubi` provides host source, two config files, schema,
   SecretRef shape and Spark/Hadoop/Hive requirements. The common compiler can build
   a source bundle. Distributions and provider assets are not included.
2. Deployable export fails `DEPENDENCY_UNRESOLVED`: no integrated shared client or
   approved snapshots are available. Host execution also rejects unresolved requires.
   Secret execution and Kubernetes execution are independently unsupported.
3. Closest real external reference: `ManagedServiceDependencyService` list/candidates/
   preview/create/get/retry/delete and its coordinator in commit `8bf556b6...`.
   `ManagedDependencyType` supports HDFS and ZOOKEEPER only. Spark/Hadoop/Hive contract
   implementations and Kyuubi client/config propagation do not exist in this worktree.
4. Cross-cluster authorization, ownership, provider loss/stale binding, snapshots,
   UNKNOWN/later response and upgrade/migration cannot be walked through with real
   calls. Required prerequisites are shared-provider contract extensions/integration,
   approved scoped secret/config delivery, then host/Kubernetes fixtures and real
   target acceptance. No synthetic binding DB or guessed endpoint fills the gap.

## Verification ledger

All planned edits and the first original-review recheck preceded the consolidated
validation phase. Failures/newly identified defects were corrected during that phase;
only affected checks were repeated, plus a final Agent integration run after host
recovery changes. Logs and non-secret fixtures are under
`/tmp/mpack-final-validation-20260910/`. Signing material is external to the repository
and is never reproduced in this document. Commands below ran from repository root
unless another directory is stated.

| Check | Actual final result / strength | Log |
| --- | --- | --- |
| Authoring unittest discovery | 28 passed; unit and offline source/export fixtures | authoring-complete.log |
| Agent/common selected suites | 83 passed, no skips; controlled native outputs plus real local child processes and loopback sockets | agent-complete.log |
| Java-to-Python fixture separately | 1 passed using the final actual Java producer output; included in the 83 above, not an extra unique test | java-agent-final.log |
| Instance manager unittest discovery | 23 passed; local filesystem/helper tests | instance-manager.log |
| Fresh Server compile and selected suites | JDK 17 compiled all 2,185 main and 850 test sources; 98 tests passed, no skips | server-fresh.log |
| Server Checkstyle / RAT | Zero violations / no issues, as part of the successful fresh build | server-fresh.log |
| Root RAT | Passed; final document check recorded with the same command | root-rat.log / root-rat-final.log |
| React selected suites | 21 passed across catalog model and routes | react-tests.log |
| React production build | tsc and Vite passed; existing Sass deprecations/large-chunk warnings remain | react-build.log |
| Repository/static checks | diff whitespace and unmerged-index checks passed; 93 existing changed/untracked files had no conflict markers or high-confidence credential patterns; eight active documents had no missing relative links | static-audit.json |

Python commands (the temporary dependency directory supplies the repository-pinned
stomp.py 8.2.0, websocket-client 1.9.0 and APScheduler 3.11.3; it does not alter system
packages or this repository):

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=mpack-authoring/src/main/python python3 -m unittest discover -s mpack-authoring/src/test/python -v
PYTHONDONTWRITEBYTECODE=1 MPACK_TASK_FIXTURE=/tmp/mpack-final-validation-20260910/java-task-final.json PYTHONPATH=/tmp/mpack-final-validation-20260910/python-deps:mpack-authoring/src/main/python:ambari-agent/src/main/python:ambari-agent/src/main/python/ambari_agent:ambari-common/src/main/python:ambari-agent/src/test/python:ambari-agent/src/test/python/ambari_agent:ambari-common/src/test/python python3 -m unittest TestMpackHost TestRuntimeAdapter TestActionQueue TestCustomServiceOrchestrator
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=mpack-instance-manager/src/main/python/instance_manager python3 -m unittest discover -s mpack-instance-manager/src/test/python/instance_manager -p 'test*.py' -v
```

The separate final producer/consumer case used the same Agent environment with
`python3 -m unittest TestMpackHost.TestMpackHost.test_actual_java_task_payload_consumes_the_shared_host_driver`.
It does not start an Ambari network session or a real systemd unit. The installed
package descriptor and source file checks are real; native responses/current-host
projection are explicit fixtures. Server task binding uses the actual producer with
mocked metadata/config providers; its database serialization is tested separately.

Before the final Server command, old target/classes and target/test-classes were
moved to `pre-fresh-classes` and `pre-fresh-test-classes` in the external log directory.
This preserved old build outputs and forced full compilation, including detecting
references to removed classes. A fresh signed HTTP export was generated using:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=mpack-authoring/src/main/python python3 mpack-authoring/src/main/python/mpack_authoring/validate_manifest.py mpack-authoring/fixtures/http/manifest.json --legacy-export /tmp/mpack-final-validation-20260910/http-host-export-final --signing-key /tmp/mpack-final-validation-20260910/signing.key
/jialiangc/bigdata/prjs/.codex-runs/ambari-mpack-v2/tools/apache-maven-3.9.16/bin/mvn -o -f ambari-server/pom.xml -Dexec.skip=true -DskipPythonTests -Dtest=MpackManagerTest,MpackDAOTest,BlueprintDAOTest,MpackTest,MpackReferenceTest,BlueprintSettingEntityTest,MetadataClusterTest,MpackTaskBindingTest,UpgradeCatalog310Test,RequestResourceProviderTest -Dmpack.host.fixture=/tmp/mpack-final-validation-20260910/http-host-export-final -Dmpack.task.fixture=/tmp/mpack-final-validation-20260910/java-task-final.json test
/jialiangc/bigdata/prjs/.codex-runs/ambari-mpack-v2/tools/apache-maven-3.9.16/bin/mvn -o -N org.apache.rat:apache-rat-plugin:0.18:check
```

In `ambari-web/latest`, commands were
`npm test -- src/screens/ManagementPacks/model.test.ts src/router/RoutesList.test.tsx`
and `npm run build`. Final repository checks used `git diff --check`,
`git ls-files -u`, changed-file conflict/credential-pattern inspection and relative
link resolution for active Mpack documents. Historical review source references
resolve at c7dc663f7c; deleted historical documents are intentionally Git references.
The credential scan is pattern-based, not a guarantee about arbitrary embedded data.

Initial failures are retained, not relabeled: Agent imports first lacked stomp,
then the existing Agent module search path; environment setup resolved both. Java
initially failed DAO/controller initialization, the real concurrent-reference test,
and Checkstyle. Each was corrected as described above. All final listed commands
passed. The root reactor, Server Python bundle/packaging, full controller boot,
production DB fresh/upgrade, live Server-Agent/systemd, OCI/Kubernetes/database,
Kyuubi provider and browser acceptance were not run. Maven explicitly skips Server
Python/exec phases because the base interpreter lacks pip; selected Python suites
were run directly with the documented environment.

Historical pre-repair evidence remains distinct: authoring 25, instance manager 23,
React 8 and six incremental Server tests passed at c7dc663f7c; root reactor failed RAT
on 32 abbreviated notices and default Server Python bundling lacked pip. Those are
baseline observations, not final acceptance or current failures.

## Remaining acceptance and operating limits

Use the external/product gates in [implementation-plan](implementation-plan.md).
Production DB dialect execution and already-running alpha schema migration need
release/upgrade procedures; adding DDL source does not migrate a live database.
HMAC uses a shared externally provisioned key; it is not an asymmetric publisher
trust ecosystem. The legacy admin package trust boundary still permits established
legacy scripts. Generated host contracts are strict and authenticated separately.
Quarantine is retained catalog evidence and needs operator storage/retention policy.

## Authorized publication

The user requested remote submission after the completed review, three inspections
and consolidated validation, then explicitly requested a single commit instead of
splitting the changes. This user instruction supersedes the default topic-commit
organization for this delivery. The publication target is the personal fork
`JiaLiangC/ambari`, branch `AMBARI-14714-mpack-v2-remote`; the branch previously had
no remote tracking branch. The AMBARI-14714 commit contains the reviewed source,
focused tests and consolidated documentation. Validation above applies to the final
integrated source tree. No pull request, upstream push, force push or live deployment
is included.
