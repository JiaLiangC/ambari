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

# Audit remediation plan

This is the single active plan. The independent review was recorded before source
changes. Finish the implementation/documentation batch before the consolidated
compilation, validation and test phase, as requested. The subsequent user request
authorizes one consolidated commit and publication to origin/AMBARI-14714-mpack-v2-remote.
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

- Kyuubi execution: shared platform must add/integrate Spark/Hadoop/Hive contracts,
  authorization, immutable binding snapshots, configuration and scoped secret
  propagation. The available reference has only HDFS/ZOOKEEPER dependency types.
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
