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

# Reference acceptance scenarios

Kyuubi is the primary end-to-end scenario. The smaller HTTP, Redis and external
database fixtures remain focused contract tests. These scenarios define acceptance;
completed evidence is recorded only in [status](status.md).

## Kyuubi golden path

| Step | Required observation |
| --- | --- |
| Build Ambari | Reproducible Server and Agent RPMs from the tested branch, with recorded SHA-256 digests. |
| Start cluster | Server database initialized; Agents registered on disposable systemd hosts; test cluster and Spark/Hadoop prerequisites healthy. |
| Build Mpack | Independent source builds a signed Kyuubi Mpack from package-local definitions/scripts and a pinned official binary checksum. Kyuubi has no RPM and Ambari has no Kyuubi-specific code. |
| Select binary | UI offers embedded content when present, approved HTTP(S), or an absolute target-host path. Every choice verifies the same locked artifact identity before installation. |
| Import | UI uploads the Kyuubi Mpack or its all-package collection; Ambari verifies publisher, signature, inventory and compatibility before catalog publication. |
| Install | Operator chooses service, hosts and configuration once; Server creates the normal Ambari request and Agent executes the package's install/configure/start lifecycle. |
| Verify | UI and task history show the actual outcome; native process, version, ports and health match; a JDBC/SQL smoke query succeeds. |
| Operate | Stop/start and a configuration-driven restart work through normal Ambari actions. Wrong digest, URL/path policy and corrupt archive failures are visible and bounded. |
| Remove | Ordinary uninstall stops Kyuubi and preserves declared logs/work data; reinstall is deterministic. Destructive cleanup, if later supported, remains separately authorized. |

## Current host and catalog slice

| Scenario | Required observation | Closest local coverage |
| --- | --- | --- |
| Author/build HTTP or Redis | One canonical validation path; deterministic exact inventory; declared payload | AuthoringSafetyTest, LegacyExportTest |
| Signed import | Actual generated modules loaded by MpackManager; digest bound in DB; wrong key/modified content rejected before publication | MpackManagerTest compiler-produced fixture |
| Publication crash before/after DB | Uncommitted files quarantined; committed projection completed; rollback failure retains definitions | MpackManagerTest crash-window cases |
| Delete while referenced | DB transaction fails with references and files retained; unreferenced deletion commits before filesystem cleanup | MpackDAOTest and MpackManagerTest |
| Create/recreate service | Existing cluster/service identity retained; new native incarnation cannot claim old data/unit | MpackDAOTest, TestMpackHost |
| Submit installation plan | Whole assignment/config intent validates before writes; repeated UUID resumes the ordinary Ambari request | MpackInstallCoordinatorTest, ClusterServiceTest and React lifecycle/dialog tests; real-provider fault injection remains open |
| Install/start/configure/stop | Declared resources, stage/publish config, active PID/application readiness, verified stop and retained data | TestMpackHost controlled native fixture |
| Duplicate/late task | Same intent verifies without duplicate mutation; older task cannot overwrite newer evidence | TestMpackHost |
| Lost response or Agent process restart | Reconstruct driver from persisted receipt; new native invocation can reconcile; ambiguity stays UNKNOWN | TestMpackHost; real Agent restart delivery still pending |
| Cancellation/output pressure | Drain both pipes, capped output, bounded termination; UNKNOWN disables automatic retries | Local child-process tests and TestActionQueue |
| Catalog UI | Existing permissions/API and delete behavior; absent runtime route not exposed | React model/route tests and production build |

HTTP and Redis fixtures remain useful for fast profile regression tests. They do not
replace the Kyuubi browser-to-Agent acceptance path.

## External observation and removal acceptance

External databases require scoped connections/probes and explicitly unsupported
mutation where appropriate. Container and orchestrator workloads are outside the
Mpack V2 contract and use their dedicated platforms instead.

External unregister must release only Ambari's registration and report provider-owned
runtime/data/ownership. Uninstall retains managed data; purge requires independent
capability, authorization, exact incarnation and retained inode evidence. A missing
Agent or receipt does not permit force-success. The supported contract excludes
foreign adoption, orphan purge and automatic data rollback.

## Human and AI authoring

A human or AI changes the same declarative source, sees the same diagnostics/diff,
and uses the same review, compiler, signed export and authenticated import. Invalid
port/config references, unsupported capabilities, secret literals and dependency gaps
must be rejected without leaking values. No AI may grant approval, directly invoke
native commands, bypass server RBAC or describe an irreversible purge as rollback.
This repository does not implement an AI provider; the authoring boundary is shared.
