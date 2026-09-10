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

The Redis walkthrough, actual call entries and breakpoints are maintained
once in [status](status.md). Its historical Kyuubi walkthrough is outside the current
scope; the user removed that example on 2026-09-10. Complete authoring examples live in fixtures linked by
[manifest-spec](manifest-spec.md). The scenarios below define acceptance requirements;
they do not report tests already run or imply missing runtime implementations exist.

## Current host and catalog slice

| Scenario | Required observation | Closest local coverage |
| --- | --- | --- |
| Author/build HTTP or Redis | One canonical validation path; deterministic exact inventory; offline declared payload | AuthoringSafetyTest, LegacyExportTest |
| Signed import | Actual generated modules loaded by MpackManager; digest bound in DB; wrong key/modified content rejected before publication | MpackManagerTest compiler-produced fixture |
| Publication crash before/after DB | Uncommitted files quarantined; committed projection completed; rollback failure retains definitions | MpackManagerTest crash-window cases |
| Delete while referenced | DB transaction fails with references and files retained; unreferenced deletion commits before filesystem cleanup | MpackDAOTest and MpackManagerTest |
| Create/recreate service | Existing cluster/service identity retained; new native incarnation does not adopt old data/unit | MpackDAOTest, TestMpackHost |
| Install/start/configure/stop | Declared resources, stage/publish config, active PID/application readiness, verified stop and retained data | TestMpackHost controlled native fixture |
| Duplicate/late task | Same intent verifies without duplicate mutation; older task cannot overwrite newer evidence | TestMpackHost |
| Lost response or Agent process restart | Reconstruct driver from persisted receipt; new native invocation can reconcile; ambiguity stays UNKNOWN | TestMpackHost; real Agent restart delivery still pending |
| Cancellation/output pressure | Drain both pipes, capped output, bounded termination; UNKNOWN disables automatic retries | Local child-process tests and TestActionQueue |
| Catalog UI | Existing permissions/API and delete behavior; absent runtime route not exposed | React model/route tests and production build |

Real Redis/systemd acceptance additionally needs isolated native hosts with supported
OS packages and service users. It must inspect real unit paths/InvocationID, occupied
ports, process exit after successful command submission, invalid config, interrupted
publication and data retention. Local fixtures do not meet this native evidence bar.
Server-Agent connection loss/restart acceptance must inspect persisted actual tasks,
metadata/config generations and late responses, not only reconstruct a local class.

## Future runtime and data lifecycle acceptance

OCI must bind an actual engine/container identity and prove immutable image, state,
volume retention and recovery semantics. Kubernetes must bind authorized API server,
namespace and native UID/revision, observe rollout/controller state and handle resource
replacement. External databases require scoped connections/probes and explicitly
unsupported mutation where appropriate. Equal method names do not establish equal
execution or cancellation semantics across these runtimes.

Adoption must verify identity/ownership before taking control. Detach must not delete
provider-owned resources. Uninstall retains persistent data; purge needs independent
capability, authorization and audit. Software rollback cannot promise data rollback.
Migration acceptance includes partial success, irreversible boundaries, backup/restore
and manual recovery evidence. These are roadmap requirements, not current host features.

## Human and AI authoring

A human or AI changes the same declarative source, sees the same diagnostics/diff,
and uses the same review, compiler, signed export and authenticated import. Invalid
port/config references, unsupported capabilities, secret literals and dependency gaps
must be rejected without leaking values. No AI may grant approval, directly invoke
native commands, bypass server RBAC or describe an irreversible migration as rollback.
This repository does not implement an AI provider; the authoring boundary is shared.
