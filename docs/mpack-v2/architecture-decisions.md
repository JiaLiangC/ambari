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

# Mpack Architecture Decision Register

Read [architecture.md](architecture.md) for the full design and
[execution-runbook.md](execution-runbook.md) for current authorization. The user
has authorized remote execution; conservative defaults cover routine choices.
Confirmed shared-platform constraints cannot be changed by the worker.

## Confirmed Direction

| ID | Direction | Meaning |
| --- | --- | --- |
| SCOPE-001 | Remote implementation is authorized | Execute in the new remote worktree with interactive Codex gpt-5.6-sol xhigh; earlier pauses and Luna assignments are superseded |
| SCOPE-002 | Broad software-management coverage | Target host software, containers, Kubernetes and externally managed software; implement in stages |
| AUTHOR-001 | Declarative authoring with Python extensions | Make common packages easy to author while retaining programmable software-specific behavior |
| MODEL-001 | Separate package, instance and runtime responsibilities | Package describes software; instance records intent/state; adapters control supported environments |
| DOC-001 | Detailed plans and decisions are durable documentation | Agents consume explicit documented scope, contracts, validation and review findings |
| REVIEW-001 | Parent owns design and independent checkpoint review | Execute documented compatible work; material shared-contract changes and exact publication candidates require parent review |
| INPUT-001 | Multi-cluster reference is a generic platform design | Review fixed commit 8bf556b6ce94b350b3c3b12e15a7882d07bd19f7; initial HBase dependency integrations do not define the overall platform scope |
| COMPAT-MC-001 | Mpack must not conflict with the generic multi-cluster design | Preserve Cluster ownership, exclusive Agent membership, service identity, RBAC, routes, workflows, dependency ownership and observation scoping |
| MODEL-003 | No independent Environment authority or host-ownership root | Separate runtime-target selection from existing Cluster/server authority |
| ALIGN-001 | Preserve current cluster/service identity in this mpack scope | Do not independently migrate service IDs, ServiceGroups or dependency foreign keys; same-cluster same-type multi-instance support requires separate platform agreement |
| ALIGN-003 | Reuse scoped workflows, UI runtime, events and numeric metric identity | Mpack does not establish parallel recovery and authorization mechanisms |
| DELIVERY-001 | V2 integration remains required before broad implementation improvements | Agree on compatibility boundaries, merge/adapt and verify V2, publish remote trunk, then create the improvement worktree |

The broad coverage statement is a product target. It does not promise every
software/OS/version/capability combination or commit to simultaneous delivery
of all runtime adapters.

## Proposed Decisions

These are working design proposals to implement/refine within the authorized
scope, using the conservative defaults below. OPEN does not reopen a confirmed
constraint or require stopping unrelated authorized implementation.

| ID | Proposal | Rationale | Status |
| --- | --- | --- | --- |
| MODEL-002 | Additive package/operation/native-resource IDs refer to authoritative cluster/service identity | Preserve source identity and binding incarnation while tracking package execution | PROPOSED |
| MODEL-004 | Separate software roles from deployment forms | Jobs, libraries and external resources need different lifecycles | PROPOSED |
| RUNTIME-001 | Capability intersection drives API and UI operations | Unsupported lifecycle operations should be explicit | PROPOSED |
| RUNTIME-002 | Existing platform controllers retain native ownership | Avoid conflicting with systemd, container engines and Kubernetes | PROPOSED |
| STATE-001 | Separate desired state, observation and operation state | A submitted command does not prove readiness | PROPOSED |
| STATE-002 | Durable plan/apply/verify with idempotency and revision checks | Make retries, drift and recovery inspectable | PROPOSED |
| STATE-003 | Observe drift by default; bounded auto-recovery by explicit policy | Avoid unexpected state changes while permitting automation | OPEN |
| OWNER-001 | Explicit observation, adoption and managed ownership | Existing services should not be destructively adopted implicitly | PROPOSED |
| OWNER-002 | Persistent data retained unless a separate deletion operation is selected | Distinguish software removal from data destruction | PROPOSED |
| CONFIG-001 | Typed layered configuration with provenance and change effects | Support generated forms, safe application and useful diagnostics | PROPOSED |
| CONFIG-002 | Secret references and scoped runtime resolution | Keep secret material outside packages, plans and logs | PROPOSED |
| DEP-001 | Separate artifact, runtime-interface, placement and ordering dependencies | Each class has different resolution semantics | PROPOSED |
| PKG-001 | Immutable published content and resolved artifact/dependency locking | Make deployment reproducible and offline-capable | PROPOSED |
| UPGRADE-001 | Declare upgrade strategies and data compatibility per capability | Version-link rollback does not reverse every data migration | PROPOSED |
| UI-001 | Metadata-generated UI as default, controlled plugin interface later | New software should not require editing React core | OPEN |
| AI-001 | One public API/schema/diagnostic contract for users and AI | Prevent duplicate validation rules and privileged AI shortcuts | PROPOSED |
| COMPAT-001 | Legacy translation plus explicit limited legacy execution profile | Preserve existing definitions without freezing the new model | OPEN |
| K8S-001 | Start with platform-level Helm/resource bindings | Keep orchestration ownership clear; operator contract breadth needs discussion | OPEN |
| TEST-001 | Layered validation and adapter conformance with reference software | Static schema checks alone cannot establish runtime behavior | PROPOSED |
| ALIGN-002 | Negotiate additive named-slot and software-adapter extensions to the shared dependency protocol | Preserve existing binding schemas and clients; unsupported extensions remain explicit | OPEN |
| ALIGN-004 | Declare adapter-specific fencing and distinguish preparation from readiness | Durable operation state alone does not fence old remote execution | PROPOSED |

## Conservative Execution Defaults

| Area | Default |
| --- | --- |
| Drift and repair | Observe/report; bounded automatic repair only through explicit supported policy |
| Data removal | Retain persistent data by default; separately declared deletion operation |
| Legacy compatibility | Preserve supported formats with explicit translation/limited profiles |
| UI | Metadata-generated forms/operations first; controlled custom plugins remain separate |
| Kubernetes | Helm/resources and native controller ownership first |
| New alpha contracts | Implement versioned, validated contracts; refine compatibly with evidence |
| Shared platform gaps | Explicit capability limitation and dependency tracking, no bypass or parallel authority |

## Refinement During Execution

The design deliverables and acceptance order are specified in
[design-work-plan.md](design-work-plan.md). Start with the concrete contract
specification, then use reference packages to resolve remaining policy choices.

Discuss the domain model and ownership boundaries first, then operation and
configuration/dependency contracts, then SDK/schema examples and delivery
scope. Record each accepted choice, tradeoff and acceptance example here.

See [multi-cluster-alignment.md](multi-cluster-alignment.md) for the pinned
reference evidence, responsibility mapping and specific joint decisions.

The active remote model is Sol xhigh. The worker reads this register together
with the runbook, implements ordinary compatible details, records rationale/tests,
and returns material shared-contract changes for parent review.
