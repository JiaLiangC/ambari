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

# Mpack V2

Mpack is intended to extend Ambari with software definitions and runtime-specific
management while retaining existing cluster/service identity, authorization,
configuration, Agent ownership, request/task history, and dependency authority.
Current availability and acceptance are recorded in [status.md](status.md).
Design descriptions are not claims of implemented or tested runtime support.

The independent [Store design](store-design.md) covers the third-party website and
backend, to be implemented later in a new repository. Ambari provides file/URL import
and local package/service management, without Store pages. The [Ambari delivery plan](implementation-plan.md#package-import-and-lifecycle-delivery-plan)
is authorized implementation in progress, separate from the completed audit remediation.
The user removed the Kyuubi example and its dedicated integration work; current
examples are HTTP, Redis and multi-service YAML. Historical review records retain
their original scope and do not override the active plan.

Package authors should start with the English [development guide and examples](../../mpack-authoring/README.md)
and run [validate.py](../../mpack-authoring/validate.py) against their own source or
offline source bundle. The guide distinguishes source checks from host export and
actual runtime acceptance.

## Read in this order

1. [Architecture](architecture.md): boundaries, ownership, decisions and tradeoffs.
2. [Contracts](contracts.md): identity, configuration, dependency and operation rules.
3. [Manifest](manifest-spec.md): versioned authoring format and validation.
4. [Reference acceptance](reference-examples.md): host, OCI, Kubernetes, external,
   dependency and AI scenarios; these are acceptance requirements.
5. [Implementation plan](implementation-plan.md): ordered work and exit criteria.
6. [Status and provenance](status.md): current findings, executed checks and limits.
7. [Independent review](reviews/independent-architecture-review-2026-09-10.md):
   historical findings against c7dc663f7c, retained for traceability.

The user authorized documentation consolidation, implementation and verification,
then explicitly requested committing and pushing this work to the personal fork.
That audit delivery was published to origin/AMBARI-14714-mpack-v2-remote; it does not
authorize deployment or publication of a new Store. Do not deploy to a
live cluster or modify another worktree. Historical model,
tmux, worker, approval, and publication instructions are not active work orders.

Keep one architecture, one implementation plan, and one status ledger. Update
these documents instead of adding per-batch completion reports. The separate Store
design is explicitly requested and will move to its future repository; it is not a
second Ambari architecture or implementation plan. Record external
acceptance dependencies explicitly. Do not replace an unresolved defect with a
claim that a fixture, command exit code, or class definition proves support.
