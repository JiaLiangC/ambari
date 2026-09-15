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

Mpack extends Ambari with signed software definitions and versioned host profiles
management while retaining existing cluster/service identity, authorization,
configuration, Agent ownership, request/task history, and dependency authority.
Current availability and acceptance are recorded in [status.md](status.md).
Design descriptions are not claims of implemented or tested runtime support.

The independent [Store design](store-design.md) covers the third-party website and
backend, to be implemented later in a new repository. Ambari provides file/URL import
and local package/service management, without Store pages. The [Ambari delivery plan](implementation-plan.md)
records the implemented local scope and the remaining real-environment acceptance gates.
The 2026-09-15 [architecture convergence decision](architecture.md#architecture-convergence-decision--2026-09-15)
removes container and orchestrator runtimes from Mpack V2 and narrows the platform to
versioned Ambari-managed host profiles. The user removed the Kyuubi example and its dedicated integration work; current
examples are HTTP, Redis, multi-service YAML and an external PostgreSQL observer. Historical review records retain
their original scope and do not override the active plan.

Package authors should start with the English [development guide and examples](../../mpack-authoring/README.md)
and run [validate.py](../../mpack-authoring/validate.py) against their own source or
offline source bundle. The guide distinguishes source checks from host export and
actual runtime acceptance.

## Read in this order

1. [Architecture](architecture.md): boundaries, ownership, decisions and tradeoffs.
2. [Contracts](contracts.md): identity, configuration, dependency and operation rules.
3. [Manifest](manifest-spec.md): versioned authoring format and validation.
4. [Reference acceptance](reference-examples.md): host, external observation,
   dependency and AI scenarios; these are acceptance requirements.
5. [Implementation plan](implementation-plan.md): ordered work and exit criteria.
6. [Status and provenance](status.md): current findings, executed checks and limits.
7. [Independent review](reviews/independent-architecture-review-2026-09-10.md):
   historical findings against c7dc663f7c, retained for traceability.

Keep one architecture, one implementation plan, and one status ledger. Update
these documents instead of adding per-batch completion reports. The separate Store
design is explicitly requested and will move to its future repository; it is not a
second Ambari architecture or implementation plan. Record external
acceptance dependencies explicitly. Do not replace an unresolved defect with a
claim that a fixture, command exit code, or class definition proves support.
