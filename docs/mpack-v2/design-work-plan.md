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

# Design Readiness and Execution Sequence

The user has authorized remote Sol xhigh execution. The previous design-only
pause is lifted. Read [README.md](README.md) for document precedence.

## Prepared Design Inputs

| Input | Location | Meaning |
| --- | --- | --- |
| Architecture | [architecture.md](architecture.md) | Target software-management model |
| Confirmed constraints/defaults | [architecture-decisions.md](architecture-decisions.md) | Hard boundaries and conservative execution choices |
| Multi-cluster compatibility | [multi-cluster-alignment.md](multi-cluster-alignment.md) | Shared foundation and acceptance matrix |
| Contracts | [contracts.md](contracts.md) | Identity, adapter, dependency and operation contracts |
| Manifest | [manifest-spec.md](manifest-spec.md) | Proposed source/built representation and validation rules |
| Worked scenarios | [reference-examples.md](reference-examples.md) | User/AI flows and failure/recovery acceptance |

These are working specifications, not claims of existing runtime support.
Ordinary compatible detail can be refined with rationale and tests. Confirmed
ownership/identity/protocol boundaries cannot be changed by the worker.

## Required Order

1. M0: record actual baseline, capability mapping and shared contract availability.
2. M1: incorporate community V2 and necessary compatibility corrections.
3. M2: verify and prepare exact candidate commits locally.
4. M3: record the local candidate as the improvement baseline.
5. M4: continue in a local improvement worktree or the authorized worktree.
6. R1+: implement reliability, runtime, schema, UI and authoring improvements.

Do not implement every future authoring feature before community integration.
Conversely, a Git merge does not excuse current API/data/runtime regressions.
The source mapping determines compatible reuse of community behavior.

## Refinement During Execution

- Validate the common model using host, OCI, Kubernetes and external profiles.
- Use existing runtime frameworks and dependency versions where possible.
- Keep manifest schema/version and adapter capability availability explicit.
- Turn test or operational evidence into focused contract improvements.
- Record any shared-platform extension dependency; keep unsupported combinations
  explicit until its compatible contract exists.
- Update examples and schemas together when field-level contracts change.

The implementation worker reports refinements and results in reviews/checkpoints.
The parent reviews compatibility and material changes; it does not need to
authorize each reversible routine implementation choice again.
