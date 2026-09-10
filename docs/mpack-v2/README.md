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

# Mpack V2 Implementation Package

Current direction: the user has authorized resuming execution on the remote
development host using an interactive Codex session, model `gpt-5.6-sol`,
reasoning effort `xhigh`. Earlier Luna assignments and architecture-only pauses
are historical. They must not stop the newly authorized execution.

The required sequence is community V2 integration, necessary compatibility
corrections and verification, reviewed remote trunk publication, a new worktree
from the published trunk, and then broader architecture/tooling improvements.
Compatibility with the generic multi-cluster design is a hard constraint.

## Reading Order

1. [Execution runbook](execution-runbook.md): environment, authority, scope and checkpoints.
2. [Decision register](architecture-decisions.md): confirmed constraints and execution defaults.
3. [Architecture](architecture.md) and [multi-cluster alignment](multi-cluster-alignment.md).
4. [Contracts](contracts.md), [manifest specification](manifest-spec.md), and [reference examples](reference-examples.md).
5. [Integration plan](integration-plan.md) and [work orders](work-orders.md).
6. [Design work plan](design-work-plan.md): remaining design refinements during execution.
7. [Execution log](execution-log.md): distinguish prior local evidence from the current remote run.

Precedence: latest user instruction, confirmed compatibility constraints, execution
runbook/work orders, then detailed design defaults. A historical checkpoint is
evidence, not an active work order. Detailed extension names are working contracts
that may be refined compatibly with tests and a recorded rationale.

Plans/specifications do not imply that the referenced APIs, adapters or tools
already exist. Record actual implementations and test results as work progresses.
The multi-cluster reference itself is an incomplete source checkpoint; do not
claim it is integrated into trunk or runtime-validated.
