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

# Remote Implementation Work Orders

Active implementer: interactive Codex, `gpt-5.6-sol`, `xhigh`.
Authorization: resume the documented task on the remote development host.
Read [execution-runbook.md](execution-runbook.md) first.

## Order W0: Establish the Remote Baseline

Allowed scope: the dedicated mpack worktree, its own run-artifact directory,
read-only reference trees, and ordinary Git metadata operations needed for this
branch. Other active worktrees and tmux sessions are not implementation targets.

1. Read repository AGENTS.md and the documentation in README order.
2. Verify HEAD, task refs, status, model/runtime and source-reference locations.
3. Inventory Java/Maven/Python/Node and reusable development caches. Use scoped
   existing tool installations before installing replacements. Never copy or
   print authentication material.
4. Write `docs/mpack-v2/reviews/W0.md`: baseline, availability matrix, V2 capability
   ledger, shared contract availability and proposed resolution batches.
5. Report a concise checkpoint in the interactive terminal, then continue W1
   for compatible work. Do not wait for another user authorization for routine
   read-only actions, implementation or tests already within scope.

Exit: clean-source baseline recorded and all integration contracts accounted for.

## Order W1: Community Integration in Coherent Batches

Follow M1 in [integration-plan.md](integration-plan.md). Begin a merge only after
writing the identity/compatibility mapping. Keep all changes in the dedicated
worktree. Inspect both sides for shared classes and every deletion affecting
current supported services or APIs.

The worker owns source and focused tests. Parent owns architecture decisions and
review findings. Update implementation evidence and propose doc corrections when
needed; do not rewrite confirmed requirements to excuse a failing implementation.

For each batch record paths, community provenance, actual behavior, checks and
open issues in `docs/mpack-v2/reviews/`. Continue independent authorized batches
while awaiting feedback. Apply parent findings before final integration acceptance.

Do not globally choose ours/theirs, insert success stubs, disable failures, omit
required features without recording them, or move unsupported behavior behind a
misleading enabled flag. Preserve current dependency/security and catalog changes.

## Order W2: Integration Verification and Candidate

Complete M2 checks. A suggested starting reactor command is:

```sh
mvn -pl ambari-server -am -DskipTests -DskipPythonTests test-compile
```

This checks compilation, not passing tests. Then run focused suites for changed
registration, metadata, API, identity, Agent, schema and lifecycle behavior using
the project's existing runners. Choose actual existing test names, and include
failure/retry cases. Record exact commands; do not paste a planned command as a
successful test result. Validate instance-manager packaging and Python tests.

Create reviewable candidate commits using `AMBARI-14714:` subjects and explicit
file selection. Keep temporary logs and host-specific launch artifacts outside
tracked source. Write `reviews/M2-candidate.md` with exact candidate SHA, test
results, feature accounting and remaining risks.

Pause publication at this checkpoint for the parent's exact-commit review. User
authorization to push is already recorded; the pending gate is technical review,
not a repeated permission request. Perform independent safe review/cleanup work
while awaiting the review; do not push a moving target.

## Order W3: Publication and New Worktree

Only after the parent's recorded acceptance of the exact candidate:

1. Verify the `apache/ambari` trunk target and check for remote advancement.
2. Push the accepted commit normally; no force push or protection changes.
3. Verify remote SHA and record it in the execution log.
4. Create a new improvement worktree from that verified trunk revision.
5. Continue W4 there, keeping the integration worktree as an auditable checkpoint.

The parent can communicate review through the tmux terminal or a clearly
identified review document. The implementation worker must not self-author the
parent's acceptance record.

## Order W4: Improvements and Authoring Tools

Follow R1+ in the integration plan, using the working contracts and reference
scenarios. Each topic includes implementation, relevant tests, documentation and
a concise checkpoint for parent review. Cover all four runtime families in the
target architecture; capability declarations must distinguish implemented,
tested and unsupported combinations.

## Checkpoint Template

```text
Order and batch:
Worktree / branch / exact HEAD:
Changed paths and upstream provenance:
Implemented behavior:
Multi-cluster compatibility evidence:
Exact validation commands and results:
Failures / skipped checks / unverified runtime cases:
Open review findings:
Next independent work:
Publication status:
```

Use English in source, scripts, CLI output, commits and repository documents.
Use ASF headers on new applicable files. Keep credentials out of all artifacts.
