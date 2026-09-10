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

# Mpack V2 Execution and Review Record

This records current remote execution and historical local evidence. See
[integration-plan.md](integration-plan.md) for the full design and acceptance
matrix and [work-orders.md](work-orders.md) for active implementation scope.

## Current Remote Handoff

The user has authorized a fresh remote worktree and interactive Codex execution
using `gpt-5.6-sol`, `xhigh`. The earlier local pause and Luna assignment are
superseded. No raw conflicted source was transferred.

| Item | State |
| --- | --- |
| Host | root@10.10.10.2 |
| Worktree | /jialiangc/bigdata/prjs/ambari-mpack-v2 |
| Branch | AMBARI-14714-mpack-v2-remote |
| Initial HEAD | 8051a841cf03673260fd025d6b9eeee68d98e0c4 |
| tmux session | ambari-mpack-v2 |
| Runtime | Codex CLI 0.153.4; Sol xhigh; interactive TUI |
| Setup state | Interactive session started and observed executing W0 |
| Current work order | W0 remote baseline and capability mapping |
| Publication | Not performed; parent exact-commit review required |

Setup verification: all 12 documentation files passed local link/header/text
checks; 38 relative links resolved and the JSON manifest example parsed.
Remote SHA-256 checks matched the reviewed local documents before launch.
The launcher passed `bash -n` locally and remotely. The tmux TUI displayed
`gpt-5.6-sol xhigh`, its pane was alive, and the worker executed the worktree
status check and began reading AGENTS.md and the supplied document set.
No compilation, integration test or publication is claimed by this setup record.

## Historical Local State

| Item | State |
| --- | --- |
| Implementer | None active; agents stopped/completed at user request |
| Parent responsibility | Planning, evidence review, acceptance and follow-up findings |
| Active order | None; architecture design takes priority |
| Worktree | /Users/jialiang/PRJS/ambari-mpack-v2-integration |
| Branch | AMBARI-14714-v2-integration |
| HEAD | 8051a841cf03673260fd025d6b9eeee68d98e0c4 |
| MERGE_HEAD | 05ffef5b6640a4adcc7af7fff1bec774539a55ae |
| Last independently counted unresolved paths | 620 at architecture pause |
| Merge commit | Not created |
| Remote trunk push | Not performed; user-authorized, pending exact-commit review |
| Improvement worktree | Not created; follows verified remote trunk update |
| Full build / runtime acceptance | Not run on an integrated result |

## Accepted Phase A Evidence

The isolated trial merge was created from the pinned trunk with
`git merge --no-commit --no-ff origin/branch-feature-AMBARI-14714`.

- Initial unresolved paths: 635.
- Initial automatically staged paths: 858.
- Conflict codes: UU 348, UD 124, UA 89, AA 30, DU 28, AU 8, DD 8.
- Server conflicts: 426; web: 163; common: 19; agent: 7; other: 20.
- Web mapping: 153 conflicts at current Classic paths, 10 at old app/test paths.
- Parent verified origin's push repository is `apache/ambari` on GitHub without
  printing credentials. Live trunk matched the pinned target when checked.

Parent accepted the census and released B1A. This acceptance covers only the
trial merge and implementation scope, not source correctness or runtime behavior.

## B1A Handoff and Review

Sol was stopped after the trial inventory. Luna-medium performed partial B1A
edits and was stopped when the user requested higher reasoning strength.
Luna-xhigh resumed the same merge with those edits preserved.

At handoff, root POM had staged and unstaged changes. The old catalog source
files no longer appeared as conflicts. No commit or push occurred.

| Finding | Evidence | State |
| --- | --- | --- |
| Preserve eight historical catalog Java files | Parent ran a HEAD comparison on 251/252/260/261/262/270/271/272; no content diff | Source preservation checked; corresponding tests still part of B1A acceptance |
| Obsolete SCM URL reintroduced | Parent saw root POM change Gitbox scm:git connection back to git-wip-us | Returned to Luna-xhigh for correction |
| XML declaration and whitespace churn | Root POM lost explicit UTF-8 and introduced a whitespace-only line | Returned to Luna-xhigh for correction |
| Legacy instance-manager build settings | Incoming POM uses old parent/module version and old plugins | Assigned for current-parent reconciliation |
| Catalog XML preservation | BIGTOP metainfo conflicts still visible at handoff | Pending implementation verification |

B1A has not been accepted. The agent reported six XML files parsed and
preserved source/test comparisons. The parent independently ran
`xmllint --noout pom.xml ambari-project/pom.xml ambari-server/pom.xml mpack-instance-manager/pom.xml`
successfully and checked the corresponding POM whitespace successfully.

The agent reported Maven unavailable on its PATH and a direct instance-manager
Python test failing on the existing Python 2 print syntax. No whole-build or
runtime acceptance is claimed. Remaining conflict codes independently counted:
UU 345, UD 112, UA 89, AA 30, DU 28, AU 8, DD 8, total 620.

Parent review also identified that the rewritten instance-manager RPM plugin
configuration no longer references the community postinstall/preremove
scriptlets; postinstall creates the executable symlink. This is an open B1A
finding to check and correct when implementation resumes. No source fix or
further agent task was issued after the user stopped implementation.

This local checkpoint was paused for architecture design. It remains historical
evidence; the active execution uses the fresh remote worktree and current runbook.

## Later Review Observations

These are analysis findings for later work orders, not additional B1A scope.

- Read-only classification found 362 unmerged Java paths and 950 conflict
  blocks. Only 25 blocks were equivalent after namespace/whitespace
  normalization. A global namespace-only resolution would be insufficient.
- Modern persistence uses Jakarta while community entities use javax.
- Some API constants are narrowed from public to protected outside explicit
  conflict markers; auto-merged areas require review too.
- Community service-instance storage retains name-only compatibility maps;
  same-named instances in different groups need targeted identity review.
- Current schema upgrade selection is version-based. A V2 schema migration
  must actually be selected for the supported upgrade starting states.

## Updating This Record

After every order, the parent records the exact checkpoint, tests, findings,
acceptance decision and next released scope. A returned finding stays open
until the parent checks the correction. Preserve failed/skipped evidence.

Before publishing, replace pending entries with actual commit IDs and test
results. After publishing, record the verified remote trunk tip and the new
improvement worktree base. Do not describe a local staged merge as a remote
integration or treat conflict count reduction as feature acceptance.

## Active Local M3 Checkpoint

The active worktree is `/jialiangc/bigdata/prjs/ambari-mpack-v2` on branch
`AMBARI-14714-mpack-v2-remote`. The explicit two-parent provenance merge is
`a34f92f1ac78feb22ce6de792d7175fae27ea4f0`; it has no unresolved Git conflict
stages. W1-B2 through W1-B6 compatibility batches are implemented and recorded
under `reviews/W1-*.md`.

The M2 candidate is `b72ade8fcfd553ff182f3d34fe63c0903616005a`. Maven 3.9.16
server compilation, Checkstyle, RAT and six mpack tests passed; instance-manager
Python tests, Python syntax checks, the React production build, 208 React test
files with 1075 tests, and the four-test management-pack model regression also
passed. The active plan now continues local improvement work from this exact
candidate. Remote publication and a remote-derived worktree are removed from
the delivery sequence.

R1 local commits now extend the candidate through manifest validation, runtime
profiles, deterministic package locks, structured diagnostics, scoped operation
planning, configuration provenance, dependency binding interfaces, recovery
transitions, and the machine-readable schema/fixture. Final R1 validation is
deferred until the implementation topics are complete.

The consolidated requirement matrix is in `reviews/R1-status.md`; it is the
authoritative local view of partial and remaining R1 work.
