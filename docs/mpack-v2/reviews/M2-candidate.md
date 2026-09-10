<!---
   Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements.  See the NOTICE file distributed with
   this work for additional information regarding copyright ownership.
   The ASF licenses this file to You under the Apache License, Version 2.0
   (the "License"); you may not use this file except in compliance with
   the License.  You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
--->

# M2 Candidate: Community Mpack V2 Integration

Recorded: 2026-09-10 UTC.

## Candidate commits

The candidate is based on the explicit provenance merge
`a34f92f1ac78feb22ce6de792d7175fae27ea4f0` and is composed of these topic
commits, in order:

| Commit | Scope |
| --- | --- |
| `5c534fd6ae` | Server registry/catalog, Blueprint/API projection, persistence, lifecycle and focused server tests |
| `cf346698cc` | Agent/common package context and instance-manager runtime/package lifecycle |
| `d612c51395` | Classic and React management-pack administration plus model regression tests |
| `20845fca01` | W0/W1 plans, capability ledger, batch evidence and execution log |

The evidence commit is followed by this candidate record. The final candidate
tip is the commit created when this file is committed; the exact SHA is
recorded below after that commit.

## Implemented scope

The integration retains current Ambari cluster and service identity and adds
community catalog, registry, package-aware Blueprint projection, advisor,
Agent, instance-manager, lifecycle, and API-backed administration behavior.
ServiceGroup/generated service identity, host reassignment, unscoped package
events, and the reference worktree's unfinished dependency-binding protocol
are excluded.

## Validation actually run

| Check | Result |
| --- | --- |
| Server Maven compile/checkstyle/RAT and focused tests | Passed with Maven 3.9.16; `MpackManagerTest` and `MpackTest`, 6 tests total |
| Instance-manager Python tests | Passed: 23 tests with Python 3.12 and explicit module `PYTHONPATH` |
| Python syntax compilation | Passed for changed Agent/common/instance-manager modules |
| React production build | Passed: TypeScript project build and Vite production bundle |
| React full test suite | Passed: 208 files, 1075 tests |
| Management-pack model regression test | Passed: 1 file, 4 tests |
| Git conflict/whitespace checks | Passed: no unmerged paths and `git diff --check` clean |

The React build emitted existing Sass deprecation and bundle-size warnings.
The full suite includes an expected recoverable-error test log; no test failed.
The host's default Maven 3.8.7 was rejected by the repository enforcer, so all
server validation used the available local Maven 3.9.16 binary.

## Review boundary

This is a local exact candidate. No remote trunk write, force push, branch
protection change, live-cluster deployment, or credential-bearing operation was
performed. The active plan continues local development from this candidate;
remote publication is removed from the delivery sequence.

Final candidate tip after this record is committed: **pending commit**.
