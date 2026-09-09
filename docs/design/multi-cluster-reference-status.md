<!--
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
-->

# Multi-cluster source reference checkpoint

Issue: [AMBARI-26654](https://issues.apache.org/jira/browse/AMBARI-26654).
Base: `a62fe4959dc948210d844295a097a3311321dea6` (PR #4208).

This branch records implementation progress for design and source review. It is
not the final accepted multi-cluster deliverable. Compilation, focused regression
tests, browser checks and isolated cluster validation have not run. Source-review
acceptance does not establish runtime correctness or release readiness.

Included source covers cluster identity and authorization scoping, exclusive host
membership, non-destructive cluster/repository creation, persisted workflow
recovery, scoped event and metric paths, unified React cluster/service directories,
explicit cluster navigation, legacy workflow isolation, managed dependency domain
and persistence, provider/client runtime helpers, and the first managed-dependency
wizard and immutable CREATE recovery integration. Focused regression source is
included with those changes. The shared preparation protocol renders the complete
client profile set while reporting only explicitly selected preparation bindings.

The incomplete next frontend advisor integration and authoritative security producer
edits were excluded from this checkpoint. They remain in the implementation
worktree. Existing safe unsupported/incomplete outcomes must not be interpreted as
completed secure cross-cluster deployment.

Remaining integration and review work includes:

- Add Service and configuration-step advisor context across the entire workflow.
- Full same-realm security producer, coherent complete-plan approval/creation,
  actual credential delivery and verification ordering.
- Provider STOP/RESTART impact confirmation and final consumer START/RESTART guards.
- Durable per-binding retry/update/detach integration and deployment progress UX.
- Final lower deletion review: complete service-removability prevalidation must be
  inside the bulk lock boundary, and the normal direct transactional deletion path
  still needs evidence of publication ordering without a fixture-only outer lock.
- One integrated build followed by relevant focused tests and isolated runtime/
  browser validation. Full unit suites have not been run or claimed.

The target model remains one server/database managing independent Cluster records;
one host/agent belongs to one runtime cluster. Provider ownership and stored data
remain independent of consumer removal. This logical separation shares the Ambari
server/database failure domain. See the architecture and interaction documents in
this directory for the intended final contract and acceptance scenarios.
