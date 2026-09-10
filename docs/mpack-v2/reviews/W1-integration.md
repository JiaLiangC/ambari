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

# W1 Community Integration Checkpoint

Recorded: 2026-09-09 UTC.

W1 is active on the explicit provenance merge
`a34f92f1ac78feb22ce6de792d7175fae27ea4f0`. Its first parent is the pinned
trunk and its second parent is the pinned community V2 tip. There are no files
with unresolved Git conflict stages in the worktree.

The implementation batches currently cover these compatible boundaries:

| Batch | Integrated behavior | Main source areas | Contract preserved |
| --- | --- | --- | --- |
| W1-B2 | Registry catalog CRUD, JSON registry loading, mpack/version/scenario projection, deterministic recommendation and validation providers | `ambari-server/src/main/java/org/apache/ambari/server/registry`, `.../controller/internal/Registry*`, `.../api/resources/Registry*` | Registry metadata is catalog state; it does not become cluster or service identity |
| W1-B3 | Mpack recommendation/validation, operating-system metadata, Blueprint `mpack_instances` projection and package-aware advisor request parsing | `.../controller/internal/Mpack*`, `.../BlueprintResourceProvider.java`, `.../topology/MpackReference.java` | Existing `(cluster_id, service_name)` identity remains authoritative; ServiceGroup/generated IDs are excluded |
| W1-B4 | Additive execution-command package context, component version reporting, Python package helper and instance-manager support | `ambari-server/src/main/java/org/apache/ambari/server/agent`, `ambari-common/src/main/python/resource_management`, `ambari-agent/src/main/python/ambari_agent` | Legacy command fields and install actions remain readable; optional package fields are additive |
| W1-B5 | Package metadata, repository/OS projection, persistence and upgrade-catalog wiring | `ambari-server/src/main/java/org/apache/ambari/server/mpack`, `.../orm`, `.../upgrade/UpgradeCatalog310.java`, `Ambari-DDL-*-CREATE.sql` | Existing repository catalogs and upgrade ownership remain present |
| W1-B6 | API-backed package administration in Classic and React | `ambari-web/classic/app`, `ambari-web/latest/src/api/mpacksApi.ts`, `ambari-web/latest/src/screens/ManagementPacks` | Existing admin route/RBAC and current frontend ownership remain in place |

The following compatibility adaptations are deliberate: request-local package
staging and archive checks, atomic publication/rollback, typed registry URI
policy, duplicate and malformed reference rejection, static advisor injection,
and redacted URI display. The implementation does not import ServiceGroup as an
authority, reassign hosts between clusters, add an unscoped package event
stream, or introduce the reference worktree's unfinished dependency-binding
protocol.

An initial server command was run before the execution direction changed to
defer validation until all implementation phases are complete. With the local
Maven 3.9.16 tool, Java compilation completed and six tests passed (`MpackTest`
and `MpackManagerTest`), then Checkstyle stopped the build on twelve import
ordering/unused-import findings. The default Maven 3.8.7 invocation was
rejected by the repository's Maven 3.9.x enforcer before compilation. The
import findings have since been corrected, but no rerun is claimed yet.
Python, browser, database migration, package, and runtime checks remain
deferred until the full implementation and candidate commit set are complete.
Remote publication remains gated on parent review of those exact candidate
commits.
