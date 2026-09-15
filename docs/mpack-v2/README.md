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

Mpack V2 lets a trusted package add and manage host software without adding that
software to Ambari core or first converting it to an RPM. A package may contain its
own Ambari service definitions, lifecycle scripts, configuration and software binary,
or acquire a digest-pinned binary from an operator-selected URL or target-host path.
Ambari still owns authorization, host assignment, configuration, requests and Agent
execution. Importing such a package is therefore trusted-code admission, not sandboxing.

Ambari itself is built as Server and Agent RPMs for the validation cluster. Software
managed by Mpack, starting with Kyuubi, is installed from its upstream binary rather
than a Kyuubi RPM. No Kyuubi-specific branch belongs in Ambari Java, Python or UI.

The independent source repository and periodic all-package collection are described in
[distribution](store-design.md). There is no hosted Store, publisher website or curated
subset. "All-package" means every Mpack definition; large upstream binaries may remain
external. [Implementation plan](implementation-plan.md) makes the Ambari RPM plus
Kyuubi UI flow the next acceptance milestone. [Status](status.md) distinguishes what is
already implemented from that unexecuted plan.

The current `v2alpha1` authoring compiler is a declarative convenience subset. It does
not yet express package-owned lifecycle scripts or optional external binary delivery;
the next milestone must add that source/build path without weakening package signing.

## Read in this order

1. [Architecture](architecture.md): boundaries, ownership, decisions and tradeoffs.
2. [Contracts](contracts.md): identity, configuration, dependency and operation rules.
3. [Manifest](manifest-spec.md): versioned authoring format and validation.
4. [Reference acceptance](reference-examples.md): the Kyuubi golden path and supporting
   host scenarios; these are acceptance requirements.
5. [Implementation plan](implementation-plan.md): ordered work and exit criteria.
6. [Status and provenance](status.md): current findings, executed checks and limits.
7. [Independent review](reviews/independent-architecture-review-2026-09-10.md):
   historical findings against c7dc663f7c, retained for traceability.

Keep one architecture, one implementation plan and one status ledger. Historical
reviews preserve their original findings and do not override these current documents.
Do not report a build, import or unit test as proof of live installation.
