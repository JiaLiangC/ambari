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

# Independent Mpack sources and distribution

This filename preserves links to the former Store proposal. The active design has no
hosted Store, website, object storage, publisher accounts or remote registration API.
The independent `ambari-mpacks` repository holds package sources and build scripts. It
is not yet a remote ASF repository or approved release.

## Source and builds

One directory under `packages/` owns one integration: metadata, Ambari service
definitions, lifecycle scripts, configuration and artifact locks. Simple packages may
use the declarative compiler; software such as Kyuubi may carry standard Ambari Python
command scripts. Software-specific behavior stays in the Mpack, not Ambari core.

Authors use the pinned Ambari tooling, an external Ed25519 key and the same validation
to build their own packages. The `master` branch and CI output are development
material. Ambari administrators independently configure trusted publisher keys and
authorize installation.

## Software artifacts

Artifact identity is fixed by logical name, upstream version, size and cryptographic
digest. Transport is selected independently:

| Mode | Source | Use |
| --- | --- | --- |
| Embedded | Verified blob carried by the Mpack | Offline installation or small software |
| Network | Administrator-approved HTTP(S) location selected during install | Large upstream releases |
| Local | Absolute path on every selected Agent host | Pre-staged or shared storage |

Every mode must resolve to the locked digest before lifecycle code receives the local
file. URLs and paths cannot redefine the expected bytes. Local sources must be regular
files under administrator-approved roots; symlinks and ambiguous Server-local paths are
rejected. Credentials belong in Ambari's credential store.

The builder may create thin and embedded variants. If their carrier bytes differ, they
must use explicit delivery variants and must not reuse one publisher/package/version
identity with different digests. Embedded builds may fetch and verify upstream files in
temporary/cache storage; source control does not store large binaries.

## Full-package distribution

`build-all` discovers every package directory. There is no curated subset or selection
list. A failure aborts the build before publishing its output. It produces individual
signed `.mpack` files and one deterministic `mpack-collection/v1` ZIP whose index lists
publisher, package, version, size and SHA-256 digest. "Full" means every Mpack
definition, not forced embedding of every upstream binary.

The current `.mpack` contains signed metadata and a definition archive. Planned
embedded variants may add signed content-addressed blobs; thin variants resolve the
same artifact identity at installation. A collection is transport, not publisher or
ASF release authentication. Official release candidates additionally require license
and redistribution review, detached signatures, project approval and ASF publication.

## Ambari flow

Single packages use the existing file or approved-URL importer. The branch also accepts
a bounded collection at `POST /api/v1/mpacks/imports/collections`, checks its exact
inventory and invokes the ordinary signed importer for each package. Import never runs
package scripts; it only publishes definitions and catalog projections.

The UI then lists services from imported Mpacks. The operator selects service, hosts,
configuration and artifact transport. Server rechecks RBAC and the complete plan before
creating a normal Ambari request. Agent resolves the chosen artifact, verifies its
digest and executes the trusted package lifecycle. Catalog deletion is not software
uninstall.

## Verification

Repository tests cover all-source discovery, deterministic thin/embedded builds,
artifact locks, damaged inputs and external-key signing. Ambari tests cover bounded
collection import, package trust, artifact source policy and install-plan authorization.
The Kyuubi flow in [implementation-plan.md](implementation-plan.md) supplies the required
real Server/Agent/systemd evidence.
