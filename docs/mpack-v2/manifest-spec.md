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

# Manifest authoring contract

The executable source of truth is
[`manifest-v2alpha1.json`](../../mpack-authoring/schema/manifest-v2alpha1.json),
with semantic checks in `mpack_authoring/schema.py` and `compiler.py`. Use
`apiVersion: mpack.ambari.apache.org/v2alpha1`, `kind: Mpack`. This alpha source
version is distinct from legacy registration format and runtime contract version.

This document describes the implemented declarative authoring subset, not the full
Mpack container. Management packs can carry complete Ambari service definitions and
package-owned command scripts. Adding that source path and optional embedded/network/
local binary delivery to the independent builder is the next milestone in
[implementation-plan.md](implementation-plan.md); those fields are not accepted by the
current schema yet.

## Source fields and limits

| Field | Meaning and current validation |
| --- | --- |
| metadata.name/version | Package release identity; neither a cluster nor generated service ID |
| metadata.displayName/description | Optional presentation |
| spec.compatibility | Declared Ambari/Agent SDK/dependency protocol requirements; declaration does not prove runtime compatibility |
| spec.artifacts | Unique file or URL references; local file hashes/sizes locked; URL requires SHA-256, no userinfo/query/fragment |
| spec.dependencies | Package-level requirements; no automatic binding approval/resolution |
| spec.services | Service definitions using existing Ambari names |
| service.components | Named category/role/cardinality and explicit profiles; CLIENT exports use host.files or external.database with their own capability limits |
| component.profiles | Profile ID, supported adapter (`host.systemd/v1`, `host.files/v1` or `external.database/v1`), declared capability subset, typed resources and optional health |
| service.configurations | Unique config names, local schema/template files and defaults; active services restart after changed publication |
| service.requires/provides | Named interface slots/version contracts; requires lock retains consumer service plus slot |
| service.operations | Reserved; only an empty array accepted |
| service.observability | Bounded existing REST metric and LogSearch projections; health has its own bounded shape |

Host resources describe packages, users/groups, directories/retention, ports, program,
arguments/environment and unit user/group/working directory. External observation uses
a package probe, non-root run-as user and provider-native identity. Static adapter
capability sets in profiles.py are authoring constraints; deployment discovery is
separate evidence. Container and orchestrator resources are not part of this schema.

Arguments support strings and typed artifactRef/configRef/configurationRef/directoryRef/
secretRef expressions. Known artifacts/config fields/directories must resolve within
the declared scope. A configurationRef requires a template. Host secret references
are allowed in private runtime configuration and environment files, never process
arguments. The P6 implementation uses scoped existing credentials and encrypted Agent dispatch; current interoperability evidence is in status. Health is process, TCP or
HTTP with a bounded timeout and a required schema-constrained port reference for
network probes. Every declared listener also requires a bounded integer port field.
Host preflight checks IPv4 listeners; HTTP probes remain at their original endpoint.

Configuration schemas use JSON Schema 2020-12, local references only, and object roots.
Defaults are validated without requiring deployment-supplied fields. Sensitive defaults
must be SecretRef objects. Host export supports closed scalar fields and closed
`x-sensitive` objects with a single required `secretRef` string. Secret defaults use
`secret://mpack.<SERVICE>.<alias>`; config projection emits a SECRET_REFERENCE property,
and runtime values are not written to durable package/config generations. Other
constraints and template substitutions retain their explicit bounded support. `x-resource` string
fields inject an isolated managed directory; defaults/overrides/extra constraints are
not allowed for these runtime-owned values. Runtime validation repeats the supported
scalar constraints after applying Ambari desired values. Unsupported constraints fail
export instead of disappearing from generated UI/runtime behavior. Host configuration
changes restart an active systemd target. Reload, upgrade, handoff and package data
procedures are not source fields or capabilities. Current local validation and native
acceptance limits are recorded in status.

## Source examples and standard onboarding

Use complete source fixtures instead of copying another illustrative schema:

- [HTTP](../../mpack-authoring/fixtures/http/manifest.json): declared Python artifact,
  user, private data directory, port and common host lifecycle.
- [Redis](../../mpack-authoring/fixtures/redis/manifest.json): OS package prerequisite,
  foreground redis-server and generated config-file argument; persistent data retained.
- [Multi-service YAML](../../mpack-authoring/fixtures/multi-service/manifest.yaml):
  two server services and a file-only CLIENT, distinct config defaults/ports and shared schemas.
- [External PostgreSQL observer](../../mpack-authoring/fixtures/external-postgresql/manifest.json):
  package-owned native identity probe, local registration and remote read-only observation.

The English [development guide](../../mpack-authoring/README.md) explains how to copy
and adapt these sources, build them and run `mpack-authoring/validate.py`. Its `examples`
command checks HTTP, Redis, multi-service YAML and external PostgreSQL source/export. A passing
suite proves no live runtime deployment.

New software that fits `host-service/v1` changes its manifest, schema/templates and artifacts,
then uses the existing compiler/export/import and Ambari service workflow. One profile
per component is explicit; there is no automatic profile selection. The exporter writes
real legacy service/config XML and one wrapper around the common Agent Script. The
native unit name is generated from existing ServiceRef/component/host binding incarnation;
there is no unit.name override or alias that creates a second service identity.

## Outputs and verification

`compile_manifest` returns canonical source, manifest digest, package digest, artifact
locks, consumer-scoped dependency requirements, metadata-only legacy preview and
provenance and a file inventory captured by compilation. Package digest covers that
inventory. Source and legacy exports compare the exact bytes to the compiled lock;
a changed input cannot silently receive the original package identity or signature. A source ZIP uses
fixed archive metadata and an exact file inventory; undeclared directory neighbors,
symlinks and previous outputs are excluded. In this subset, local archives are payloads
and URL artifacts must be vendored before host export. This is not a product requirement
that every software binary be embedded.

`--legacy-export` is distinct from `--export`: it requires an external signing key
and creates the actual legacy V2 registration layout for the host subset. The Server
verifies the signature and content before publication. See the
[tooling commands](../../mpack-authoring/README.md) and [trust contract](contracts.md).
Compiler validation/build executes no scripts, dependency mutations or native commands.

Deployment-time authorization, host assignment, native capabilities and shared approval
cannot be validated by source compilation alone. Source fixtures must not be described
as successful Redis deployment; current matrices and exact evidence are in
[status](status.md).
