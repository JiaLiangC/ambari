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

# Mpack authoring tooling

JSON/YAML source uses `mpack.ambari.apache.org/v2alpha1`. All CLI/compiler/fixture
entry points share schema/semantic validation; dependencies are in requirements.txt.
Run from this directory with `PYTHONPATH=src/main/python`.

```bash
PYTHONPATH=src/main/python python3 src/main/python/mpack_authoring/validate_manifest.py fixtures/http/manifest.json --compile --export /tmp/http-source.zip
PYTHONPATH=src/main/python python3 src/main/python/mpack_authoring/validate_manifest.py fixtures/http/manifest.json --legacy-export /tmp/http-host-export --signing-key /path/outside/source/signing.key
```

The first command builds a deterministic source ZIP. It is not directly registered
as a legacy Mpack. The second emits actual `mpack.json`/`definition.tar.gz` containing
service/config XML, declared payload and a wrapper for the shared Agent ManifestService.
Its output directory must be empty and outside the source package. It never runs
native commands. The same external HMAC key must be provisioned to the Server through
`mpack.signing.key.file`; no key is created or committed by these examples.

Exports consume the compiled file lock and reject changes during materialization.
Source ZIP export includes only declared file artifacts/schema/templates. Symlinks,
traversal and input/output collision are rejected. Remote URLs require SHA-256 and
must be vendored before offline export. Requirements retain consumer/slot identity;
they are not resolved/approved bindings. OS package repositories and runtimes are
not bundled. `verify_package` checks a trusted digest, optional HMAC, exact inventory
and source/lock agreement without executing hooks. HMAC is symmetric authentication,
not an asymmetric publisher ecosystem.

Host export supports a single host.systemd/v1 profile per foreground server component,
scalar closed config schemas/templates, packages/users/directories/file artifacts,
typed argv and loopback health. Native unit names derive from the server-owned binding;
there is no manifest unit.name override. It rejects runtime secrets, clients, unresolved
shared dependencies, unsupported templates/constraints, no-effect/reload and migration. Multiple
services/components and files use the same driver; new software does not need a Java
switch or copied lifecycle implementation.

HTTP and Redis fixtures can emit host exports. HTTP includes a small Python program;
Redis uses an OS package prerequisite. Kyuubi includes source, two configuration files
and shared requirements; source export works but deployable export rejects missing
Spark/Hadoop/Hive binding integration. No real runtime success is implied by fixtures.

The local simulated adapters/executor/recovery/journal were removed. ServiceRef and
static profile constraints remain; the real operation authority is Ambari request/task.
DependencyAdapter only delegates to an explicit real client and fails when absent.
See [current status](../docs/mpack-v2/status.md) for executed checks and support limits.
