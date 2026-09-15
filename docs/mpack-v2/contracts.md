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

# Mpack V2 contracts and authority

## Identity and trust

A release is identified by publisher/package/version metadata and immutable content
digest. A registry ID or download URI is discovery metadata, not execution authority.
Public publisher releases require an accepted asymmetric signature. The alpha HMAC
format is an explicitly enabled local compatibility path and cannot authenticate a
publisher identity.

Package URLs allow `file`, `http` and `https`. They reject user information, query
strings, fragments, redirects and remote file hosts. Network imports require an
administrator-owned source policy that permits an exact origin and path prefix.
Private bearer credentials come from Ambari's credential store and require HTTPS;
they never appear in package metadata or URLs.

The Server allocates a target incarnation for each service row. Task identity is:

```text
cluster + service + component + assigned host + target incarnation
```

Recreating a service creates a different incarnation. A matching native name without
that identity is not owned and cannot be adopted or deleted.

## Authoring and import

The source schema is closed. Unknown fields, unsupported profiles/capabilities,
undeclared references, unsafe paths, symlinks and mutable input bytes fail validation.
Compilation captures a deterministic inventory and produces reproducible source and
legacy exports. Compilation does not download software, execute hooks, contact a
cluster or grant deployment approval.

The deployable `.mpack` contains exactly `mpack.json` and its referenced definition
archive. Import applies entry, byte and expansion limits, verifies metadata and
signature before publication, and uses pending markers to reconcile filesystem/DB
crash windows. DB catalog state is authoritative; files and Stack links are required
projections.

## Install plan

The UI and external clients use:

```http
POST /api/v1/clusters/{cluster}/mpack_install_plans/{planId}
Content-Type: application/json

{
  "MpackInstallPlan": {
    "repositoryVersionId": 43,
    "serviceName": "HTTP_ECHO",
    "assignments": {"HTTP_ECHO_SERVER": ["host.example"]},
    "configurations": {"http": {"port": "18080"}},
    "validateOnly": true
  }
}
```

`planId` is a canonical UUID and remains stable when the operator retries the same
dialog. The client first submits `validateOnly=true`, then repeats the same request
with `false`. Server revalidates both requests. It requires service-create,
host-component and start/stop permissions, plus modify-config permission when configs
are present.

Before mutation Server verifies that the repository belongs to an imported Mpack,
the service comes from that exact definition, assignments cover every component,
host values are unique and registered, cardinalities match, configuration types are
declared and values satisfy package schema. It rejects a running service or one pinned
to another release.

Execution reuses existing service/component/host/config resource providers. Missing
records are created; matching records are retained. Config tags are deterministic for
the plan. The final state change creates an ordinary Ambari request. A repeated plan
after request persistence returns that request ID instead of scheduling a second
install. The client never performs the individual writes itself.

## Task and Agent execution

Immediately before `execution_command` persistence, Server binds package ID/digest,
cluster, service, component, host, target incarnation, operation, config tags and
config value hashes. Reserved Mpack/runtime parameters cannot override this binding.
Only the service's declared config types are forwarded.

Agent mutation is accepted only for an existing Server task and current host
assignment. Its plan includes current native observation, expected receipt digest and
a 30-second expiry. A root-owned receipt is atomically written under an exclusive
per-target lock before and after side effects. A reused or older task, changed intent,
stale package digest, expired plan or foreign native target fails before mutation.

The executable lifecycle is limited to:

| Profile | Actions |
| --- | --- |
| `host.systemd/v1` | install, configure, start, stop, restart, observe, uninstall, purge |
| `host.files/v1` | install, configure, observe, uninstall, purge |
| `external.database/v1` | install, configure, observe, uninstall |

Configuration publication uses immutable generations and an atomic `current` pointer.
Changing configuration restarts an active systemd service. Readiness requires the
exact loaded unit, active process identity and declared local health. File readiness
requires the exact publication pointer, hashes and modes. External database readiness
requires a signed, non-root probe to confirm the declared provider identity; Ambari
never creates, upgrades, migrates or deletes that database.

Native subprocesses have bounded output, deadline and process-group cancellation.
Cancellation is a request, not proof that side effects stopped. An interrupted result
remains `UNKNOWN` unless observation independently proves the same intent. Automatic
retry does not repeat ambiguous mutation. STOP may reconcile uncertain process state.

## Removal and retention

Every successful uninstall or purge observation includes these typed common fields:

```json
{
  "managementReleased": true,
  "runtimeDisposition": "absent",
  "dataDisposition": "retained",
  "ownershipDisposition": "released"
}
```

Only these released combinations are valid:

| runtimeDisposition | dataDisposition | ownershipDisposition | State |
| --- | --- | --- | --- |
| `absent` | `retained` | `released` | `UNINSTALLED_RETAINED` |
| `absent` | `purged` | `released` | `PURGED` |
| `external` | `external` | `external` | `UNREGISTERED` |

`managementReleased=false`, missing fields, strings used as booleans and mixed
external/managed dispositions fail closed. Server consumes only this common envelope
for release admission; adapter-specific observation remains diagnostic evidence.

Uninstall stops and verifies a managed process where applicable, withdraws owned
runtime publication and records retained paths. It never deletes persistent data,
shared OS packages or users. External uninstall removes only Ambari registration and
reports external ownership.

Purge requires `SERVICE.PURGE_DATA`, the current retained target incarnation and a
verified uninstall receipt. It validates the exact retained device/inode inventory,
does not follow symlinks or cross mount boundaries, and retains a receipt tombstone.
Once purge begins, only the same purge recovery may advance that incarnation.

Service/host-component deletion is admitted only for
`UNINSTALLED_RETAINED`, `PURGED` or `UNREGISTERED`. Catalog deletion remains blocked
while retained resources reference the release. There is no force-abandon API: when
the Agent or receipt is unavailable, the target remains blocked until evidence can be
recovered or the installation is repaired under an operator-controlled procedure.

## Catalog and Store

Package reference writes and catalog removal share the package-row lock; foreign keys
remain the final integrity guard. Removal deletes unreferenced repository/Stack/catalog
rows transactionally, invalidates cached projections, then quarantines filesystem
content. A filesystem cleanup failure is retried during startup. Catalog removal never
uninstalls software.

The Store owns publication accounts, moderation, key lifecycle and public discovery.
Ambari consumes only signed registry metadata and immutable artifacts. Store state is
never copied into cluster authorization, tasks or native ownership.

UI, CLI and AI are untrusted clients of these same APIs. None can fabricate target
incarnation, task binding, source approval or removal evidence. Stable error categories
include `SCHEMA_INVALID`, `CAPABILITY_UNSUPPORTED`, `DEPENDENCY_UNRESOLVED`,
`PLAN_STALE`, `TARGET_CONFLICT`, `AUTHORIZATION_DENIED` and `OUTCOME_UNKNOWN`; error
messages must not echo secrets.
