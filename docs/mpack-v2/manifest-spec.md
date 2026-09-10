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

# Mpack Authoring Manifest Specification

This is the working new-authoring contract for the improvement phase. It is not
the manifest accepted by unmodified legacy V2 registration. Implement a validated
reader/compiler and compatibility projection before using it for deployment.

## Source and Built Forms

YAML and JSON serialize one canonical model. The proposed source discriminator
is `apiVersion: mpack.ambari.apache.org/v2alpha1` and `kind: Mpack`. Keep the alpha
version until the contract is validated; do not mislabel it as the legacy package
version or imply that the schema is already a released Ambari API.

| Field | Required meaning |
| --- | --- |
| metadata.name | Stable package identifier; not a Cluster name |
| metadata.version | Package release version; distinct from software binary version |
| metadata.displayName / description | Optional presentation metadata |
| spec.compatibility | Supported Ambari, Agent SDK and adapter contracts |
| spec.artifacts | Local or supported remote source references with platform facts |
| spec.services | Stable service definitions projected onto current service-name identity |
| service.components | Existing component categories plus declared management roles |
| component.profiles | Explicit runtime adapter, artifacts, resources and capabilities |
| service.configurations | Typed schema/template references and change effects |
| service.requires / provides | Named interface requirements and exported capabilities |
| service.operations | Typed custom-operation parameters and implementation references |
| service.observability | Health, metrics, logs, alerts and generic presentation metadata |

Deployment intent is separate from package source. It supplies existing Cluster
identity, authorized targets, selected profile, user configuration and explicit
provider bindings. A source manifest cannot grant itself a target or permission.

## Minimal Illustrative Source

The referenced payload/schema/template files must be supplied by the template
generator. This is a field-level example, not a claimed runnable existing package.

```json
{
  "apiVersion": "mpack.ambari.apache.org/v2alpha1",
  "kind": "Mpack",
  "metadata": {
    "name": "http-echo",
    "version": "0.1.0",
    "displayName": "HTTP Echo"
  },
  "spec": {
    "compatibility": {"agentSdk": "v1"},
    "artifacts": [
      {"id": "echo-script", "source": {"kind": "file", "path": "payload/server.py"}}
    ],
    "services": [
      {
        "name": "HTTP_ECHO",
        "configurations": [
          {"name": "echo", "schema": "schemas/echo.json", "template": "templates/echo.conf.j2", "changeEffect": "restart"}
        ],
        "components": [
          {
            "name": "ECHO_SERVER",
            "category": "MASTER",
            "role": "service",
            "cardinality": {"min": 1, "max": 1},
            "profiles": [
              {
                "id": "linux-systemd",
                "adapter": "host.systemd/v1",
                "capabilities": ["install", "configure", "start", "stop", "observe"],
                "resources": {
                  "packages": ["python3"],
                  "command": {
                    "program": "python3",
                    "arguments": [{"artifactRef": "echo-script"}, "--port", {"configRef": "echo.port"}]
                  }
                },
                "health": {"kind": "http", "portRef": "echo.port", "path": "/health"}
              }
            ]
          }
        ]
      }
    ]
  }
}
```

Runtime profile identifiers are versioned extension contracts, not a claim that
all these adapters are already installed. Literal arguments and typed references
are resolved through the SDK, not evaluated as arbitrary shell expressions.

## Validation Rules

- Validate schema version, types, required fields and recognized extensions.
- Enforce unique package-local artifact, service, component and profile keys.
- Resolve every file and reference within the package boundary; reject traversal
  and incompatible archive/link layouts before publishing.
- Validate existing service/component naming and cardinality rules. Reject a
  collision with an existing service identity; do not invent aliases to bypass it.
- Match capabilities to declared implementation and required verification.
- Check effective configuration types, defaults, references, secret handling
  and change effects. Unknown fields are diagnostics rather than silent drops.
- Distinguish service JDK requirements from Ambari server JDK requirements.
- Validate adapter/platform combinations and required runtime versions.
- Resolve named dependency requirements only through supported shared protocol
  versions. Two same-type slots are not supported by a one-slot protocol merely
  because the source format can express them.

## Built Package

Build emits normalized metadata, resolved artifact/dependency locks, content
digests, file inventory and provenance. Remote references are pinned for an
executable plan. Local source artifacts are hashed during build. Sources with
credentials are handled through credential references, not archived URL secrets.

The build must be deterministic for identical resolved inputs. Offline export
includes the referenced artifacts and enough metadata to validate without a
running Ambari instance. Registering a package does not execute its install hooks.

## Legacy Projection

Legacy V1/V2 readers retain their explicit format detection. Normalize compatible
service metadata without changing Cluster/service identity. Where runtime still
requires XML/Python/Stack views, compile those artifacts from the canonical model
with one declared source of truth; do not run two competing lifecycle engines.

Unsupported legacy ServiceGroup or service-ID semantics produce a useful
compatibility result. Do not silently perform a primary-key migration.

## Schema Delivery

Implement the machine-readable schema, fixture manifest, generator and validator
together in the improvement worktree. Tests cover this positive example, missing
files/references, invalid types, capability mismatch, identity collision, unknown
schema version, malicious paths and deterministic build output. Keep all example
field changes synchronized with contracts and tooling.
