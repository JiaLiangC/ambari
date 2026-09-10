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

# Developing and validating a new Mpack

An Mpack describes software using a manifest, configuration schemas/templates and
explicit artifacts. New software within an implemented runtime profile uses the
shared Ambari lifecycle; it does not need software-specific Java/Python dispatch,
copied lifecycle scripts or a Store plugin. This guide covers the current
`mpack.ambari.apache.org/v2alpha1` authoring format and bounded `host.systemd/v1`
export, not the future public Store or unimplemented runtimes.

## Set up the tools

Use Python 3.9 or later and the dependencies in [requirements.txt](requirements.txt).
The following Bash examples start in the Ambari repository root and keep working
files outside the checkout. On Windows, use your virtual environment's
`Scripts/python.exe`; the validation script itself is portable Python.

```bash
MPACK_TOOLS="$(pwd)/mpack-authoring"
MPACK_WORK="$(mktemp -d)"
python3 -m venv "$MPACK_WORK/venv"
MPACK_PY="$MPACK_WORK/venv/bin/python"
"$MPACK_PY" -m pip install -r "$MPACK_TOOLS/requirements.txt"
"$MPACK_PY" "$MPACK_TOOLS/validate.py" examples
```

For an offline environment, install these Python dependencies from an approved local
wheel directory beforehand. Validation itself does not download dependencies or
software, start services, call systemd, contact a Store or need a running Ambari.

## Choose an example

The fixtures below are the canonical examples used by tests; there is no separate
copy under an `examples` directory. Copy one whole directory before editing.

| Example | What it demonstrates | Validation scope and prerequisites |
| --- | --- | --- |
| [HTTP](fixtures/http/manifest.json) | Local Python artifact, user, private directory, scalar config and HTTP health | Source build and host export; target needs Python 3 and systemd. The small server binds loopback and answers `/health`; its port and message come from the rendered config. Reload requires an HTTP acknowledgement of the rendered generation. |
| [Redis](fixtures/redis/manifest.json) | OS package prerequisite, rendered config passed through `configurationRef`, foreground process and retained data | Source build and host export; target must provide the declared `redis` OS package and `redis-server`. Adjust package naming for the supported OS. The bundle does not vendor Redis or pin its upstream binary version. |
| [Multi-service YAML](fixtures/multi-service/manifest.yaml) | Two server services and a file-only CLIENT, distinct config types/ports, one reused schema, `directoryRef` and HTTP health | Source build and host export; server targets need Python 3/systemd. The optional `host.files/v1` client publishes configuration and a CLI artifact without starting a process. Runtime acceptance is pending. |

The [minimal](fixtures/minimal/manifest.json) and `fixtures/conformance` inputs are
contract-test shapes, not complete deployment starters. No fixture proves a live
Redis deployment. Actual runtime acceptance is recorded in
[current status](../docs/mpack-v2/status.md).

## Develop your package

1. Copy the HTTP example and choose package, service and component names.

   ```bash
   cp -R "$MPACK_TOOLS/fixtures/http" "$MPACK_WORK/my-service"
   ```

   Edit `metadata.name` and `metadata.version` for package identity; edit service and
   component names for the definitions Ambari will manage. Do not invent cluster IDs,
   host ownership, service aliases or native systemd unit names. Package revision is
   not proof of a particular upstream software version. Publisher packages use `metadata.publisher`; components may declare
   `softwareVersion`. See the publisher release instructions below.

2. Declare artifacts and prerequisites. List every shipped binary/script in
   `spec.artifacts` with a relative `file` path. Configuration schema/template files
   are included through their configuration declarations. Neighboring files are not
   implicitly bundled. A program such as `redis-server` must be supplied by a declared
   OS prerequisite; an arbitrary path to a missing binary is not a distribution.
   Archive artifacts are payloads, not an instruction to extract/install themselves.
   Vendor URL artifacts before offline builds; URL declarations require SHA-256 and
   cannot contain credentials, query strings or fragments. Do not put secrets in files.

3. Define configuration in a closed JSON Schema object with supported scalar fields.
   Give ports integer bounds `1..65535`, and validate defaults. Each configuration
   name is a distinct Ambari config type: update all `configRef`/`portRef` uses when
   renaming it. A template can contain `{{ field }}` substitutions for declared fields and the
   reserved `{{ mpack_config_generation }}` acknowledgement token. The `.j2` suffix does not enable arbitrary Jinja expressions, loops or
   filters. Use several configuration entries for several files, and
   `configurationRef` to pass a rendered file path to the program. Use `x-resource`
   when a field must receive a managed directory path; do not assign it a user default.

4. Select one `host.systemd/v1` profile per foreground server component. Declare
   required OS packages, user/group, isolated directory names, listeners, command and
   unit user/working directory. Arguments are strings or typed references, not shell
   snippets. Run the process in the foreground; the shared adapter owns systemd unit
   creation and lifecycle. `directoryRef` resolves to the bound deployment directory.
   OS users/packages and ports are shared host resources, not private namespaces.
   Reuse compatible users/packages and choose distinct ports when co-locating services.

5. Declare actual health checks and supported behavior. TCP/HTTP probes require a
   scoped `portRef`; HTTP probes use a local path. Configuration changes use restart
   or the generation-acknowledged reload contract below. Host export rejects client-only
   components, unresolved shared dependencies, no-effect configuration, migration and
   non-host profiles. Uninstall, scoped execution secrets and verified reload have source
   implementations in this active batch; consolidated verification is pending. Purge
   follows the separate destructive authorization and retained-target contract below.
   Upgrade and detach still require their explicit lifecycle implementation.

6. Validate, inspect generated content and then build. For authoring-only
   sources, explicitly choose `--target source`. A requirement lock describes needed
   dependencies; it is not a binding UUID, authorization or approved provider snapshot.
   AI-generated manifests must pass exactly the same checks and human review.

The detailed field contract is [manifest-spec.md](../docs/mpack-v2/manifest-spec.md),
with executable schema [manifest-v2alpha1.json](schema/manifest-v2alpha1.json).

## Validate your own Mpack

```bash
# Default target: schema/references, two source builds and two host exports.
"$MPACK_PY" "$MPACK_TOOLS/validate.py" source "$MPACK_WORK/my-service/manifest.json"

# Source-only authoring and offline source-build validation.
"$MPACK_PY" "$MPACK_TOOLS/validate.py" source "$MPACK_WORK/my-service/manifest.json" --target source

# Machine-readable result suitable for CI; preserve the process exit code.
"$MPACK_PY" "$MPACK_TOOLS/validate.py" --json source "$MPACK_WORK/my-service/manifest.json" > "$MPACK_WORK/validation.json"

# All three included examples: HTTP, Redis and multi-service YAML.
"$MPACK_PY" "$MPACK_TOOLS/validate.py" --json examples > "$MPACK_WORK/examples.json"
```

The script works from any current directory. It reuses the compiler, source ZIP
verifier and legacy exporter; it does not implement another manifest schema.
Temporary build products are removed automatically and source files are unchanged.
Host checks use an ephemeral in-memory HMAC or Ed25519 key, according to the
manifest publisher field, only to exercise export. It grants no import trust. Successful checks report stages and
digests without dumping the compiled manifest, credentials or signing material.

Exit codes: `0` means the requested checks passed; `2` means invalid content, a failed
check or invalid command arguments; `3` means missing Python validation dependencies.
The example suite returns `0` only when all three source and host-export checks
succeed. These checks do not install or execute the software.
Diagnostics identify the failed stage and correction category without echoing input
values or exception paths. Edit locally using the schema and the guidance below.

## Review a human or AI repair

Keep the baseline and proposed sources in separate directories. Run the same
validator regardless of who authored the change:

```bash
"$MPACK_PY" "$MPACK_TOOLS/validate.py" --json review \
  "$MPACK_WORK/baseline/manifest.json" "$MPACK_WORK/candidate/manifest.json" \
  > "$MPACK_WORK/review.json"
"$MPACK_PY" "$MPACK_TOOLS/validate.py" source "$MPACK_WORK/candidate/manifest.json"
```

The review report lists changed manifest fields and payload file digests, without
configuration values or file contents. Inspect the actual source diff locally as
well. Invalid candidate sources return exit code 2. A source review alone does not
verify host export, upgrade compatibility, rollback or runtime behavior. A template
change is reported even when the manifest itself is unchanged.

The installed authoring distribution also provides `mpack-review BASELINE CANDIDATE`,
with the same source-review contract. These new commands have source regression
coverage written but not yet executed in the active batch. No AI provider is required
or called. After review, the usual signing, administrator trust policy, authenticated
Ambari import and service authorization still apply. The tool neither applies repairs
nor labels irreversible data changes as reversible software upgrades.

| Diagnostic | Action |
| --- | --- |
| `SCHEMA_INVALID` | Check field names/types, config defaults and scoped references; confirm source files are readable. |
| `PACKAGE_CONTENT_CONFLICT` | Check inventory, file hashes, paths and archive digest; vendor remote artifacts for offline build. |
| `CAPABILITY_UNSUPPORTED` | Stay within the implemented host subset, or use source-only validation without claiming deployment. |
| `DEPENDENCY_UNRESOLVED` | Integrate real shared dependency contracts before host export; a declaration is not approval. |
| `TARGET_CONFLICT` | Remove conflicting definitions or unsupported identity structures. |
| `TOOLING_UNAVAILABLE` | Install requirements with the same Python interpreter used to run the script. |

Offline validation cannot prove that an executable exists on a target, an OS package
is compatible, a port is free, a publisher is trusted, or a service reaches healthy
state. Source reproducibility covers declared bytes, not external OS repositories.
Perform separate Server-Agent/native acceptance before advertising runtime support.

## Build and verify an offline source bundle

```bash
PYTHONPATH="$MPACK_TOOLS/src/main/python" "$MPACK_PY" -m mpack_authoring.validate_manifest \
  "$MPACK_WORK/my-service/manifest.json" --export "$MPACK_WORK/my-service-source.zip" \
  > "$MPACK_WORK/build.json"
MPACK_SHA256="$("$MPACK_PY" -c 'import json, sys; print(json.load(open(sys.argv[1]))["sha256"])' "$MPACK_WORK/build.json")"
"$MPACK_PY" "$MPACK_TOOLS/validate.py" bundle "$MPACK_WORK/my-service-source.zip" --sha256 "$MPACK_SHA256"
```

This locally produced build report can supply the digest for checking your own build.
For a received archive, obtain the expected digest through an independently trusted
channel; computing a digest from the same untrusted download does not establish trust.
The `bundle` command checks a source ZIP's trusted digest, bounded inventory and
source/lock agreement. It does not verify legacy `mpack.json`/`definition.tar.gz` or a
publisher public-key signature. Source ZIPs are not deployable Ambari import packages.

## Export the current deployable host layout

With an externally provisioned alpha signing key, use the existing export command:

```bash
PYTHONPATH="$MPACK_TOOLS/src/main/python" "$MPACK_PY" -m mpack_authoring.validate_manifest \
  "$MPACK_WORK/my-service/manifest.json" \
  --legacy-export "$MPACK_WORK/my-service-host" \
  --signing-key /path/outside/source/signing.key
```

The output directory must be empty and outside the package source. It contains
`mpack.json` and `definition.tar.gz`, including real service/config XML, declared
payload and a wrapper invoking the shared Agent `ManifestService`. Both files must be
available through the existing registration flow. The Ambari Server must be configured
with the same external HMAC key through `mpack.signing.key.file`. Never publish that
key or include it in source, archives, logs or a Store upload. This alpha shared-key
mode is not the planned asymmetric multi-publisher distribution contract.

Registration and local export are distinct from software deployment. Current
independent-package composition into existing clusters and generic uninstall have
open implementation gates; follow [the Ambari plan](../docs/mpack-v2/implementation-plan.md)
and status instead of treating a successful export as a completed install.
Store pages/backend will be implemented later in a separate repository using the
[Store design](../docs/mpack-v2/store-design.md). This guide and validator add no Store
implementation or deployment authority.


## Publisher releases and a single deployable file

For third-party distribution, add `metadata.publisher` (for example `community-demo`)
to your package manifest. `metadata.name` is the package name inside that namespace;
`metadata.version` is the packaging release. Each component may additionally declare
`softwareVersion`. Do not use a packaging version to imply that an unpinned OS package
has that software version. Host OS packages and executables remain explicit external
prerequisites; an offline payload bundle does not contain an entire OS repository.

Create the publisher key outside this repository and outside all package source roots:

```bash
mkdir -p /tmp/my-mpack-publisher
python3 mpack-authoring/publisher-key.py --publisher community-demo \
  --private-key /tmp/my-mpack-publisher/publisher.pem \
  --trust-entry /tmp/my-mpack-publisher/trust.json
```

Keep the private PEM private. Give the public `trust.json` entry and its independently
verified fingerprint to the Ambari administrator. The administrator merges approved
publishers/keys into an external trust file and configures `mpack.trust.store.file`.
A key entry has `publicKey` (base64 DER SubjectPublicKeyInfo), `status: active`, and
optional ISO-8601 `notBefore`/`notAfter`. Revoked, expired, unknown or wrong-publisher
keys cannot import new releases. Revocation does not automatically stop installed
software. The local HMAC alpha path is separate and cannot claim a publisher namespace.
Set `mpack.legacy.allow=false` to reject unsigned legacy imports.

Build one download/upload artifact (activate the authoring environment first):

```bash
PYTHONPATH=mpack-authoring/src/main/python python3 -m mpack_authoring.validate_manifest \
  /path/to/my-package/manifest.yaml --signature-algorithm Ed25519 \
  --signing-key /tmp/my-mpack-publisher/publisher.pem \
  --deployable-export /tmp/my-package-1.0.0.mpack --diagnostics
```

A `.mpack` file contains exactly the signed `mpack.json` and `definition.tar.gz`.
It is distinct from the source ZIP. Upload it in Management Packs, or import an approved
URL ending in `.mpack`; the existing two-file metadata URL also remains supported.
The server stages the complete content and verifies publisher trust before catalog
publication. Installing a service is a separate action using an existing cluster and
registered hosts. Repeating a release identity with different bytes is rejected.

Network imports require an administrator-owned `mpack.download.policy.file`, for example:

```json
{"sources":{"https://packages.example.org:443":{"pathPrefix":"/releases/"}}}
```

Origins include their effective port. Each path prefix starts and ends with `/`.
Redirects, URL user information, query credentials and paths outside that origin/prefix
are rejected. A private HTTPS source can add
`"credential":{"cluster":"existing-cluster","alias":"artifact-bearer"}`;
the alias is resolved through Ambari's existing credential store. Never put the bearer
value in a manifest, URL, catalog, export, diagnostics or source-policy file.

After installation, use existing service configuration and request/task controls.
For profiles declaring `uninstall`, the UNINSTALL request stops owned processes,
removes their owned runtime definitions and retains data/configuration evidence. Check
all target results before removing the service record. Retained resources keep a durable
reference to their package definition even after service/task history removal. Purge is
a separate lifecycle capability; uninstall never means purge.

For profiles declaring `purge`, purge before removing the service record. The user
needs SERVICE.PURGE_DATA (Ambari Administrator by default), and the PURGE request
must include `RequestInfo.parameters.expected_target_incarnation` from the retained
resource row. Ambari rejects historical/recreated targets and unfinished uninstall.
After a partial purge, explicitly resume purge; do not start or uninstall that target
again. Purge deletes retained owned data irreversibly, keeps the receipt tombstone,
and never deletes shared users or OS packages. No automatic backup/restore is promised.
These source paths remain unverified until the consolidated acceptance run.

For local `.mpack` imports, the catalog's source URI points to its verified installed
`mpack.json`, since the uploaded transport is temporary. Approved HTTP imports retain
their artifact URL. Publisher identity and content digest remain the immutable release
identity in both cases; a local source URI does not establish publisher trust.

These newly implemented import/lifecycle paths are undergoing the authorized P0-P8
implementation batch. Their consolidated tests and native acceptance are pending; see
[the active ledger](../docs/mpack-v2/implementation-plan.md#active-implementation-ledger-verification-deferred).


## Scoped execution credentials

Use the existing cluster credentials API at
`/api/v1/clusters/<cluster>/credentials/mpack.<SERVICE>.<alias>` with
`CLUSTER.MANAGE_CREDENTIALS`. That API requires `Credential/principal` (a descriptive
label such as `mpack`), `Credential/key` (entered securely) and `Credential/type`
(`persisted` or `temporary`). Temporary credentials expire and cannot support unattended
restart after expiry. This guide deliberately does not embed credential values in commands.

Declare a sensitive schema field as follows; only the reference is stored in config:

```json
{"type":"object","properties":{"password":{"type":"object","x-sensitive":true,
 "properties":{"secretRef":{"type":"string"}},"required":["secretRef"],
 "additionalProperties":false,"default":{"secretRef":"secret://mpack.REDIS.password"}}},
 "additionalProperties":false}
```

Render `{{ password }}` in a template. The default encoding is a quoted JSON string;
use `x-secret-encoding: literal` only for a format whose grammar safely accepts that value.
Multiline/NUL secrets and secret process arguments are rejected. Environment references
use a private systemd EnvironmentFile. Private config generations reside under
`/run/ambari-mpack`, with individual files readable only by the declared service user.
Stopping/uninstalling clears those files; the next start resolves credentials again.
A changed credential between task persistence and dispatch returns `PLAN_STALE`.
References and keyed generation fingerprints, never plaintext, are retained in tasks.

## Acknowledged reload

The HTTP example implements the source-side acknowledgement for this contract, with native acceptance pending.
Declare `reload` capability, `resources.reloadSignal` (`HUP`, `USR1` or `USR2`), HTTP
health and `changeEffect: reload`. Render `{{ mpack_config_generation }}` into the
config. After validation and actual in-process application, the software must return
that token in `X-Ambari-Config-Generation` at its local health endpoint. The adapter
requires matching generation and an unchanged invocation. Sending a signal is not an
acknowledgement. Port/unit changes, restart-only config and environment secrets require
restart. A missing acknowledgement leaves `UNKNOWN`; recovery observes before any
retry, or the operator explicitly stops and starts through the existing workflow.
Redis retains restart semantics and does not claim this HTTP acknowledgement contract.

## Standalone distribution

The compiler can be packaged without building Ambari. The wheel contains the canonical
schema copied into build output, and installs `mpack-validate`; there is no second schema
source or Store-specific validator. Source implementation is present; wheel acceptance
belongs to the consolidated batch and has not run yet.

```bash
python3 -m pip wheel ./mpack-authoring --wheel-dir /tmp/mpack-wheels
# Install the resulting wheel and its dependencies in a separate environment.
mpack-validate /path/to/manifest.yaml --compile --diagnostics
```

The repository's `validate.py` additionally checks example expectations and repeated
build reproducibility. Human and AI authors use the same compiler, review the source
diff, and sign only accepted output. This tooling does not approve deployments, repair
a live cluster, or claim a reversible data migration.


## File-only client components

Use `category: CLIENT`, `role: client` and `host.files/v1` for files/configuration
consumed by a user-invoked CLI. Supported actions are install, configure, observe,
uninstall and separately authorized purge. Declare vendored executable artifact IDs
in `resources.executableArtifacts`; files are published as 0755 only when explicitly
listed. No daemon, port, health endpoint, start, stop or reload is implied. This profile
currently rejects live secrets and upgrades to another package digest.

The multi-service YAML package includes `STATIC_WEB_CLIENT`. Its executable and
configuration are under the existing incarnation-scoped Agent deployment directory:
`releases/<package-digest>/client.py` and `config/current/website.conf`. Run the former
with `--config` pointing to the latter on a host where the demonstration server is
listening. Ambari never runs the CLI as an installation hook. Observation checks
published file hashes/modes; uninstall withdraws the config publication and retains
files/data until purge. Source and regression coverage are added, with the consolidated
verification phase still pending.


## Compatible artifact updates and ownership handoff

A `host.systemd/v1` profile may declare `upgrade` plus `upgradePolicy` with explicit
`fromPackageDigests`, `configuration: compatible` and `data: unchanged`. Stop the
service, select the imported candidate in Ambari, then submit the existing UPGRADE
request pinned to its digest and target incarnation. Resource layout and package
identity must remain unchanged. Starting is a separate action. This does not upgrade
Redis's shared OS package, migrate data or provide an automatic rollback. Failed
updates preserve the last confirmed release reference; selecting that release restores
metadata and requires native verification before another start.

Declare `detach` and `adopt` together only for non-secret server profiles. Both require
a stopped, verified target. Detach leaves its unit, files and data for external
management; adopt reclaims only the same target while the service incarnation and
package still exist. Changed publication, foreign units or a recreated service fail
admission. Complete a pending handoff before other operations. Remove the service
record only after deciding that the external owner will manage those retained resources.

## Existing metrics and log integrations

Optional `spec.services[].observability` maps existing component names to collector
contracts. For example:

```json
{
  "logs": {"HTTP_ECHO_SERVER": "mpack_http_echo"},
  "metrics": {
    "HTTP_ECHO_SERVER": {
      "portRef": "http.port",
      "protocol": "http",
      "path": "/metrics",
      "fields": {"requests": ["http", "requests"]}
    }
  }
}
```

The metric port must reference an integer schema field bounded to 1..65535. The
compiler emits Ambari's built-in REST metric provider, with point-in-time numeric
fields such as `metrics/mpack/requests`. It does not load a publisher-selected Java
class. Expose only non-sensitive JSON at this dedicated endpoint and make it reachable
from the Server on the component host; the loopback HTTP fixture does not meet that
remote-network prerequisite. Logs map to existing LogSearch IDs and require an
installed collector and configured redaction. Existing metrics/log permissions and
host/service APIs control access. These declarations do not install a collector or
claim that log ingestion has been verified.


## Software and runtime extension boundary

Keep product-specific installation recipes, configuration, readiness semantics and
upgrade/data compatibility in your Mpack. Ambari's core manages validation, identity,
permissions, requests/tasks and shared runtime execution. Adding another product to
an existing runtime must not require Java/Agent/UI branches for its software name.
Declare only capabilities backed by an implemented execution/verification/recovery
contract. A manifest declaration alone does not supply a missing executor.

The local `oci.container/v1` implementation currently accepts rootful Docker or Podman,
a preloaded `name@sha256:<digest>` image, a non-root host `runAsUser`, scoped directory
`mounts`, and optional literal command/environment entries. Configuration files appear
at `/etc/ambari-config/current/<configuration-name>.conf`; resource-backed configuration
fields use their declared container paths. Image provisioning is an external
prerequisite, so an offline source bundle does not include the OCI image automatically.
Install creates a stopped container; configure publishes files and start/restart applies
them. Uninstall removes only the bound container, and a separately authorized purge
removes owned retained host data. Images, shared users/packages and foreign volumes
are never removed. No arbitrary engine flags, daemon credentials, image pulls,
live secrets, OCI upgrade or ownership handoff are supported by this slice.
The source and its CLI-response fixtures are unverified until the consolidated run;
no Docker/Podman deployment has been performed for this batch.
