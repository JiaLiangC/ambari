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

# W1 Batch 1: Instance Manager and Packaging

Recorded: 2026-09-09 UTC.

## Checkpoint

| Item | Evidence |
| --- | --- |
| Order and batch | W1-B1: current build layout, Agent dependency, instance-manager runtime and packaging |
| Starting HEAD | `8051a841cf03673260fd025d6b9eeee68d98e0c4` |
| Community parent/source | `05ffef5b6640a4adcc7af7fff1bec774539a55ae` (`refs/mpack/community-v2`) |
| Integration state | Explicit merge is in progress; this batch will make the merge commit substantive |
| Publication state | Local only; no remote write and no parent-acceptance record |

## History Strategy and Provenance

The required ordinary trial merge was run first with `--no-commit --no-ff`.
It produced 635 unmerged paths: 426 under `ambari-server`, 163 under
`ambari-web`, 19 under `ambari-common`, 11 under `ambari-funtest`, 7 under
`ambari-agent`, 3 under `ambari-server-spi`, 2 under `contrib`, 2 under
`ambari-admin`, 1 root POM path and 1 metrics path. It also auto-staged 858
paths and left conflict markers in 402 files. Those results are consistent with
629 legacy commits being replayed across eight years of trunk development, and
they do not form a reviewable semantic merge.

That trial was aborted. The current merge uses the pinned community commit as
an explicit second parent while retaining the current trunk tree as the starting
index. This is not the batch result by itself: community topics are being restored
from the exact parent and adapted in reviewed batches. Every retained topic is
listed in its checkpoint, while excluded behavior remains accounted for in the
W0 capability ledger. The resulting merge commit is substantive; it includes
the complete compatible instance-manager topic rather than an empty merge.

The following files were restored directly from the community parent before
adaptation:

- `mpack-instance-manager/pom.xml`
- `mpack-instance-manager/src/main/package/**`
- `mpack-instance-manager/src/main/python/**`
- `mpack-instance-manager/src/packages/**`
- `mpack-instance-manager/src/test/python/**`

The current root `pom.xml` and
`ambari-agent/src/main/package/dependencies.properties` were edited from trunk;
they were not replaced by legacy versions.

## Implemented Behavior

- Adds `mpack-instance-manager` to every root reactor profile that builds the
  Agent and makes each supported Agent package depend on the helper package.
- Retains the community RPM and DEB postinstall/preremove lifecycle. Installation
  creates or updates `/usr/sbin/mpack-instance-manager` only as a symlink and
  refuses to overwrite an unrelated regular path. Removal deletes only the
  expected owned symlink and distinguishes DEB removal from upgrade.
- Reconciles the module with the current `${revision}` parent, managed plugin
  versions, architecture properties, Python 3 runtime dependencies and current
  package version parsing. Retired SCM/build-number configuration is not restored.
- Ports the runtime and CLI to Python 3. The CLI emits machine-readable JSON,
  sends errors to stderr, accepts an isolated `--root`, and treats malformed
  literal input as a typed failure.
- Validates all filesystem-derived identifiers, confines resolved paths and
  symlink targets to the configured root, supports absolute and relative managed
  links, uses atomic version-link replacement and refuses to replace a regular
  file at a managed link path.
- Fixes recursive link discovery, deterministic directory output and cleanup of
  a partially created component directory.
- Adds the descriptor ID required by the current Assembly plugin and excludes
  Python bytecode/cache files from the distributable archive.

The `mpack instance` and `subgroup` labels in this helper are filesystem adapter
metadata. They do not create server-side service identities, alter the confirmed
`(cluster_id, service_name)` authority, assign hosts, authorize REST operations,
or provide a dependency binding protocol.

## Validation Actually Run

| Command/check | Result |
| --- | --- |
| `PYTHONPATH=mpack-instance-manager/src/main/python/instance_manager python3 -m unittest discover -s mpack-instance-manager/src/test/python/instance_manager -p 'test*.py' -v` | Pass: 23 tests, including traversal rejection, relative links, regular-file protection and CLI JSON |
| `python3 -m py_compile ...` for the two runtime and two test entry files | Pass |
| `bash -n` on both RPM and both DEB maintainer scripts | Pass |
| `xmllint --noout pom.xml mpack-instance-manager/pom.xml mpack-instance-manager/src/packages/tarball/all.xml` | Pass |
| Maven 3.8.7 `mvn -Denforcer.skip=true -pl mpack-instance-manager -DassemblyPhase=none test` | Expected tool failure after all 21 then-current tests passed: RAT 0.18 requires Maven 3.9 |
| Checksum-verified isolated Maven 3.9.16 `mvn -pl mpack-instance-manager -DassemblyPhase=none test` | Pass before final link tests: 21 tests, enforcer and RAT passed |
| Maven 3.9.16 `mvn -pl mpack-instance-manager package` | Pre-fix failure: Assembly 3.8 rejected the missing descriptor ID after 23 tests and RAT passed |
| Maven 3.9.16 `mvn -pl mpack-instance-manager clean package` | Pass: 23 tests, RAT, JAR and tar assembly |
| `tar -tzvf mpack-instance-manager/target/mpack-instance-manager-3.1.0.0-SNAPSHOT.tar.gz` | Pass by inspection: only `instance_manager.py` and `mpack-instance-manager.py` below `/usr/lib/mpack-instance-manager`; no `.pyc` or cache directory |
| `git diff --check` on the batch | Pass |

The isolated Maven binary and its SHA-512 file live under
`/jialiangc/bigdata/prjs/.codex-runs/ambari-mpack-v2/tools`; they are not tracked
repository inputs. The downloaded SHA-512 value matched the actual archive.

## Remaining Limits and Next Batch

- RPM and DEB package creation/install/uninstall were not run because RPM build
  tools and an isolated package-install environment are unavailable. The source
  scripts, XML and tar payload were validated.
- No Agent process or live cluster was touched. Agent call-site integration and
  payload semantics require later W1 command/lifecycle batches.
- Instance creation can span several component directories. Component-local
  failures are cleaned, but a later component failure does not yet roll back
  components created earlier in the same command. This is recorded for the R1
  transactional lifecycle work rather than represented as complete recovery.
- The next W1 batch reviews current registration against the community metadata,
  registry and advisor topic, beginning with failure isolation and consumable
  metadata. No generated service-ID or dependency-branch schema is eligible.
