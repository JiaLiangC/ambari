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

# Remote Interactive Codex Execution Runbook

## Current Authorization

The user explicitly requested a new worktree on `root@10.10.10.2`, an interactive
Codex session in tmux, model `gpt-5.6-sol`, reasoning `xhigh`, and execution of the
documented plan. This supersedes the previous architecture-only pause and Luna
model selection. It does not authorize changes to other ongoing projects or
deployment to existing live clusters.

The parent owns architecture and independent review. This Codex session is the
implementation worker. Do not spawn additional agents or switch the requested
model. Provide readable interactive progress and durable checkpoints.

## Environment

| Item | Value |
| --- | --- |
| Host | root@10.10.10.2 |
| Main repository | /jialiangc/bigdata/prjs/ambari |
| Dedicated integration worktree | /jialiangc/bigdata/prjs/ambari-mpack-v2 |
| Branch | AMBARI-14714-mpack-v2-remote |
| Initial HEAD | 8051a841cf03673260fd025d6b9eeee68d98e0c4 |
| Community task ref | refs/mpack/community-v2 |
| Dependency task ref | refs/mpack/community-dependencies |
| Pinned trunk task ref | refs/mpack/upstream-trunk |
| Read-only multi-cluster snapshot | /jialiangc/bigdata/prjs/.codex-runs/ambari-multicluster/reference-worktree |
| Multi-cluster snapshot HEAD | 8bf556b6ce94b350b3c3b12e15a7882d07bd19f7 |
| Own launch/log artifacts | /jialiangc/bigdata/prjs/.codex-runs/ambari-mpack-v2 |
| tmux session | ambari-mpack-v2 |
| Codex executable | /root/.nvm/versions/node/v22.23.1/bin/codex |
| Verified CLI version at setup | 0.153.4 |
| Publication repository | apache/ambari, refs/heads/trunk, after parent exact-commit review |

On this host `origin` is JiaLiangC/ambari and `apache` is apache/ambari. Verify
actual remote destinations before writes; do not assume origin means upstream.
The task refs were fetched explicitly. Existing worktrees and other tmux sessions
belong to independent work and must remain untouched.

## Start and Continue

Read repository AGENTS.md, then [README.md](README.md) and its documents in order.
Start W0 in [work-orders.md](work-orders.md), write the baseline/capability ledger,
and continue authorized compatible work. Do not ask whether to begin again.

The local Mac integration tree and its 620-conflict snapshot are historical
evidence only. This remote worktree begins clean from trunk. Do not copy raw
conflict markers or the unreviewed POM rewrite from that tree.

Use explicit working directories for mutations. Manual edits use apply_patch;
stage explicit path lists. Preserve current dependency/security changes and
existing service catalogs. No force push, hard reset, blanket conflict preference,
or change to another worktree's branch/index/files.

The runtime session has filesystem/network access needed for Git worktree
metadata and development builds. That is not authorization to operate unrelated
services, read/export credentials, change host security settings, send messages
to third parties, or deploy to live clusters.

## Design Defaults for Execution

Use these conservative defaults within the confirmed architecture:

- Observe/report drift by default; bounded automatic recovery requires explicit
  supported capability/policy. No implicit auto-upgrade.
- Retain persistent data on uninstall/detach unless a separately declared and
  authorized deletion operation applies.
- Preserve supported legacy definitions through translation or a limited legacy
  adapter. Do not remove existing formats or invent silent service-ID migrations.
- Metadata-generated UI first; no implicit arbitrary JavaScript plugin execution.
- Kubernetes platform-level Helm/resources first, with native controller ownership.
- Public schemas, SDK/CLI and structured diagnostics are shared by humans and AI.
- All runtime families are target scope; actual availability is explicit and
  supported by conformance/runtime evidence.

Working alpha manifest/API field details may be refined with tests and recorded
rationale. Do not reinterpret PROPOSED design wording as a requirement to stop
all authorized work. Escalate only material changes to confirmed shared contracts
or an actual dependency that prevents meaningful progress.

## Checkpoints and Parent Review

After each coherent batch write a report under `docs/mpack-v2/reviews/` with the
work-order template. Distinguish tests actually run from planned checks, source
inspection from runtime evidence, and existing failures from new regressions.
Continue independent reversible work while feedback is pending.

At the integration publication boundary, prepare exact candidate commits and
`reviews/M2-candidate.md`, then display `READY_FOR_PARENT_REVIEW` with the SHA and
report path. Do not push until the parent has reviewed that exact candidate.
The worker cannot author its own parent-acceptance record. This is the agreed
technical review gate; user authorization for publication already exists.

Do not invent parent feedback or use a timeout as acceptance. If the parent
requests changes, apply them and update the candidate evidence. If remote trunk
advances, the changed candidate needs affected checks and another parent review.

After publication, create the separate improvement worktree from verified remote
trunk and continue the R1+ topics there. Parent reviews meaningful checkpoints.

## Interactive Session Requirement

Launch the ordinary `codex` TUI, with no `exec` subcommand and no `--json` output.
Use `--no-alt-screen` to keep readable terminal scrollback in tmux. Command-line
model/config overrides pin `gpt-5.6-sol` and `model_reasoning_effort="xhigh"` without
rewriting global user configuration.

The user can attach to the session. Keep it available after a model turn completes;
do not kill other tmux sessions. Record problems and the exact current phase in
the terminal and checkpoint files so the session can be resumed without guessing.

The installation was already authenticated during setup. Do not copy local
credentials to this host or print its auth/config secrets.
