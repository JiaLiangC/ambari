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

# Disposable Server-Agent acceptance

Run `acceptance.py` only against an explicitly disposable cluster after consolidated
local tests pass. It imports a trusted .mpack twice, creates/uses the declared service,
assigns its components to the specified existing Agent host, installs/starts/stops,
uninstalls, checks retained-resource evidence and removes the service record. It
leaves the package and retained data available for inspection. It never purges data,
restarts infrastructure or changes another worktree.

Set `AMBARI_USERNAME` and `AMBARI_PASSWORD` through a private process environment.
Use HTTPS for remote endpoints; HTTP is allowed only for loopback. Provision package
publisher trust, prerequisites and an assigned host before running:

```sh
python3 dev-support/mpack/acceptance.py --api-url https://ambari.example \
  --cluster disposable --host agent.example --package /private/example.mpack \
  --service HTTP_ECHO --allow-disposable-cluster-changes
```

No deployment has been performed merely by adding this script. An HTTP failure or
lost response stops execution; inspect the reported existing request ID and Ambari
resource evidence before resuming manually. Missing request identity is not success.

For native fault acceptance, repeat in separately reset disposable environments:

| Fault | Operator action | Required evidence |
| --- | --- | --- |
| Agent restart after publication | Restart that Agent while its tracked task is pending | Same incarnation/package, observed native ID, no duplicate target |
| Lost runtime response | Interrupt response transport after the native mutation | UNKNOWN followed by observation of the saved intent, no blind data-operation apply |
| Server restart | Restart Server after request/task persistence | Existing request/task identity and retained-resource state remain queryable |
| Source outage | Withdraw artifact source during a new import | No incomplete available catalog entry; retry identical bytes safely |
| Native replacement | Replace a disposable target or namespace with another UID | TARGET_CONFLICT; no mutation of the replacement |
| Data operation response loss | Use a disposable package handler with fault injection | Retry executes verify only for the original operation key |

These actions are manual environment acceptance, not automatically performed by the
harness. Production DB fresh/upgrade acceptance must cover the actual database engine
and existing data; H2 fixtures cannot substitute for it. Preserve sanitized request
IDs, native IDs, operation outcomes and physical retained-data checks as evidence.
