<!--
   Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements.  See the NOTICE file distributed with
   this work for additional information regarding copyright ownership.
   The ASF licenses this file to you under the Apache License, Version 2.0
   (the "License"); you may not use this file except in compliance with
   the License.  You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
-->

# R1 UI and Observability Checkpoint

The React management-pack flow now has a runtime view at
`/main/admin/mpacks/:mpackId/runtime`. It is reached from a registered mpack
row and retains the existing Ambari mpack ID and authorization scope.

The view consumes additive runtime resources for schema, capabilities,
observations, plans and operations. It presents health, metrics, logs and
alerts through the common observation shape (`kind`, `name`, `state`, value,
timestamp and freshness), and presents operation recovery actions returned by
the server. Unsupported capabilities are disabled; `UNKNOWN` and stale
observations remain visibly uncertain and are never rendered as healthy.

The API adapter is in `ambari-web/latest/src/api/mpackRuntimeApi.ts`. The
normalizers in `ambari-web/latest/src/screens/ManagementPacks/runtimeModel.ts`
accept both direct arrays and Ambari resource envelopes so a server-side
projection can evolve without changing the page. Planning validates JSON
input locally, while apply, cancel and recover remain server-authorized
operations. The page is read-only for users without
`AMBARI.MANAGE_STACK_VERSIONS`.

This batch supplies the generic presentation and client boundary. It does not
claim that the server has implemented a runtime adapter, durable operation
store, telemetry provider or recovery coordinator. Those endpoints return an
explicit load error until their corresponding server contracts are available.
The focused `runtimeModel.test.ts` covers capability, observation, operation,
plan and state normalization; the test is queued for the final validation
batch.
