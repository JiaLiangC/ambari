#!/usr/bin/env python3
"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

"""Reject the retired parameter-driven runtime execution protocol.

An ordinary service-check permission does not authorize arbitrary adapter argv.
Keep this guard for queued commands from older servers. A future typed producer
must bind verified package content and the existing service/task authority before
any native runtime dispatch can be enabled.
"""


class RuntimeAdapterExecutor:
  """Compatibility guard; never executes native commands."""

  def execute(self, command, cancel_event=None):
    params = command.get("commandParams") or {}
    if not any(str(key).startswith("runtime_") for key in params):
      return None
    message = "Parameter-driven runtime execution is unsupported"
    payload = {"state": "FAILED", "code": "CAPABILITY_UNSUPPORTED",
               "message": message, "retryable": False}
    return {"exitcode": 1, "stdout": "", "stderr": message,
            "structuredOut": payload, "runtimeState": "FAILED"}
