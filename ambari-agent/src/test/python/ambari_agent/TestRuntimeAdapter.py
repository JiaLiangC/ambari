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

import threading
import unittest
from ambari_agent.RuntimeAdapter import RuntimeAdapterExecutor


class TestRuntimeAdapter(unittest.TestCase):
  def test_reserved_parameters_cannot_execute_or_echo_commands(self):
    executor = RuntimeAdapterExecutor()
    for key in ("runtime_context", "runtime_profile", "runtime_plan",
                "runtime_operation", "runtime_operation_id", "runtime_idempotency_key"):
      command = {"taskId": 1, "commandParams": {key: "untrusted-payload"}}
      result = executor.execute(command, threading.Event())
      self.assertEqual(1, result["exitcode"])
      self.assertFalse(result["structuredOut"]["retryable"])
      self.assertNotIn("untrusted-payload", str(result))

  def test_legacy_service_command_uses_existing_orchestrator(self):
    self.assertIsNone(RuntimeAdapterExecutor().execute(
        {"commandParams": {"script": "service.py", "command_timeout": "600"}}))
