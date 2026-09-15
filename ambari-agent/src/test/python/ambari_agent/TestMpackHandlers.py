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


import hashlib
import json
import os
from pathlib import Path
import pwd
import tempfile
import types
import unittest
from unittest.mock import patch

import TestMpackHost as host_tests
from resource_management.libraries.functions.mpack_host import HostError
from resource_management.libraries.functions.mpack_handler import PackageHandler


class TestMpackDataOperations(unittest.TestCase):
  def setUp(self):
    self.host = host_tests.TestMpackHost(methodName="runTest")
    self.host.setUp()
    self.addCleanup(self.host.doCleanups)
    profile = self.host.descriptor["service"]["components"][0]["profiles"][0]
    profile["capabilities"].extend(["backup", "migrate", "restore"])
    profile["dataOperations"] = {name: {"artifactRef": "server"} for name in ("backup", "migrate", "restore")}
    self.host.apply("install")
    self.host.command["taskId"] = 2
    self.calls = []
    self.applied = False
    def call(instance, phase, action, key, configs, precondition=None):
      self.calls.append((phase, key))
      if phase == "apply":
        self.applied = True
        raise HostError("OUTCOME_UNKNOWN", "Fixture response lost", "UNKNOWN")
      return {"result": "READY" if phase == "prepare" else "SUCCEEDED" if self.applied else "UNKNOWN",
              "evidenceDigest": "a" * 64}
    constructor = patch.object(PackageHandler, "__init__", return_value=None)
    constructor.start()
    self.addCleanup(constructor.stop)
    invocation = patch.object(PackageHandler, "call", call)
    invocation.start()
    self.addCleanup(invocation.stop)

  def test_lost_data_response_never_reapplies_and_blocks_other_mutations(self):
    with self.assertRaises(HostError):
      self.host.apply("migrate")
    self.host.command["taskId"] = 3
    with self.assertRaisesRegex(HostError, "pending package data"):
      self.host.apply("start")
    result = self.host.apply("migrate")
    self.assertEqual("SUCCEEDED", result["state"])
    self.assertEqual(1, sum(phase == "apply" for phase, key in self.calls))
    self.assertEqual(1, len({key for phase, key in self.calls}))
    self.assertEqual("migrate", result["observation"]["dataOperation"]["operation"])

  def test_unconfirmed_result_and_changed_configuration_cannot_replay_apply(self):
    with self.assertRaises(HostError):
      self.host.apply("restore")
    self.applied = False
    self.host.command["taskId"] = 3
    with self.assertRaises(HostError):
      self.host.apply("restore")
    self.host.command["configurations"] = {"http": {"message": "changed"}}
    with self.assertRaises(HostError):
      self.host.apply("restore")
    self.assertEqual(1, sum(phase == "apply" for phase, key in self.calls))

  def test_interruption_before_prepare_does_not_invent_pending_evidence(self):
    deployment = self.host.deployment()
    receipt = deployment._receipt()
    with self.assertRaisesRegex(HostError, "Fixture response lost"):
      deployment._data_operation("backup", {}, receipt, interrupted=True)
    self.assertEqual(["prepare", "apply"], [phase for phase, key in self.calls])

  def test_interrupted_final_verification_reuses_successful_data_evidence(self):
    deployment = self.host.deployment()
    receipt = deployment._receipt()
    receipt.update(dataAttemptKey="prior-attempt", dataOperation={"operation": "backup", "key": "prior-attempt",
      "configGeneration": deployment._generation({}), "preconditionDigest": "a" * 64, "state": "SUCCEEDED"})
    self.applied = True
    deployment._data_operation("backup", {}, receipt, interrupted=True)
    self.assertEqual([("verify", "prior-attempt")], self.calls)


class TestMpackHandlerProcess(unittest.TestCase):
  def setUp(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name)
    self.root.chmod(0o755)
    self.source = self.root / "handler.py"
    self.source.write_text("import json,os,sys\nr=json.load(sys.stdin)\nassert os.getuid()!=0\n"
      "print(json.dumps(dict(protocol=r['protocol'],phase=r['phase'],operationKey=r['operationKey'],"
      "targetIdentity=r['targetIdentity'],result='SUCCEEDED',evidenceDigest='a'*64)))\n")
    self.source.chmod(0o644)
    account = next((entry for entry in pwd.getpwall() if entry.pw_uid != 0 and entry.pw_name == "nobody"), None)
    if os.geteuid() != 0 or account is None:
      self.skipTest("Requires root and a non-root fixture account for privilege-drop integration")
    self.user = account.pw_name
    self.deployment = types.SimpleNamespace(descriptor={"artifacts": [{"id": "handler", "path": "handler.py",
      "sha256": hashlib.sha256(self.source.read_bytes()).hexdigest()}]}, _source=lambda path: self.source,
      identity={"clusterId": 1, "serviceName": "FIXTURE"}, package_digest="a" * 64, cancel=None, directories={}, resources={})

  def test_real_process_runs_as_non_root_and_returns_only_bound_evidence(self):
    result = PackageHandler(self.deployment, {"artifactRef": "handler"}, self.user).call("verify", "backup", "key", {})
    self.assertEqual("SUCCEEDED", result["result"])
    self.assertEqual("key", result["operationKey"])

  def test_root_and_modified_source_are_rejected_before_execution(self):
    with self.assertRaisesRegex(HostError, "root"):
      PackageHandler(self.deployment, {"artifactRef": "handler"}, "root")
    self.source.write_text("raise RuntimeError('never run')")
    with self.assertRaisesRegex(HostError, "artifact"):
      PackageHandler(self.deployment, {"artifactRef": "handler"}, self.user)
