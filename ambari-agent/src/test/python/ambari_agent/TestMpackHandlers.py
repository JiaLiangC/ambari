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

from resource_management.libraries.functions.mpack_host import HostError
from resource_management.libraries.functions.mpack_handler import PackageHandler


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
    result = PackageHandler(self.deployment, {"artifactRef": "handler"}, self.user).call("verify", "observe", "key", {})
    self.assertEqual("SUCCEEDED", result["result"])
    self.assertEqual("key", result["operationKey"])

  def test_root_and_modified_source_are_rejected_before_execution(self):
    with self.assertRaisesRegex(HostError, "root"):
      PackageHandler(self.deployment, {"artifactRef": "handler"}, "root")
    self.source.write_text("raise RuntimeError('never run')")
    with self.assertRaisesRegex(HostError, "artifact"):
      PackageHandler(self.deployment, {"artifactRef": "handler"}, self.user)
