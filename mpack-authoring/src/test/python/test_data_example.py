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

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


class DataExampleTest(unittest.TestCase):
  def test_backup_migration_restore_verify_durable_output_without_reapplying(self):
    path = Path(__file__).resolve().parents[3] / "fixtures/http/data-handler.py"
    spec = importlib.util.spec_from_file_location("data_example", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory() as root:
      source = Path(root) / "records.json"
      original = b'{"version":1,"records":[{"id":1}]}'
      source.write_bytes(original)
      request = {"directories": {"data": root}, "targetIdentity": "target", "configurations": {"http": {}}, "operationKey": "a" * 64}
      for action, key in (("backup", "a" * 64), ("migrate", "b" * 64), ("restore", "c" * 64)):
        request.update(operation=action, operationKey=key, phase="prepare")
        prepared = module.procedure(request)
        self.assertEqual("READY", prepared["result"])
        request.update(phase="apply", preconditionDigest=prepared["evidenceDigest"])
        module.procedure(request)
        request["phase"] = "verify"
        self.assertEqual("SUCCEEDED", module.procedure(request)["result"])
        self.assertEqual("SUCCEEDED", module.procedure(request)["result"])
        if action == "backup":
          request["configurations"]["http"]["restore_backup"] = key
        elif action == "migrate":
          self.assertEqual(2, json.loads(source.read_bytes())["version"])
      self.assertEqual(original, source.read_bytes())
