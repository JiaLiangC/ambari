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


import copy
import hashlib
import json
import socket
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mpack_authoring.compiler import compile_manifest, payload_lock
from resource_management.libraries.functions.mpack_files import FilesDeployment
from resource_management.libraries.functions.mpack_host import HostError


class TestMpackFiles(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory()
    self.addCleanup(self.temporary.cleanup)
    self.root = Path(self.temporary.name)
    self.payload = Path(__file__).resolve().parents[5] / "mpack-authoring/fixtures/multi-service"
    compiled = compile_manifest(str(self.payload / "manifest.yaml"))
    self.descriptor = {"format": "mpack.ambari.apache.org/host-service/v1",
      "package": {"name": "multi-service-authoring-example", "version": "0.1.0", "digest": compiled["packageDigest"]},
      "service": copy.deepcopy(compiled["manifest"]["spec"]["services"][0]),
      "artifacts": compiled["artifacts"], "files": payload_lock(compiled, str(self.payload))}
    self.command = {"clusterId": 1, "serviceName": "STATIC_WEB", "role": "STATIC_WEB_CLIENT",
      "hostname": socket.gethostname(), "taskId": 1, "configurations": {}, "commandParams": {
        "mpack_content_digest": compiled["packageDigest"],
        "mpack_target_incarnation": "00000000-0000-0000-0000-000000000001"}}

  def deployment(self, action):
    self.command["roleCommand"] = action.upper()
    parameters = self.command["commandParams"]
    hashes = {name: {field: hashlib.sha256(str(value).encode()).hexdigest() for field, value in fields.items()}
              for name, fields in self.command["configurations"].items()}
    self.command["mpackCurrentHost"] = {"hostName": self.command["hostname"],
      "components": [self.command["role"]], "configurationHashes": hashes}
    binding = {"clusterId": 1, "serviceName": "STATIC_WEB", "role": "STATIC_WEB_CLIENT",
      "packageDigest": parameters["mpack_content_digest"], "operation": action.upper(),
      "hostName": self.command["hostname"], "targetIncarnation": parameters["mpack_target_incarnation"],
      "configTags": {}, "configurationHashes": hashes}
    parameters["mpack_task_binding"] = json.dumps(binding)
    self.command["serviceLevelParams"] = {key: parameters[key] for key in ("mpack_content_digest", "mpack_target_incarnation")}
    def provision(resources, directories, root):
      for directory in directories.values():
        directory.mkdir(parents=True, exist_ok=True)
    return FilesDeployment(self.descriptor, self.payload, self.command, root=self.root / "deployments",
      units=self.root / "units", runtime_root=self.root / "runtime", provision=provision)

  def apply(self, action):
    deployment = self.deployment(action)
    return deployment.apply(deployment.plan(action))

  def test_client_publication_and_retention_have_no_native_process_semantics(self):
    result = self.apply("install")
    self.assertEqual("host.files/v1", result["observation"]["kind"])
    self.assertTrue(result["observation"]["ready"])
    self.assertNotIn("pid", result["observation"])
    self.assertFalse((self.root / "units").exists())
    deployment = self.deployment("install")
    executable = deployment.root / "releases" / deployment.package_digest / "client.py"
    self.assertEqual(0o755, executable.stat().st_mode & 0o777)
    current = deployment.root / "config/current/website.conf"
    self.assertEqual({"port": 18100}, json.loads(current.read_text()))
    self.assertTrue(self.apply("install")["replayed"])
    self.command["taskId"] = 2
    result = self.apply("uninstall")
    self.assertTrue(result["observation"]["publicationAbsent"])
    self.assertTrue(executable.exists())
    self.assertTrue(result["retainedResources"])
    self.command["taskId"] = 3
    self.assertTrue(self.apply("purge")["purged"])
    self.assertFalse(executable.exists())
    self.assertEqual({"receipt.json", "operation.lock"}, {path.name for path in deployment.root.iterdir()})

  def test_tampered_file_cannot_be_reported_as_ready_or_successfully_replayed(self):
    self.apply("install")
    deployment = self.deployment("install")
    executable = deployment.root / "releases" / deployment.package_digest / "client.py"
    executable.write_text("changed client")
    self.assertFalse(deployment.observe()["ready"])
    with self.assertRaises(HostError):
      self.apply("install")
    self.command["taskId"] = 2
    self.assertTrue(self.apply("configure")["observation"]["ready"])

  def test_file_publication_response_loss_can_repeat_staging(self):
    deployment = self.deployment("install")
    stage = deployment._stage
    def lost(configs, generation):
      stage(configs, generation)
      raise HostError("OUTCOME_UNKNOWN", "Client publication interrupted", "UNKNOWN")
    with patch.object(deployment, "_stage", lost):
      with self.assertRaises(HostError):
        deployment.apply(deployment.plan("install"))
    self.assertEqual("UNKNOWN", deployment._receipt()["state"])
    self.command["taskId"] = 2
    self.assertTrue(self.apply("install")["observation"]["ready"])
    self.assertFalse((self.root / "units").exists())

  def test_file_client_rejects_process_actions_and_superseded_tasks(self):
    with self.assertRaises(HostError):
      self.apply("start")
    self.command["taskId"] = 2
    self.apply("install")
    self.command["taskId"] = 1
    with self.assertRaisesRegex(HostError, "newer task"):
      self.apply("configure")


if __name__ == "__main__":
  unittest.main()
