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
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from mpack_authoring.compiler import compile_manifest, payload_lock
from resource_management.libraries.functions.mpack_external import ExternalDatabaseDeployment
from resource_management.libraries.functions.mpack_handler import PackageHandler
from resource_management.libraries.functions.mpack_host import HostError


class TestMpackExternal(unittest.TestCase):
  def setUp(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name)
    self.payload = Path(__file__).resolve().parents[5] / "mpack-authoring/fixtures/external-postgresql"
    compiled = compile_manifest(str(self.payload / "manifest.json"))
    self.descriptor = {"format": "mpack.ambari.apache.org/host-service/v1", "package": {"name": "observer", "version": "1", "digest": compiled["packageDigest"]},
      "service": copy.deepcopy(compiled["manifest"]["spec"]["services"][0]), "artifacts": compiled["artifacts"], "files": payload_lock(compiled, str(self.payload))}
    self.command = {"clusterId": 1, "serviceName": "EXTERNAL_POSTGRESQL", "role": "POSTGRESQL_OBSERVER", "hostname": socket.gethostname(),
      "taskId": 1, "configurations": {}, "commandParams": {"mpack_content_digest": compiled["packageDigest"],
        "mpack_target_incarnation": "00000000-0000-0000-0000-000000000001"}}
    self.native_identity = "123456789/16384"
    self.available = True
    self.phases = []
    constructor = patch.object(PackageHandler, "__init__", return_value=None)
    constructor.start()
    self.addCleanup(constructor.stop)
    def call(instance, phase, operation, key, configs, precondition=None):
      self.phases.append(phase)
      if not self.available:
        raise HostError("OUTCOME_UNKNOWN", "Fixture provider unavailable", "UNKNOWN")
      return {"result": "SUCCEEDED", "evidenceDigest": "a" * 64, "nativeIdentity": self.native_identity}
    invocation = patch.object(PackageHandler, "call", call)
    invocation.start()
    self.addCleanup(invocation.stop)

  def deployment(self, action):
    self.command["roleCommand"] = action.upper()
    params = self.command["commandParams"]
    self.command["mpackCurrentHost"] = {"hostName": self.command["hostname"], "components": [self.command["role"]], "configurationHashes": {}}
    params["mpack_task_binding"] = json.dumps({"clusterId": 1, "serviceName": self.command["serviceName"], "role": self.command["role"],
      "packageDigest": params["mpack_content_digest"], "operation": action.upper(), "hostName": self.command["hostname"],
      "targetIncarnation": params["mpack_target_incarnation"], "configTags": {}, "configurationHashes": {}})
    self.command["serviceLevelParams"] = {key: params[key] for key in ("mpack_content_digest", "mpack_target_incarnation")}
    return ExternalDatabaseDeployment(self.descriptor, self.payload, self.command, root=self.root / "targets", units=self.root / "units")

  def apply(self, action):
    deployment = self.deployment(action)
    return deployment.apply(deployment.plan(action))

  def test_registration_observes_identity_and_can_unregister_during_provider_loss(self):
    self.assertTrue(self.apply("install")["observation"]["ready"])
    self.assertTrue(self.apply("install")["replayed"])
    self.available = False
    with self.assertRaises(HostError):
      self.deployment("status").observe()
    self.command["taskId"] = 2
    result = self.apply("uninstall")
    self.assertTrue(result["observation"]["registrationAbsent"])
    self.assertEqual("observed", result["observation"]["ownership"])
    self.assertTrue(set(self.phases) <= {"discover", "observe"})
    self.assertFalse((self.root / "units").exists())

  def test_wrong_native_identity_and_remote_mutations_are_rejected(self):
    self.native_identity = "123456789/999"
    with self.assertRaisesRegex(HostError, "native database identity"):
      self.apply("install")
    for action in ("start", "stop", "purge", "upgrade"):
      with self.assertRaises(HostError):
        self.apply(action)
