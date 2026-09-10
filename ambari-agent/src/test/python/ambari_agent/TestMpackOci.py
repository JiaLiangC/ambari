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
import types
import unittest
from unittest.mock import patch

from mpack_authoring.compiler import compile_manifest, payload_lock
from resource_management.libraries.functions.mpack_host import HostError
from resource_management.libraries.functions.mpack_oci import OciDeployment


class EngineFixture:
  """Explicit CLI response fixture. Does not invoke Docker or Podman."""
  def __init__(self, root):
    self.root = root
    self.native = None
    self.engine_id = "fixture-engine"
    self.image_id = "sha256:" + "a" * 64
    self.sequence = 0
    self.invocation = 0
    self.mutations = []
    self.lost = None
    self.list_failed = False

  def run(self, argv, cancel=None, timeout=30):
    args = argv[3:] if argv[0].endswith("docker") else argv[2:]
    if args[0] == "info":
      if argv[0].endswith("docker"):
        value = {"OSType": "linux", "ID": self.engine_id, "DockerRootDir": str(self.root), "ServerVersion": "fixture"}
      else:
        value = {"host": {"security": {"rootless": False}, "serviceIsRemote": False},
                 "store": {"graphRoot": str(self.root)}, "version": {"Version": "fixture"}}
      return 0, json.dumps(value)
    if args[:2] == ["image", "inspect"]:
      return 0, json.dumps([{"Id": self.image_id, "RepoDigests": [args[2]], "Config": {}}])
    action = args[1]
    if action == "ls":
      if self.list_failed:
        return 1, ""
      selector = args[args.index("--filter") + 1]
      matches = self.native and (selector.startswith("name=") or selector == "id=" + self.native["Id"])
      return 0, self.native["Id"] + "\n" if matches else ""
    if action == "inspect":
      return 0, json.dumps([self.native])
    self.mutations.append(action)
    if action == "create":
      self.sequence += 1
      labels = dict(args[index + 1].split("=", 1) for index, value in enumerate(args) if value == "--label")
      self.native = {"Id": format(self.sequence, "064x"), "Name": "/" + args[args.index("--name") + 1],
        "Image": self.image_id, "Config": {"Labels": labels}, "State": {"Running": False, "Pid": 0}}
    elif action in ("start", "restart"):
      self.invocation += 1
      self.native["State"] = {"Running": True, "Pid": 1234, "StartedAt": str(self.invocation)}
    elif action == "stop":
      self.native["State"] = {"Running": False, "Pid": 0}
    elif action == "rm":
      self.native = None
    else:
      raise AssertionError("Unexpected fixture action")
    if self.lost == action:
      self.lost = None
      raise HostError("OUTCOME_UNKNOWN", "Fixture response lost", "UNKNOWN")
    return 0, ""


class TestMpackOci(unittest.TestCase):
  def setUp(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name)
    self.payload = Path(__file__).resolve().parents[5] / "mpack-authoring/fixtures/http"
    compiled = compile_manifest(str(self.payload / "manifest.json"))
    self.descriptor = {"format": "mpack.ambari.apache.org/host-service/v1",
      "package": {"name": "oci-fixture", "version": "0.1.0", "digest": compiled["packageDigest"]},
      "service": copy.deepcopy(compiled["manifest"]["spec"]["services"][0]),
      "artifacts": compiled["artifacts"], "files": payload_lock(compiled, str(self.payload))}
    self.profile = self.descriptor["service"]["components"][0]["profiles"][0]
    self.profile.update(adapter="oci.container/v1", capabilities=sorted(OciDeployment.operations), health={"kind": "process"},
      resources={"engine": "docker", "image": "localhost/example@sha256:" + "b" * 64, "runAsUser": "http",
        "directories": [{"path": "data", "owner": "http", "persistent": True, "retention": "retain"}],
        "mounts": [{"directoryRef": "data", "containerPath": "/data"}]})
    self.command = {"clusterId": 1, "serviceName": "HTTP_ECHO", "role": "HTTP_ECHO_SERVER",
      "hostname": socket.gethostname(), "taskId": 1, "configurations": {}, "commandParams": {
        "mpack_content_digest": compiled["packageDigest"],
        "mpack_target_incarnation": "00000000-0000-0000-0000-000000000001"}}
    self.native = EngineFixture(self.root)
    account = patch("resource_management.libraries.functions.mpack_oci.pwd.getpwnam",
                    return_value=types.SimpleNamespace(pw_uid=1234, pw_gid=1234))
    account.start()
    self.addCleanup(account.stop)

  def deployment(self, action):
    self.command["roleCommand"] = action.upper()
    params = self.command["commandParams"]
    hashes = {name: {field: hashlib.sha256(str(value).encode()).hexdigest() for field, value in fields.items()}
              for name, fields in self.command["configurations"].items()}
    self.command["mpackCurrentHost"] = {"hostName": self.command["hostname"], "components": [self.command["role"]],
                                       "configurationHashes": hashes}
    params["mpack_task_binding"] = json.dumps({"clusterId": 1, "serviceName": "HTTP_ECHO", "role": self.command["role"],
      "packageDigest": params["mpack_content_digest"], "operation": action.upper(), "hostName": self.command["hostname"],
      "targetIncarnation": params["mpack_target_incarnation"], "configTags": {}, "configurationHashes": hashes})
    self.command["serviceLevelParams"] = {key: params[key] for key in ("mpack_content_digest", "mpack_target_incarnation")}
    def provision(resources, directories, root):
      for directory in directories.values():
        directory.mkdir(parents=True, exist_ok=True)
    return OciDeployment(self.descriptor, self.payload, self.command, root=self.root / "deployments",
      units=self.root / "units", runtime_root=self.root / "runtime", runner=self.native, provision=provision)

  def apply(self, action):
    deployment = self.deployment(action)
    return deployment.apply(deployment.plan(action))

  def test_both_engines_use_native_ids_and_retain_data_until_purge(self):
    for engine in ("docker", "podman"):
      with self.subTest(engine=engine):
        self.profile["resources"]["engine"] = engine
        self.command["commandParams"]["mpack_target_incarnation"] = ("00000000-0000-0000-0000-000000000001"
          if engine == "docker" else "00000000-0000-0000-0000-000000000002")
        self.command["taskId"] = 1
        result = self.apply("install")
        self.assertTrue(result["observation"]["exists"])
        self.assertEqual("inactive", result["observation"]["state"])
        self.assertNotIn("loadState", result["observation"])
        deployment = self.deployment("install")
        data = deployment.directories["data"] / "persistent.txt"
        data.write_text("retained fixture data")
        self.command["taskId"] = 2
        self.assertEqual("active", self.apply("start")["observation"]["state"])
        self.command["taskId"] = 3
        self.assertEqual("inactive", self.apply("stop")["observation"]["state"])
        self.command["taskId"] = 4
        self.assertFalse(self.apply("uninstall")["observation"]["exists"])
        self.assertTrue(data.exists())
        self.command["taskId"] = 5
        self.assertTrue(self.apply("purge")["purged"])
        self.assertFalse(data.exists())
        self.assertFalse((self.root / "units").exists())

  def test_lost_create_and_start_responses_recover_without_repeating_mutation(self):
    for action in ("install", "start"):
      self.native.lost = "create" if action == "install" else "start"
      with self.assertRaises(HostError):
        self.apply(action)
      self.command["taskId"] += 1
      self.assertEqual("SUCCEEDED", self.apply(action)["state"])
      self.command["taskId"] += 1
    self.assertEqual(1, self.native.mutations.count("create"))
    self.assertEqual(1, self.native.mutations.count("start"))

  def test_failed_lookup_never_proves_absence_and_engine_replacement_is_denied(self):
    self.apply("install")
    self.command["taskId"] = 2
    self.native.list_failed = True
    with self.assertRaisesRegex(HostError, "requires observation"):
      self.apply("uninstall")
    self.assertNotIn("rm", self.native.mutations)
    self.native.list_failed = False
    self.native.engine_id = "replacement-engine"
    with self.assertRaisesRegex(HostError, "engine identity"):
      self.apply("uninstall")

  def test_engine_replacement_after_first_plan_is_stale_before_creation(self):
    deployment = self.deployment("install")
    plan = deployment.plan("install")
    self.native.engine_id = "another-engine"
    with self.assertRaisesRegex(HostError, "Native state changed"):
      deployment.apply(plan)
    self.assertEqual([], self.native.mutations)

  def test_foreign_same_name_and_lost_remove_response(self):
    self.apply("install")
    self.command["taskId"] = 2
    self.native.native["Config"]["Labels"]["ambari.mpack.intent"] = "foreign"
    with self.assertRaises(HostError):
      self.apply("start")
    self.native.native["Config"]["Labels"]["ambari.mpack.intent"] = self.deployment("start")._receipt()["creationIntent"]
    self.native.lost = "rm"
    with self.assertRaises(HostError):
      self.apply("uninstall")
    self.command["taskId"] = 3
    self.assertFalse(self.apply("uninstall")["observation"]["exists"])
    self.assertEqual(1, self.native.mutations.count("rm"))

  def test_reinstall_after_explicit_removal_can_change_creation_recipe(self):
    self.apply("install")
    first = self.native.native["Id"]
    self.command["taskId"] = 2
    self.apply("uninstall")
    self.profile["resources"]["limits"] = {"memoryMiB": 1024}
    self.command["taskId"] = 3
    self.apply("install")
    self.assertNotEqual(first, self.native.native["Id"])
    self.assertEqual(2, self.native.mutations.count("create"))

  def test_container_paths_are_injected_and_unsafe_mounts_are_rejected(self):
    deployment = self.deployment("install")
    deployment.provision(deployment.resources, deployment.directories, deployment.root)
    configs = deployment.validate_inputs()
    self.assertEqual("/data", configs["http"]["data_dir"])
    self.profile["resources"]["mounts"][0]["containerPath"] = "/etc"
    with self.assertRaises(HostError):
      self.apply("install")
    self.assertNotIn("create", self.native.mutations)


if __name__ == "__main__":
  unittest.main()
