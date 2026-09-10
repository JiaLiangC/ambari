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
import shutil
import socket
import tempfile
import unittest
from unittest.mock import patch

from mpack_authoring.compiler import compile_manifest, payload_lock
from resource_management.libraries.functions.mpack_host import HostError
from resource_management.libraries.functions.mpack_kubernetes import KubernetesDeployment, _private_file


class KubernetesFixture:
  """API/controller result fixture; never contacts a Kubernetes cluster."""
  def __init__(self):
    self.identity = {"server": "https://kubernetes.invalid", "caDigest": "a" * 64}
    self.namespace_uid = "namespace-uid"
    self.native = None
    self.last_uid = None
    self.pods = 0
    self.serial = 0
    self.writes = []
    self.lost = None
    self.conflict = False
    self.linger = False

  def request(self, method, path, body=None, absent=False):
    if method == "GET":
      if path == "/api/v1/namespaces/example":
        return {"metadata": {"uid": self.namespace_uid}}
      if path == "/apis/apps/v1":
        return {"resources": [{"name": "deployments", "namespaced": True, "verbs": ["get", "create", "update", "delete"]}]}
      if "/replicasets?" in path:
        return {"items": ([{"metadata": {"uid": "replicaset-uid", "ownerReferences": [
          {"uid": self.last_uid, "kind": "Deployment", "controller": True}]}}] if self.pods else [])}
      if "/pods?" in path:
        return {"items": [{"metadata": {"uid": "pod-" + str(index), "ownerReferences": [
          {"uid": "replicaset-uid", "kind": "ReplicaSet", "controller": True}]}} for index in range(self.pods)]}
      return copy.deepcopy(self.native)
    if method == "POST":
      self.serial += 1
      self.native = copy.deepcopy(body)
      self.native["metadata"].update(uid="deployment-" + str(self.serial), resourceVersion="1", generation=1)
      self.last_uid = self.native["metadata"]["uid"]
    elif method == "PUT":
      if self.conflict:
        self.conflict = False
        self.native["metadata"]["resourceVersion"] = str(int(self.native["metadata"]["resourceVersion"]) + 1)
      if body["metadata"]["resourceVersion"] != self.native["metadata"]["resourceVersion"] or body["metadata"]["uid"] != self.native["metadata"]["uid"]:
        raise HostError("TARGET_CONFLICT", "Fixture resourceVersion conflict")
      self.native = copy.deepcopy(body)
      self.native["metadata"]["resourceVersion"] = str(int(self.native["metadata"]["resourceVersion"]) + 1)
      self.native["metadata"]["generation"] += 1
    elif method == "DELETE":
      assert body["preconditions"] == {"uid": self.native["metadata"]["uid"], "resourceVersion": self.native["metadata"]["resourceVersion"]}
      assert body["propagationPolicy"] == "Foreground"
      self.native = None
      if not self.linger:
        self.pods = 0
    else:
      raise AssertionError("Unexpected fixture API method")
    self.writes.append(method)
    if self.native is not None:
      self.pods = self.native["spec"]["replicas"]
      self.native["status"] = {"observedGeneration": self.native["metadata"]["generation"],
        "replicas": self.pods, "readyReplicas": self.pods, "availableReplicas": self.pods, "updatedReplicas": self.pods}
    if method == self.lost:
      self.lost = None
      raise HostError("OUTCOME_UNKNOWN", "Fixture API response lost", "UNKNOWN")
    return copy.deepcopy(self.native) or {"kind": "Status"}


class TestMpackKubernetes(unittest.TestCase):
  def setUp(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name)
    self.payload = self.root / "payload"
    shutil.copytree(Path(__file__).resolve().parents[5] / "mpack-authoring/fixtures/http", self.payload)
    path = self.payload / "manifest.json"
    manifest = json.loads(path.read_text())
    service = manifest["spec"]["services"][0]
    service["configurations"][0].pop("template")
    service["configurations"][0]["changeEffect"] = "restart"
    schema = json.loads((self.payload / "config.schema.json").read_text())
    schema["properties"].pop("data_dir")
    (self.payload / "config.schema.json").write_text(json.dumps(schema))
    self.profile = service["components"][0]["profiles"][0]
    self.profile.update(adapter="kubernetes.workload/v1", capabilities=sorted(KubernetesDeployment.operations),
      resources={"connectionRef": "example", "namespace": "example", "image": "example/software@sha256:" + "b" * 64,
        "runAsUserId": 1000, "replicas": 1, "command": {"environment": {"PORT": {"configRef": "http.port"}, "MESSAGE": {"configRef": "http.message"}}}})
    path.write_text(json.dumps(manifest))
    compiled = compile_manifest(str(path))
    self.descriptor = {"format": "mpack.ambari.apache.org/host-service/v1", "package": {"name": "fixture", "version": "1", "digest": compiled["packageDigest"]},
      "service": compiled["manifest"]["spec"]["services"][0], "artifacts": compiled["artifacts"], "files": payload_lock(compiled, str(self.payload))}
    self.command = {"clusterId": 1, "serviceName": "HTTP_ECHO", "role": "HTTP_ECHO_SERVER", "hostname": socket.gethostname(),
      "taskId": 1, "configurations": {}, "commandParams": {"mpack_content_digest": compiled["packageDigest"],
        "mpack_target_incarnation": "00000000-0000-0000-0000-000000000001"}}
    self.api = KubernetesFixture()

  def deployment(self, action):
    self.command["roleCommand"] = action.upper()
    params = self.command["commandParams"]
    hashes = {name: {key: hashlib.sha256(str(value).encode()).hexdigest() for key, value in fields.items()}
              for name, fields in self.command["configurations"].items()}
    self.command["mpackCurrentHost"] = {"hostName": self.command["hostname"], "components": [self.command["role"]], "configurationHashes": hashes}
    params["mpack_task_binding"] = json.dumps({"clusterId": 1, "serviceName": self.command["serviceName"], "role": self.command["role"],
      "packageDigest": params["mpack_content_digest"], "operation": action.upper(), "hostName": self.command["hostname"],
      "targetIncarnation": params["mpack_target_incarnation"], "configTags": {}, "configurationHashes": hashes})
    self.command["serviceLevelParams"] = {key: params[key] for key in ("mpack_content_digest", "mpack_target_incarnation")}
    return KubernetesDeployment(self.descriptor, self.payload, self.command, root=self.root / "deployments",
      units=self.root / "units", runtime_root=self.root / "runtime", connection=self.api)

  def apply(self, action):
    deployment = self.deployment(action)
    return deployment.apply(deployment.plan(action))

  def test_stopped_install_configure_and_rollout_have_no_host_process_semantics(self):
    installed = self.apply("install")
    self.assertEqual(0, installed["observation"]["replicas"])
    self.assertNotIn("pid", installed["observation"])
    self.command["taskId"] = 2
    self.assertTrue(self.apply("start")["observation"]["ready"])
    self.command["configurations"] = {"http": {"message": "changed"}}
    self.command["taskId"] = 3
    with self.assertRaisesRegex(HostError, "Stop the Kubernetes"):
      self.apply("configure")
    self.command["taskId"] = 4
    self.apply("stop")
    self.command["taskId"] = 5
    self.apply("configure")
    env = self.api.native["spec"]["template"]["spec"]["containers"][0]["env"]
    self.assertIn({"name": "MESSAGE", "value": "changed"}, env)
    self.command["taskId"] = 6
    self.assertTrue(self.apply("start")["observation"]["ready"])
    self.command["taskId"] = 7
    self.assertFalse(self.apply("uninstall")["observation"]["exists"])
    self.command["taskId"] = 8
    self.assertTrue(self.apply("purge")["purged"])
    self.assertFalse((self.root / "units").exists())

  def test_lost_create_and_scale_responses_reconcile_existing_intent(self):
    self.api.lost = "POST"
    with self.assertRaises(HostError):
      self.apply("install")
    self.command["taskId"] = 2
    self.apply("install")
    self.assertEqual(1, self.api.writes.count("POST"))
    self.command["taskId"] = 3
    self.api.lost = "PUT"
    with self.assertRaises(HostError):
      self.apply("start")
    count = len(self.api.writes)
    self.command["taskId"] = 4
    self.assertTrue(self.apply("start")["recovered"])
    self.assertEqual(count, len(self.api.writes))

  def test_namespace_and_native_uid_replacement_are_rejected(self):
    self.apply("install")
    self.command["taskId"] = 2
    self.api.namespace_uid = "other-namespace"
    with self.assertRaisesRegex(HostError, "namespace identity"):
      self.apply("uninstall")
    self.api.namespace_uid = "namespace-uid"
    self.api.native["metadata"]["uid"] = "foreign-deployment"
    with self.assertRaisesRegex(HostError, "UID"):
      self.apply("start")
    self.assertEqual(["POST"], self.api.writes)

  def test_namespace_recreation_after_first_plan_is_stale_before_creation(self):
    deployment = self.deployment("install")
    plan = deployment.plan("install")
    self.api.namespace_uid = "replacement-before-install"
    with self.assertRaisesRegex(HostError, "Native state changed"):
      deployment.apply(plan)
    self.assertEqual([], self.api.writes)

  def test_concurrent_resource_version_change_is_not_overwritten(self):
    self.apply("install")
    self.command["taskId"] = 2
    self.api.conflict = True
    with self.assertRaisesRegex(HostError, "resourceVersion"):
      self.apply("start")
    self.assertEqual(0, self.api.native["spec"]["replicas"])
    self.assertEqual(["POST"], self.api.writes)

  def test_delete_waits_for_terminating_children_and_recovers_without_another_delete(self):
    self.apply("start")
    self.command["taskId"] = 2
    self.api.linger = True
    with patch("resource_management.libraries.functions.mpack_kubernetes.time.monotonic", side_effect=[0, 121]):
      with self.assertRaisesRegex(HostError, "postcondition"):
        self.apply("uninstall")
    self.assertIsNone(self.api.native)
    self.assertEqual("UNKNOWN", self.deployment("uninstall")._receipt()["state"])
    self.api.pods = 0
    self.command["taskId"] = 3
    self.assertEqual(0, self.apply("uninstall")["observation"]["remainingPods"])
    self.assertEqual(1, self.api.writes.count("DELETE"))

  def test_connection_material_requires_private_non_symlink_files(self):
    path = self.root / "connection.json"
    path.write_text("{}")
    path.chmod(0o600)
    self.assertEqual(b"{}", _private_file(path))
    path.chmod(0o644)
    with self.assertRaises(HostError):
      _private_file(path)
    path.chmod(0o600)
    link = self.root / "link.json"
    link.symlink_to(path)
    with self.assertRaises(HostError):
      _private_file(link)


if __name__ == "__main__":
  unittest.main()
