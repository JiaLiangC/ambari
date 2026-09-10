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
import os
import socket
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from mpack_authoring.compiler import compile_manifest, payload_lock
from resource_management.libraries.functions.mpack_host import HostDeployment, HostError, NativeRunner


class SystemdFixture:
  """Explicit native-output fixture; never invokes systemd or installs packages."""
  def __init__(self, units):
    self.units = units
    self.active = False
    self.invocation = 0
    self.mutations = []
    self.lose_response = False

  def run(self, argv, cancel=None, timeout=30):
    if argv[1] == "--version":
      return 0, "systemd 252 (fixture)\n"
    if argv[1] == "show":
      unit = argv[2]
      loaded = (self.units / unit).exists()
      return 0, "\n".join(["Id=" + unit, "LoadState=" + ("loaded" if loaded else "not-found"),
        "ActiveState=" + ("active" if self.active else "inactive"), "SubState=running",
        "MainPID=" + ("1234" if self.active else "0"), "FragmentPath=" + str(self.units / unit),
        "InvocationID=" + (str(self.invocation) if self.active else ""), "Job=0 /"])
    self.mutations.append(argv[1])
    if argv[1] in ("start", "restart"):
      self.active = True
      self.invocation += 1
      if self.lose_response:
        self.lose_response = False
        raise HostError("OUTCOME_UNKNOWN", "Fixture lost response after apply", "UNKNOWN")
    elif argv[1] == "stop":
      self.active = False
    return 0, ""


class TestMpackHost(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory()
    self.addCleanup(self.temporary.cleanup)
    self.root = Path(self.temporary.name)
    self.units = self.root / "units"
    self.units.mkdir()
    self.payload = Path(__file__).resolve().parents[5] / "mpack-authoring/fixtures/http"
    compiled = compile_manifest(str(self.payload / "manifest.json"))
    self.descriptor = {"format": "mpack.ambari.apache.org/host-service/v1",
      "package": {"digest": compiled["packageDigest"]},
      "service": copy.deepcopy(compiled["manifest"]["spec"]["services"][0]),
      "artifacts": compiled["artifacts"], "files": payload_lock(compiled, str(self.payload))}
    # Native health is an explicit process-state fixture here, not a live HTTP claim.
    self.descriptor["service"]["components"][0]["profiles"][0]["health"] = {"kind": "process"}
    self.command = {"clusterId": 1, "serviceName": "HTTP_ECHO", "role": "HTTP_ECHO_SERVER",
      "taskId": 1, "roleCommand": "START", "configurations": {}, "commandParams": {
        "mpack_content_digest": compiled["packageDigest"],
        "mpack_target_incarnation": "00000000-0000-0000-0000-000000000001"}}
    self.native = SystemdFixture(self.units)
    # Most lifecycle tests use a native fixture, including listener availability.
    self.port_guard = patch.object(HostDeployment, "_check_ports")
    self.port_guard.start()
    self.addCleanup(self.port_guard.stop)

  def deployment(self, command=None):
    if command is None:
      self.command["hostname"] = socket.gethostname()
      self.command["mpackCurrentHost"] = {"hostName": socket.gethostname(), "components": [self.command["role"]]}
      params = self.command["commandParams"]
      binding = {"clusterId": self.command["clusterId"], "serviceName": self.command["serviceName"],
        "role": self.command["role"], "packageDigest": params["mpack_content_digest"],
        "operation": self.command["roleCommand"], "hostName": self.command["hostname"],
        "targetIncarnation": params["mpack_target_incarnation"],
        "configTags": self.command.get("configurationTags", {}),
        "configurationHashes": {name: {key: hashlib.sha256(str(value).encode()).hexdigest()
          for key, value in values.items()} for name, values in self.command["configurations"].items()}}
      self.command["mpackCurrentHost"]["configurationHashes"] = copy.deepcopy(binding["configurationHashes"])
      params["mpack_task_binding"] = json.dumps(binding)
      self.command["serviceLevelParams"] = {name: params[name] for name in
        ("mpack_content_digest", "mpack_target_incarnation")}
    def provision(resources, directories, root):
      for directory in directories.values():
        directory.mkdir(parents=True, exist_ok=True)
    return HostDeployment(self.descriptor, self.payload, command or self.command,
      root=self.root / "deployments", units=self.units, runner=self.native, provision=provision)

  def apply(self, action):
    self.command["roleCommand"] = action.upper()
    deployment = self.deployment()
    return deployment.apply(deployment.plan(action))

  def test_apply_replay_stop_and_late_task(self):
    self.assertEqual("SUCCEEDED", self.apply("start")["state"])
    self.assertTrue(self.apply("start")["replayed"])
    self.assertEqual(1, self.native.mutations.count("start"))
    self.command["taskId"] = 2
    self.assertEqual("inactive", self.apply("stop")["observation"]["state"])
    self.assertTrue((self.deployment().root / "resources/data").exists())
    self.command["taskId"] = 1
    with self.assertRaisesRegex(HostError, "superseded"):
      self.apply("start")
    self.assertFalse(self.native.active)

  def test_occupied_listener_fails_before_provision_or_publication(self):
    self.port_guard.stop()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
      listener.bind(("127.0.0.1", 0))
      listener.listen()
      self.command["configurations"] = {"http": {"port": str(listener.getsockname()[1])}}
      deployment = self.deployment()
      with patch.object(deployment, "provision") as provision:
        with self.assertRaisesRegex(HostError, "listener is unavailable"):
          deployment.apply(deployment.plan("start"))
        provision.assert_not_called()
      self.assertFalse(deployment.unit_path.exists())
      self.assertFalse((deployment.root / "receipt.json").exists())
    self.assertEqual([], self.native.mutations)

  def test_local_health_does_not_follow_redirects(self):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    requests = []
    class RedirectHandler(BaseHTTPRequestHandler):
      def do_GET(self):
        requests.append(self.path)
        self.send_response(302)
        self.send_header("Location", "/outside-declared-probe")
        self.end_headers()
      def log_message(self, *args):
        pass
    server = HTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
      deployment = self.deployment()
      deployment.profile["health"] = {"kind": "http", "portRef": "http.port", "path": "/health"}
      self.assertFalse(deployment._healthy({"http": {"port": server.server_port}}))
      self.assertEqual(["/health"], requests)
    finally:
      server.shutdown()
      thread.join(2)
      server.server_close()

  def test_interrupted_start_without_surviving_evidence_is_not_reexecuted(self):
    self.native.lose_response = True
    with self.assertRaises(HostError):
      self.apply("start")
    self.native.active = False
    self.command["taskId"] = 2
    mutations = list(self.native.mutations)
    with self.assertRaisesRegex(HostError, "no surviving invocation"):
      self.apply("start")
    self.assertEqual(mutations, self.native.mutations)
    self.command["taskId"] = 3
    self.apply("stop")
    self.command["taskId"] = 4
    self.apply("start")
    self.assertEqual(2, self.native.mutations.count("start"))

  def test_pending_native_job_and_observe_cannot_enter_mutation(self):
    deployment = self.deployment()
    native_run = self.native.run
    def pending(argv, *args, **kwargs):
      code, output = native_run(argv, *args, **kwargs)
      return code, output.replace("Job=0 /", "Job=42 /org/freedesktop/systemd1/job/42")
    with patch.object(self.native, "run", side_effect=pending):
      with self.assertRaisesRegex(HostError, "job is still pending"):
        deployment.apply(deployment.plan("start"))
    with self.assertRaises(HostError):
      deployment.plan("observe")
    self.assertEqual([], self.native.mutations)

  def test_changed_configuration_is_published_and_restarted(self):
    first = self.apply("start")
    self.command["taskId"] = 2
    self.command["configurations"] = {"http": {"port": "19000"}}
    second = self.apply("start")
    self.assertNotEqual(first["runningConfigGeneration"], second["runningConfigGeneration"])
    self.assertEqual(second["publishedConfigGeneration"], second["runningConfigGeneration"])
    self.assertEqual(1, self.native.mutations.count("restart"))
    self.assertIn("--port", self.deployment().unit_path.read_text())
    self.assertIn("19000", self.deployment().unit_path.read_text())

  def test_lost_response_recovers_by_invocation_without_second_mutation(self):
    self.native.lose_response = True
    with self.assertRaises(HostError) as result:
      self.apply("start")
    self.assertEqual("UNKNOWN", result.exception.state)
    self.command["taskId"] = 2
    self.assertTrue(self.apply("start")["recovered"])
    self.assertEqual(1, self.native.mutations.count("start"))
    self.assertNotIn("restart", self.native.mutations)

  def test_conflicting_target_stale_plan_and_invalid_config_have_no_effects(self):
    deployment = self.deployment()
    plan = deployment.plan("start")
    self.command["configurations"] = {"http": {"port": "19000"}}
    with self.assertRaises(HostError) as result:
      deployment.apply(plan)
    self.assertEqual("PLAN_STALE", result.exception.code)
    self.command["configurations"] = {"http": {"port": "70000"}}
    with self.assertRaises(HostError):
      self.apply("start")
    self.assertEqual([], self.native.mutations)
    self.command["configurations"] = {}
    deployment.unit_path.write_text("foreign unit")
    with self.assertRaises(HostError) as result:
      deployment.plan("start")
    self.assertEqual("TARGET_CONFLICT", result.exception.code)

  def test_recreated_service_uses_new_target_without_adopting_old_data(self):
    original = self.deployment()
    self.apply("install")
    self.command["commandParams"]["mpack_target_incarnation"] = "00000000-0000-0000-0000-000000000002"
    replacement = self.deployment()
    self.assertNotEqual(original.root, replacement.root)
    self.assertTrue((original.root / "resources/data").exists())
    self.assertFalse(replacement.unit_path.exists())

  def test_native_runner_drains_large_output_and_cancels(self):
    runner = NativeRunner()
    code, output = runner.run([sys.executable, "-c",
      "import sys; sys.stdout.write('x'*200000); sys.stderr.write('y'*200000)"], timeout=5)
    self.assertEqual(0, code)
    self.assertEqual(65536, len(output))
    with self.assertRaises(HostError) as result:
      runner.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.2)
    self.assertEqual("UNKNOWN", result.exception.state)
    event = threading.Event()
    event.set()
    with self.assertRaises(HostError):
      runner.run([sys.executable, "-c", "raise AssertionError('must not run')"], cancel=event)

  def test_service_metadata_resolves_status_and_check_target(self):
    deployment = self.deployment()
    command = copy.deepcopy(self.command)
    command["serviceLevelParams"] = command.pop("commandParams")
    command["role"] = "HTTP_ECHO_SERVICE_CHECK"
    command["localComponents"] = ["HTTP_ECHO_SERVER"]
    checked = self.deployment(command)
    self.assertEqual(deployment.identity, checked.identity)
    checked.validate_inputs()
    command["localComponents"] = []
    with self.assertRaises(HostError) as result:
      self.deployment(command)
    self.assertEqual("TARGET_CONFLICT", result.exception.code)

  def test_config_tags_are_bound_to_task_intent(self):
    self.command["configurationTags"] = {"http": {"tag": "version1"}}
    self.apply("start")
    self.command["configurationTags"] = {"http": {"tag": "version2"}}
    with self.assertRaises(HostError) as result:
      self.apply("start")
    self.assertEqual("TARGET_CONFLICT", result.exception.code)

  def test_old_task_cannot_follow_recreated_service_metadata(self):
    self.deployment()
    old = copy.deepcopy(self.command)
    old["serviceLevelParams"]["mpack_target_incarnation"] = "00000000-0000-0000-0000-000000000002"
    deployment = self.deployment(old)
    with self.assertRaises(HostError) as result:
      deployment.apply(deployment.plan("start"))
    self.assertEqual("PLAN_STALE", result.exception.code)
    self.assertEqual([], self.native.mutations)
    old["serviceLevelParams"]["mpack_target_incarnation"] = old["commandParams"]["mpack_target_incarnation"]
    del old["commandParams"]["mpack_task_binding"]
    deployment = self.deployment(old)
    with self.assertRaises(HostError):
      deployment.apply(deployment.plan("start"))
    self.assertEqual([], self.native.mutations)

  def test_staging_failure_preserves_published_and_running_config(self):
    self.apply("start")
    deployment = self.deployment()
    previous = (deployment.root / "config/current").resolve()
    unit = deployment.unit_path.read_bytes()
    mutations = list(self.native.mutations)
    self.command["taskId"] = 2
    self.command["configurations"] = {"http": {"port": "19000"}}
    from resource_management.libraries.functions import mpack_host
    original = mpack_host._atomic
    def fail_config(path, data, mode=0o600):
      if str(path).endswith("http.conf"):
        raise OSError("fixture staging failure")
      return original(path, data, mode)
    with patch.object(mpack_host, "_atomic", side_effect=fail_config):
      with self.assertRaises(HostError) as result:
        self.apply("start")
    self.assertEqual("UNKNOWN", result.exception.state)
    self.assertEqual(previous, (deployment.root / "config/current").resolve())
    self.assertEqual(unit, deployment.unit_path.read_bytes())
    self.assertEqual(mutations, self.native.mutations)
    self.assertTrue(self.native.active)

  def test_cancel_verification_keeps_unknown_and_child_group_cannot_escape(self):
    deployment = self.deployment()
    deployment.cancel = threading.Event()
    deployment.cancel.set()
    with self.assertRaises(HostError) as result:
      deployment.verify("start", deployment.validate_inputs())
    self.assertEqual("UNKNOWN", result.exception.state)
    marker = self.root / "escaped-child"
    child = "import time; from pathlib import Path; time.sleep(0.5); Path({!r}).write_text('escaped')".format(str(marker))
    parent = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c', {!r}]); time.sleep(30)".format(child)
    with self.assertRaises(HostError):
      NativeRunner().run([sys.executable, "-c", parent], timeout=0.15)
    time.sleep(0.7)
    self.assertFalse(marker.exists())

  def test_two_cluster_targets_are_distinct_and_occupied_unit_is_rejected(self):
    first = self.deployment()
    second_command = copy.deepcopy(self.command)
    second_command["clusterId"] = 2
    second = self.deployment(second_command)
    self.assertNotEqual(first.root, second.root)
    self.assertNotEqual(first.unit, second.unit)
    second.unit_path.write_text("foreign unit")
    with self.assertRaises(HostError) as result:
      second.plan("start")
    self.assertEqual("TARGET_CONFLICT", result.exception.code)

  def test_redis_uses_same_host_driver_and_retains_data_on_stop(self):
    self.payload = self.payload.parent / "redis"
    compiled = compile_manifest(str(self.payload / "manifest.json"))
    self.descriptor = {"format": "mpack.ambari.apache.org/host-service/v1",
      "package": {"digest": compiled["packageDigest"]},
      "service": copy.deepcopy(compiled["manifest"]["spec"]["services"][0]),
      "artifacts": compiled["artifacts"], "files": payload_lock(compiled, str(self.payload))}
    self.descriptor["service"]["components"][0]["profiles"][0]["health"] = {"kind": "process"}
    self.command.update(serviceName="REDIS", role="REDIS_SERVER")
    self.command["commandParams"]["mpack_content_digest"] = compiled["packageDigest"]
    with patch("resource_management.libraries.functions.mpack_host.shutil.which", return_value=sys.executable):
      self.assertEqual("SUCCEEDED", self.apply("start")["state"])
      deployment = self.deployment()
      self.assertIn("redis.conf", deployment.unit_path.read_text())
      retained = deployment.root / "resources/data/fixture.rdb"
      retained.write_text("retained fixture")
      self.command["taskId"] = 2
      self.assertEqual("SUCCEEDED", self.apply("stop")["state"])
      self.assertEqual("retained fixture", retained.read_text())

  def test_explicit_restart_is_one_task_and_preserves_unknown_recovery_intent(self):
    self.apply("start")
    self.command["taskId"] = 2
    self.native.lose_response = True
    with self.assertRaises(HostError):
      self.apply("restart")
    self.command["taskId"] = 3
    self.assertTrue(self.apply("restart")["recovered"])
    self.assertEqual(1, self.native.mutations.count("restart"))
    self.assertNotIn("stop", self.native.mutations)

  def test_host_authoring_capabilities_match_the_executable_contract(self):
    from mpack_authoring.profiles import profile_capabilities
    from resource_management.libraries.functions.mpack_host import HOST_OPERATIONS
    self.assertEqual(HOST_OPERATIONS, profile_capabilities("host.systemd/v1"))

  def test_actual_java_task_payload_consumes_the_shared_host_driver(self):
    fixture = os.environ.get("MPACK_TASK_FIXTURE")
    if not fixture:
      self.skipTest("Requires the Java producer fixture generated in consolidated validation")
    envelope = json.loads(Path(fixture).read_text())
    command = envelope["command"]
    command["serviceLevelParams"] = envelope["serviceMetadata"]
    command["mpackCurrentHost"] = {"hostName": command["hostname"], "components": [command["role"]],
      "configurationHashes": json.loads(command["commandParams"]["mpack_task_binding"])["configurationHashes"]}
    deployment = self.deployment(command)
    self.assertEqual("SUCCEEDED", deployment.apply(deployment.plan("start"))["state"])
    self.assertTrue(deployment.apply(deployment.plan("start"))["replayed"])
    self.assertEqual(1, self.native.mutations.count("start"))

  def test_task_rejects_removed_host_assignment_and_changed_action(self):
    self.deployment()
    command = copy.deepcopy(self.command)
    command["mpackCurrentHost"]["components"] = []
    deployment = self.deployment(command)
    with self.assertRaises(HostError) as result:
      deployment.apply(deployment.plan("start"))
    self.assertEqual("TARGET_CONFLICT", result.exception.code)
    command["mpackCurrentHost"]["components"] = [command["role"]]
    deployment = self.deployment(command)
    with self.assertRaises(HostError):
      deployment.apply(deployment.plan("stop"))
    self.assertEqual([], self.native.mutations)

  def test_stop_is_not_blocked_by_invalid_desired_configuration(self):
    self.apply("start")
    self.command["taskId"] = 2
    self.command["configurations"] = {"http": {"port": "invalid"}}
    self.assertEqual("SUCCEEDED", self.apply("stop")["state"])
    self.assertFalse(self.native.active)

  def test_changed_current_config_cannot_reinterpret_an_old_task(self):
    self.deployment()
    command = copy.deepcopy(self.command)
    command["mpackCurrentHost"]["configurationHashes"] = {"http": {"port": "changed"}}
    deployment = self.deployment(command)
    with self.assertRaises(HostError) as result:
      deployment.apply(deployment.plan("start"))
    self.assertEqual("PLAN_STALE", result.exception.code)
    self.assertEqual([], self.native.mutations)

  def test_status_health_uses_running_config_after_desired_config_changes(self):
    profile = self.descriptor["service"]["components"][0]["profiles"][0]
    profile["health"] = {"kind": "tcp", "portRef": "http.port"}
    with patch("resource_management.libraries.functions.mpack_host.socket.create_connection") as connect:
      self.apply("start")
      self.command["configurations"] = {"http": {"port": "19000"}}
      deployment = self.deployment()
      self.assertTrue(deployment._healthy())
      self.assertEqual(("127.0.0.1", 18080), connect.call_args.args[0])

  def test_stop_cannot_turn_a_changed_package_into_an_implicit_upgrade(self):
    self.apply("start")
    self.descriptor["package"]["digest"] = "b" * 64
    self.command["commandParams"]["mpack_content_digest"] = "b" * 64
    self.command["taskId"] = 2
    self.assertEqual("SUCCEEDED", self.apply("stop")["state"])
    self.command["taskId"] = 3
    with self.assertRaises(HostError) as result:
      self.apply("start")
    self.assertEqual("CAPABILITY_UNSUPPORTED", result.exception.code)

  def test_zero_exit_without_readiness_is_not_success(self):
    deployment = self.deployment()
    with patch("resource_management.libraries.functions.mpack_host.time.monotonic", side_effect=[0, 31]):
      with self.assertRaises(HostError) as result:
        deployment.verify("start", deployment.validate_inputs())
    self.assertEqual("UNKNOWN", result.exception.state)

  def test_host_user_group_conflict_precedes_resource_mutation(self):
    from types import SimpleNamespace
    from resource_management.libraries.script import manifest_service
    service = object.__new__(manifest_service.ManifestService)
    with patch.object(manifest_service.pwd, "getpwnam", return_value=SimpleNamespace(pw_gid=10)), \
         patch.object(manifest_service.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=20)), \
         patch.object(manifest_service, "Package") as package, \
         patch.object(manifest_service, "User") as user:
      with self.assertRaises(HostError) as result:
        service._provision({"packages": ["redis"], "users": [{"name": "redis", "group": "other"}]}, {}, self.root)
      self.assertEqual("TARGET_CONFLICT", result.exception.code)
      package.assert_not_called()
      user.assert_not_called()
