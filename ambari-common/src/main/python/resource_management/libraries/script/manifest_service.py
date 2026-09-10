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

"""One Script consumer for authenticated declarative host packages."""

import json
import grp
import os
import pwd
from pathlib import Path
import signal
import threading

from resource_management.core.exceptions import Fail, ComponentIsNotRunning
from resource_management.core.resources.accounts import Group, User
from resource_management.core.resources.system import Directory
from resource_management.core.resources.packaging import Package
from resource_management.libraries.functions.mpack_host import HostDeployment, HostError
from resource_management.libraries.script.script import Script


class ManifestService(Script):
  @staticmethod
  def _existing_users(resources):
    existing = set()
    for user in resources.get("users", []):
      try:
        account = pwd.getpwnam(user["name"])
      except KeyError:
        continue
      if user.get("group"):
        try:
          compatible = account.pw_gid == grp.getgrnam(user["group"]).gr_gid
        except KeyError:
          compatible = False
        if not compatible:
          raise HostError("TARGET_CONFLICT", "Existing host user has another primary group")
      existing.add(user["name"])
    return existing

  def _provision(self, resources, directories, root):
    self._existing_users(resources)
    for name in resources.get("packages", []):
      Package(name)
    existing = self._existing_users(resources)
    for user in resources.get("users", []):
      if user["name"] in existing:
        continue
      if user.get("group"):
        Group(user["group"])
      User(user["name"], system=True, **({"gid": user["group"]} if user.get("group") else {}))
    Directory(str(root), create_parents=True, mode=0o755)
    for directory in resources.get("directories", []):
      Directory(str(directories[directory["path"]]), create_parents=True,
                owner=directory["owner"], mode=int(directory.get("mode", "0750"), 8))

  def _deployment(self, cancel=None, command=None):
    root = Path(self.basedir)
    descriptor = json.loads((root / "manifest-service.json").read_text())
    return HostDeployment(descriptor, root / "payload", command or self.get_config(),
                          cancel=cancel, provision=self._provision)

  def _run(self, operation):
    cancel = threading.Event()
    previous = signal.signal(signal.SIGTERM, lambda *_: cancel.set())
    try:
      if self.get_config().get("commandType") != "EXECUTION_COMMAND":
        raise HostError("CAPABILITY_UNSUPPORTED", "Host mutation requires a server-persisted task")
      deployment = self._deployment(cancel)
      plan = deployment.plan(operation)
      result = deployment.apply(plan)
      self.put_structured_out({"mpackOperation": result})
    except HostError as error:
      self.put_structured_out({"mpackOperation": {"state": error.state, "code": error.code,
        "message": str(error), "retryable": False}})
      raise Fail(str(error)) from None
    finally:
      signal.signal(signal.SIGTERM, previous)

  def install(self, env):
    self._run("install")

  def configure(self, env):
    self._run("configure")

  def start(self, env):
    self._run("start")

  def stop(self, env):
    self._run("stop")

  def restart(self, env):
    # One persisted task and one native intent, not stop/start with a reused task ID.
    if self.get_config().get("commandParams", {}).get("upgrade_type"):
      raise Fail("CAPABILITY_UNSUPPORTED: host-service/v1 does not declare upgrade compatibility")
    self._run("restart")

  def status(self, env):
    try:
      deployment = self._deployment()
      deployment.validate_inputs(validate_config=False)
      observation = deployment.observe()
      self.put_structured_out({"mpackObservation": observation})
      if observation["state"] != "active" or int(observation["pid"]) <= 0 or not deployment._healthy():
        raise ComponentIsNotRunning()
    except HostError:
      raise ComponentIsNotRunning() from None

  def service_check(self, env):
    command = dict(self.get_config())
    descriptor = json.loads((Path(self.basedir) / "manifest-service.json").read_text())
    local = set(command.get("localComponents", []))
    observations = {}
    for component in descriptor["service"]["components"]:
      if component["name"] not in local:
        continue
      scoped = dict(command, role=component["name"], roleCommand="STATUS")
      deployment = self._deployment(command=scoped)
      deployment.validate_inputs(validate_config=False)
      observation = deployment.observe()
      if observation["state"] != "active" or int(observation["pid"]) <= 0 or not deployment._healthy():
        raise Fail("Service check failed for a local managed component")
      observations[component["name"]] = observation
    if not observations:
      raise Fail("Service check has no assigned local managed component")
    self.put_structured_out({"mpackObservations": observations})

  def pre_upgrade_restart(self, env, upgrade_type=None):
    raise Fail("CAPABILITY_UNSUPPORTED: host-service/v1 does not declare upgrade compatibility")

  def create_mpack_component_instance(self):
    # This profile materializes one native target per existing ServiceRef/role.
    # The older name-only instance projection cannot represent that scope.
    pass
