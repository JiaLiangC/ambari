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

"""Observed external database registration; remote lifecycle belongs to its provider."""

import time
from resource_management.libraries.functions.mpack_host import HostDeployment, HostError, _json_hash
from resource_management.libraries.functions.mpack_handler import PackageHandler


class ExternalDatabaseDeployment(HostDeployment):
  runtime_profile = "external.database/v1"
  operations = frozenset({"install", "configure", "uninstall", "observe"})

  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    if (self.component.get("category") != "CLIENT" or set(self.profile["capabilities"]) - self.operations
        or set(self.resources) - {"probe", "runAsUser", "nativeIdentity"}
        or not isinstance(self.resources.get("nativeIdentity"), str)
        or not 1 <= len(self.resources["nativeIdentity"]) <= 256
        or "health" in self.profile
        or any(config.get("template") for config in self.service.get("configurations", []))):
      raise HostError("CAPABILITY_UNSUPPORTED", "External database supports only verified local observation registration")

  def _probe(self, phase):
    configs = self._configurations()
    if (self.task_binding or {}).get("secretGenerations"):
      raise HostError("CAPABILITY_UNSUPPORTED", "External probe credentials must be provisioned outside package configuration")
    handler = PackageHandler(self, self.resources.get("probe", {}), self.resources.get("runAsUser"))
    result = handler.call(phase, "observe", _json_hash({"identity": self.identity, "package": self.package_digest}), configs)
    if result["result"] != "SUCCEEDED" or result.get("nativeIdentity") != self.resources["nativeIdentity"]:
      raise HostError("TARGET_CONFLICT", "External probe did not confirm the declared native database identity")
    return result

  def discover(self):
    result = self._probe("discover")
    return {"profile": self.runtime_profile, "identity": self.identity,
      "target": _json_hash(self.resources["nativeIdentity"]), "evidenceDigest": result["evidenceDigest"],
      "observedAt": time.time(), "validForSeconds": 30, "capabilities": sorted(self.profile["capabilities"])}

  def _owned(self, receipt):
    if self.root.is_symlink() or self.root.exists() and (self.root.stat().st_uid != 0 or self.root.stat().st_mode & 0o022):
      raise HostError("TARGET_CONFLICT", "External registration receipt must remain root controlled")

  def plan(self, action):
    # Deregistration remains possible during provider loss; it mutates no remote data.
    if action == "uninstall":
      self._validate_task_binding(action)
      self.validate_inputs(validate_config=False)
      receipt = self._receipt()
      return {"identity": self.identity, "target": _json_hash(self.resources["nativeIdentity"]), "operation": action,
        "taskId": self.command.get("taskId"), "packageDigest": self.package_digest, "configGeneration": self._generation({}),
        "configTags": self._config_tags(), "expectedReceipt": _json_hash(receipt), "observation": self.observe(),
        "createdAt": time.time(), "expiresAt": time.time() + 30}
    return super().plan(action)

  def observe(self):
    receipt = self._receipt()
    active = receipt.get("registered", False)
    deregister = self.command.get("roleCommand") == "UNINSTALL" or self.command.get("commandParams", {}).get("custom_command") == "UNINSTALL"
    evidence = self._probe("observe") if active and not deregister else None
    return {"kind": self.runtime_profile, "identity": self.identity, "state": "registered" if active else "absent",
      "target": _json_hash(self.resources["nativeIdentity"]), "ready": bool(evidence), "registrationAbsent": not active,
      "ownership": "observed", "evidenceDigest": evidence["evidenceDigest"] if evidence else None, "observedAt": time.time()}

  def _check_ports(self, configs, observation, receipt):
    pass

  def _publish(self, configs, generation, receipt):
    self._probe("observe")
    receipt.update(registered=True, publishedConfigGeneration=generation)
    self._save(receipt)

  def _uninstall(self, configs, receipt):
    receipt.update(registered=False, retainedResources=self._retained_resources())
    self._save(receipt)

  def verify(self, action, configs):
    observation = self.observe()
    if action in ("install", "configure") and observation["ready"] or action == "uninstall" and observation["registrationAbsent"]:
      return observation
    raise HostError("OUTCOME_UNKNOWN", "External registration postcondition is unavailable", "UNKNOWN")
