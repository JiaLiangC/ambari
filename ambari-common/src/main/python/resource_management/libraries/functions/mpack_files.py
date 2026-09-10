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

"""File-only client materialization using the existing host task and receipt flow."""

import os
import time

from resource_management.libraries.functions.mpack_host import HostDeployment, HostError, _hash


class FilesDeployment(HostDeployment):
  runtime_profile = "host.files/v1"
  operations = frozenset({"install", "configure", "uninstall", "purge", "observe"})

  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    if (self.component.get("category") != "CLIENT"
        or set(self.profile["capabilities"]) - self.operations
        or set(self.resources) - {"packages", "users", "directories", "executableArtifacts"}
        or "health" in self.profile):
      raise HostError("CAPABILITY_UNSUPPORTED", "File clients cannot declare process resources or actions")
    if set(self.resources.get("executableArtifacts", [])) - {item["id"] for item in self.descriptor["artifacts"]}:
      raise HostError("SCHEMA_INVALID", "Executable client artifact is undeclared")

  def discover(self):
    if os.name != "posix" or not os.path.isfile("/proc/self/mountinfo"):
      raise HostError("CAPABILITY_UNSUPPORTED", "File client materialization requires a Linux Agent")
    return {"profile": self.runtime_profile, "identity": self.identity, "target": str(self.root),
            "observedAt": time.time(), "validForSeconds": 30,
            "capabilities": sorted(set(self.profile["capabilities"]) & self.operations)}

  def _owned(self, receipt):
    if self.root.is_symlink():
      raise HostError("TARGET_CONFLICT", "Client resource directory is not owned")
    if self.root.exists() and (self.root.stat().st_uid != 0 or self.root.stat().st_mode & 0o022):
      raise HostError("TARGET_CONFLICT", "Client receipt must remain root controlled")

  def _check_ports(self, configs, current, receipt):
    pass  # File publication owns no ports or process invocation.

  def _publish(self, configs, generation, receipt):
    if (self.task_binding or {}).get("secretGenerations"):
      raise HostError("CAPABILITY_UNSUPPORTED", "File clients do not own a live secret-consumer lifetime")
    if self.provision is None:
      raise HostError("CAPABILITY_UNSUPPORTED", "Ambari resource provisioner is required")
    self.provision(self.resources, self.directories, self.root)
    self._stage(configs, generation)
    files = {}
    executable = set(self.resources.get("executableArtifacts", []))
    for item in self.descriptor["artifacts"]:
      relative = "releases/" + self.package_digest + "/" + item["path"]
      path = self.root / relative
      mode = 0o755 if item["id"] in executable else 0o644
      os.chmod(path, mode)
      files[relative] = {"sha256": item["sha256"], "mode": mode}
    for config in self.service.get("configurations", []):
      if config.get("template"):
        relative = "config/g-" + generation + "/" + config["name"] + ".conf"
        files[relative] = {"sha256": _hash((self.root / relative).read_bytes()), "mode": 0o644}
    receipt.update(filesInstalled=True, publishedFiles=files, publishedConfigGeneration=generation)
    self._save(receipt)

  def observe(self):
    receipt = self._receipt()
    self._owned(receipt)
    current = self.root / "config" / "current"
    installed = receipt.get("filesInstalled", False)
    ready = bool(installed)
    if installed:
      expected = self.root / "config" / ("g-" + receipt.get("publishedConfigGeneration", ""))
      ready = current.is_symlink() and current.resolve() == expected
      for relative, evidence in receipt.get("publishedFiles", {}).items():
        path = self.root / relative
        if (path.is_symlink() or self.root not in path.resolve().parents or not path.is_file()
            or path.stat().st_mode & 0o777 != evidence["mode"] or _hash(path.read_bytes()) != evidence["sha256"]):
          ready = False
          break
    return {"kind": self.runtime_profile, "identity": self.identity, "target": str(self.root),
            "state": "installed" if installed else "absent", "ready": ready,
            "publicationAbsent": not current.exists() and not current.is_symlink(),
            "observedAt": time.time(), "publishedConfigGeneration": receipt.get("publishedConfigGeneration")}

  def verify(self, action, configs):
    observation = self.observe()
    if action in ("install", "configure") and observation["ready"]:
      return observation
    if action in ("uninstall", "purge") and observation["state"] == "absent" and observation["publicationAbsent"]:
      if action != "purge" or set(path.name for path in self.root.iterdir()) <= {"receipt.json", "operation.lock"}:
        return observation
    raise HostError("OUTCOME_UNKNOWN", "Client file publication could not be verified", "UNKNOWN")

  def _uninstall(self, configs, receipt):
    receipt["retainedResources"] = self._retained_resources()
    self._save(receipt)
    current = self.root / "config" / "current"
    if current.is_symlink():
      current.unlink()
      directory = os.open(current.parent, os.O_RDONLY | os.O_DIRECTORY)
      try:
        os.fsync(directory)
      finally:
        os.close(directory)
    elif current.exists():
      raise HostError("TARGET_CONFLICT", "Client publication link was replaced")
    receipt["filesInstalled"] = False
    self._save(receipt)
