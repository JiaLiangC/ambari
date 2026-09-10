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


"""Local rootful OCI materialization through the shared task receipt lifecycle."""

import json
from pathlib import Path
import pwd
import re
import time

from resource_management.libraries.functions.mpack_host import HostDeployment, HostError, _json_hash


class OciDeployment(HostDeployment):
  runtime_profile = "oci.container/v1"
  operations = frozenset({"install", "configure", "start", "stop", "restart", "uninstall", "purge", "observe"})

  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.engine = self.resources.get("engine")
    if (self.engine not in ("docker", "podman") or self.component.get("category") == "CLIENT"
        or set(self.resources) - {"engine", "image", "runAsUser", "users", "directories", "ports", "command", "mounts", "limits"}
        or set(self.profile["capabilities"]) - self.operations
        or not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}", self.resources.get("image", ""))
        or not self.resources.get("runAsUser")):
      raise HostError("CAPABILITY_UNSUPPORTED", "OCI requires an explicit local engine, immutable image and runtime user")
    self.cli = ["/usr/bin/" + self.engine] + (["--host", "unix:///var/run/docker.sock"] if self.engine == "docker" else ["--remote=false"])
    self.container_name = "mpack-" + _json_hash(self.identity)[:40]

  def _run(self, arguments, timeout=10):
    code, output = self.runner.run(self.cli + arguments, self.cancel, timeout)
    if code != 0:
      raise HostError("OUTCOME_UNKNOWN", "Container engine result requires observation", "UNKNOWN")
    return output

  def _json(self, arguments):
    try:
      return json.loads(self._run(arguments))
    except (ValueError, TypeError):
      raise HostError("OUTCOME_UNKNOWN", "Container engine returned invalid observation", "UNKNOWN") from None

  def _engine_identity(self):
    info = self._json(["info", "--format", "{{json .}}" if self.engine == "docker" else "json"])
    try:
      if self.engine == "docker":
        if (info["OSType"] != "linux" or not info["ID"]
            or any("rootless" in option for option in info.get("SecurityOptions", []))):
          raise ValueError()
        root = Path(info["DockerRootDir"])
        engine_id = info["ID"]
        version = info["ServerVersion"]
      else:
        if info["host"]["security"]["rootless"] or info["host"].get("serviceIsRemote"):
          raise ValueError()
        root = Path(info["store"]["graphRoot"])
        engine_id = Path("/etc/machine-id").read_text().strip()
        version = info["version"]["Version"]
      if not root.is_absolute() or root.is_symlink() or not root.is_dir() or not engine_id:
        raise ValueError()
      state = root.stat()
      if state.st_uid != 0 or state.st_mode & 0o022:
        raise ValueError()
      identity = {"engine": self.engine, "id": engine_id, "rootDevice": state.st_dev, "rootInode": state.st_ino}
      receipt = self._receipt()
      if receipt.get("engineIdentity") not in (None, identity):
        raise HostError("TARGET_CONFLICT", "Container engine identity differs from the bound target")
      return identity, version
    except (KeyError, TypeError, ValueError, OSError):
      raise HostError("CAPABILITY_UNSUPPORTED", "Local rootful engine discovery could not be established") from None

  def discover(self):
    identity, version = self._engine_identity()
    return {"profile": self.runtime_profile, "identity": self.identity, "target": self.container_name,
            "engineIdentity": identity, "version": version, "observedAt": time.time(), "validForSeconds": 30,
            "capabilities": sorted(set(self.profile["capabilities"]) & self.operations)}

  def _configurations(self):
    values = super()._configurations()
    mounts = {mount["directoryRef"]: mount["containerPath"] for mount in self.resources.get("mounts", [])}
    for config in self.service.get("configurations", []):
      schema = json.loads(self._source(config["schema"]).read_text())
      for name, field in schema.get("properties", {}).items():
        if field.get("x-sensitive"):
          raise HostError("CAPABILITY_UNSUPPORTED", "OCI does not resolve live secrets")
        if field.get("x-resource"):
          if field["x-resource"] not in mounts:
            raise HostError("SCHEMA_INVALID", "OCI configuration directory requires a declared container mount")
          values[config["name"]][name] = mounts[field["x-resource"]]
    return values

  def _inspect(self, receipt):
    # A successful filtered list proves absence; a failed inspect never does.
    selector = "id=" + receipt["containerId"] if receipt.get("containerId") else "name=" + self.container_name
    ids = self._run(["container", "ls", "--all", "--no-trunc", "--filter", selector, "--format", "{{.ID}}"]).splitlines()
    if len(ids) > 16 or any(not re.fullmatch(r"[a-f0-9]{64}", value) for value in ids):
      raise HostError("TARGET_CONFLICT", "Container lookup exceeded its identity bound")
    for identifier in ids:
      values = self._json(["container", "inspect", identifier])
      if not isinstance(values, list) or len(values) != 1:
        raise HostError("OUTCOME_UNKNOWN", "Container identity could not be inspected", "UNKNOWN")
      value = values[0]
      if not receipt.get("containerId") and value.get("Name", "").lstrip("/") != self.container_name:
        continue
      labels = value.get("Config", {}).get("Labels") or {}
      if (value.get("Id") != identifier or receipt.get("containerId") not in (None, identifier)
          or not receipt.get("creationIntent")
          or labels.get("ambari.mpack.intent") != receipt["creationIntent"]
          or labels.get("ambari.mpack.target") != _json_hash(self.identity)
          or labels.get("ambari.mpack.package") != self.package_digest):
        raise HostError("TARGET_CONFLICT", "Container native identity or creation ownership differs")
      if receipt.get("imageId") and value.get("Image", "").removeprefix("sha256:") != receipt["imageId"].removeprefix("sha256:"):
        raise HostError("TARGET_CONFLICT", "Container image differs from its pinned image")
      return value
    return None

  def _owned(self, receipt):
    if self.root.is_symlink():
      raise HostError("TARGET_CONFLICT", "Container receipt path is not owned")
    self._engine_identity()
    self._inspect(receipt)

  def observe(self):
    receipt = self._receipt()
    identity, _ = self._engine_identity()
    native = self._inspect(receipt)
    state = native.get("State", {}) if native else {}
    running = state.get("Running", False)
    pid = state.get("Pid", 0)
    if type(pid) is not int or pid < 0:
      raise HostError("OUTCOME_UNKNOWN", "Container process identity is unavailable", "UNKNOWN")
    health = state.get("Health", state.get("Healthcheck", {})) or {}
    return {"kind": self.runtime_profile, "identity": self.identity, "target": self.container_name,
      "engineIdentity": identity, "nativeId": native["Id"] if native else receipt.get("containerId"),
      "exists": native is not None, "state": "active" if running else "inactive", "pid": str(pid),
      "invocationId": state.get("StartedAt", "") if running else "",
      "job": "pending" if state.get("Restarting") or state.get("Paused") else "",
      "healthy": health.get("Status", "") in ("", "healthy"), "observedAt": time.time(),
      "publishedConfigGeneration": receipt.get("publishedConfigGeneration"),
      "runningConfigGeneration": receipt.get("runningConfigGeneration")}

  def _observation_stamp(self, observation):
    return {field: observation.get(field) for field in
            ("engineIdentity", "nativeId", "exists", "state", "invocationId", "job")}

  def _image(self):
    values = self._json(["image", "inspect", self.resources["image"]])
    try:
      image = values[0]
      digest = self.resources["image"].split("@", 1)[1]
      identifier = image["Id"].removeprefix("sha256:")
      if (len(values) != 1 or not re.fullmatch(r"[a-f0-9]{64}", identifier)
          or not any(item.endswith("@" + digest) for item in image.get("RepoDigests", []))
          or image.get("Config", {}).get("Volumes")):
        raise ValueError()
      return "sha256:" + identifier
    except (KeyError, TypeError, ValueError, IndexError):
      raise HostError("CAPABILITY_UNSUPPORTED", "Preloaded image digest is unavailable or declares untracked volumes") from None

  def _create_arguments(self, configs, image, creation_intent):
    account = pwd.getpwnam(self.resources["runAsUser"])
    if account.pw_uid == 0:
      raise HostError("CAPABILITY_UNSUPPORTED", "OCI workload requires a non-root runtime user")
    limits = self.resources.get("limits", {})
    for key, lower, upper, default in (("memoryMiB", 64, 65536, 512), ("cpus", 1, 64, 1), ("pids", 16, 4096, 256)):
      value = limits.get(key, default)
      if type(value) is not int or not lower <= value <= upper:
        raise HostError("SCHEMA_INVALID", "Container resource limit is invalid")
    args = ["container", "create", "--name", self.container_name, "--pull=never", "--restart=no",
      "--network=bridge", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", str(account.pw_uid) + ":" + str(account.pw_gid),
      "--memory", str(limits.get("memoryMiB", 512)) + "m", "--cpus", str(limits.get("cpus", 1)),
      "--pids-limit", str(limits.get("pids", 256))]
    args += (["--log-driver=json-file", "--log-opt=max-size=10m", "--log-opt=max-file=3"] if self.engine == "docker"
             else ["--log-driver=k8s-file", "--log-opt=max-size=10485760"])
    for name, value in (("target", _json_hash(self.identity)), ("package", self.package_digest), ("intent", creation_intent)):
      args += ["--label", "ambari.mpack." + name + "=" + value]
    args += ["--mount", "type=bind,src=" + str(self.root / "config") + ",dst=/etc/ambari-config,readonly"]
    mounts = {}
    for mount in self.resources.get("mounts", []):
      destination = mount["containerPath"]
      source = self.directories.get(mount["directoryRef"])
      if (source is None or source.is_symlink() or not source.is_dir() or mount["directoryRef"] in mounts
          or not re.fullmatch(r"/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", destination)
          or destination == "/etc" or any(destination == reserved or destination.startswith(reserved + "/")
             for reserved in ("/proc", "/sys", "/dev", "/etc/ambari-config"))
          or any(destination == previous or destination.startswith(previous + "/") or previous.startswith(destination + "/") for previous in mounts.values())):
        raise HostError("TARGET_CONFLICT", "Container bind is outside the declared target resources")
      mounts[mount["directoryRef"]] = destination
      args += ["--mount", "type=bind,src=" + str(source) + ",dst=" + destination]
    for port in self._declared_ports(configs):
      args += ["--publish", "127.0.0.1:{0}:{0}/{1}".format(port["port"], port["protocol"])]
    command = self.resources.get("command", {})
    for name, value in command.get("environment", {}).items():
      if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or not isinstance(value, str) or any(char in value for char in ("\0", "\n", "\r")):
        raise HostError("SCHEMA_INVALID", "Container environment must be literal non-secret text")
      args += ["--env", name + "=" + value]
    if command:
      if not command.get("program", "").startswith("/"):
        raise HostError("SCHEMA_INVALID", "Container entrypoint must be absolute")
      args += ["--entrypoint", command["program"]]
    args.append(image)
    for argument in command.get("arguments", []):
      if isinstance(argument, dict) and set(argument) == {"configurationRef"} and argument["configurationRef"] in configs:
        argument = "/etc/ambari-config/current/" + argument["configurationRef"] + ".conf"
      elif isinstance(argument, dict) and set(argument) == {"directoryRef"}:
        argument = mounts.get(argument["directoryRef"])
      if not isinstance(argument, str) or any(char in argument for char in ("\0", "\n", "\r")):
        raise HostError("SCHEMA_INVALID", "Container arguments must use declared mounts or literal text")
      args.append(argument)
    return args

  def _publish(self, configs, generation, receipt):
    if (self.task_binding or {}).get("secretGenerations") or self.provision is None:
      raise HostError("CAPABILITY_UNSUPPORTED", "OCI requires its provisioner and does not support live secrets")
    self.provision(self.resources, self.directories, self.root)
    engine, _ = self._engine_identity()
    image = receipt.get("imageId") or self._image()
    replacing = receipt.get("containerRemoved", False)
    intent = receipt["intentDigest"] if replacing else receipt.get("creationIntent") or receipt["intentDigest"]
    args = self._create_arguments(configs, image, intent)
    recipe = _json_hash(args)
    if not replacing and receipt.get("containerRecipe") not in (None, recipe):
      raise HostError("CAPABILITY_UNSUPPORTED", "Container command, user, mounts and ports require explicit uninstall before replacement")
    native = self._inspect(receipt)
    if native is None and receipt.get("containerId") and not receipt.get("containerRemoved"):
      raise HostError("TARGET_CONFLICT", "Confirmed container disappeared; explicitly uninstall before reinstalling")
    self._stage(configs, generation)
    if native is None:
      receipt.update(engineIdentity=engine, imageId=image, creationIntent=intent, containerRecipe=recipe,
                     containerId=None, containerRemoved=False)
      self._save(receipt)
      self._run(args, timeout=60)
      native = self._inspect(receipt)
      if native is None:
        raise HostError("OUTCOME_UNKNOWN", "Created container could not be identified", "UNKNOWN")
    receipt.update(containerId=native["Id"], engineIdentity=engine, imageId=image, containerRecipe=recipe,
                   publishedConfigGeneration=generation)
    self._save(receipt)

  def _native(self, action):
    self._engine_identity()
    native = self._inspect(self._receipt())
    if native is None:
      raise HostError("TARGET_CONFLICT", "Bound container no longer exists")
    args = ["container", action]
    if action in ("stop", "restart"):
      args += ["--time", "30"]
    self._run(args + [native["Id"]], timeout=60)

  def _uninstall(self, configs, receipt):
    native = self._inspect(receipt)
    if native is not None:
      if native.get("State", {}).get("Running"):
        self._native("stop")
      self.verify("stop", configs)
      self._native("rm")
    receipt["containerRemoved"] = True
    receipt["retainedResources"] = self._retained_resources()
    self._save(receipt)

  def _healthy(self, configs=None, generation=None):
    observation = self.observe()
    return observation["healthy"] and super()._healthy(configs, generation)

  def verify(self, action, configs):
    deadline = time.monotonic() + 30
    while True:
      observation = self.observe()
      if action in ("uninstall", "purge") and not observation["exists"]:
        if action != "purge" or set(path.name for path in self.root.iterdir()) <= {"receipt.json", "operation.lock"}:
          return observation
      if action == "stop" and observation["state"] == "inactive" and observation["pid"] == "0" and not observation["job"]:
        return observation
      if action in ("install", "configure") and observation["exists"]:
        return observation
      if (action in ("start", "restart") and observation["state"] == "active" and int(observation["pid"]) > 0
          and not observation["job"] and self._healthy(configs)):
        return observation
      if time.monotonic() >= deadline or self.cancel is not None and self.cancel.is_set():
        raise HostError("OUTCOME_UNKNOWN", "Container postcondition is not established", "UNKNOWN")
      time.sleep(0.2)
