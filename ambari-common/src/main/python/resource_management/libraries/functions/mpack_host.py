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

"""Declarative host materialization behind the existing Ambari Script boundary.

The server task is the intent authority. receipt.json is a local materialization
receipt for that task, not a second workflow or permission store. No caller can
supply executable argv; commands come from an authenticated installed definition.
"""

import contextlib
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import subprocess
import time
import urllib.request
import uuid


HOST_OPERATIONS = frozenset({"install", "configure", "start", "stop", "restart", "reload", "upgrade", "detach", "adopt", "uninstall", "purge", "observe"})


class HostError(Exception):
  def __init__(self, code, message, state="FAILED"):
    super().__init__(message)
    self.code = code
    self.state = state


def _hash(value):
  return hashlib.sha256(value).hexdigest()


def _json_hash(value):
  return _hash(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _name(value):
  if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value):
    raise HostError("SCHEMA_INVALID", "Invalid resource identifier")
  return value


def _atomic(path, data, mode=0o600):
  path = Path(path)
  path.parent.mkdir(parents=True, exist_ok=True)
  temporary = path.with_name(path.name + ".pending")
  descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
  try:
    with os.fdopen(descriptor, "wb") as stream:
      stream.write(data)
      stream.flush()
      os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
      os.fsync(directory)
    finally:
      os.close(directory)
  finally:
    if temporary.exists():
      temporary.unlink()


class _LocalProbeRedirectHandler(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, request, fp, code, message, headers, new_url):
    # A local health endpoint cannot redirect Agent credentials/network authority.
    return None


class NativeRunner:
  """Bounded process output, deadline and whole-group cancellation."""

  def run(self, argv, cancel=None, timeout=30):
    if cancel is not None and cancel.is_set():
      raise HostError("OUTCOME_UNKNOWN", "Operation canceled", "UNKNOWN")
    try:
      process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
        start_new_session=True)
    except OSError as error:
      raise HostError("CAPABILITY_UNSUPPORTED", "Native runtime executable is unavailable") from error
    output = bytearray()
    completed = False
    deadline = time.monotonic() + timeout
    try:
      with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        while selector.get_map():
          if time.monotonic() >= deadline or (cancel is not None and cancel.is_set()):
            raise HostError("OUTCOME_UNKNOWN", "Native command timed out or was canceled", "UNKNOWN")
          for key, _ in selector.select(0.1):
            chunk = os.read(key.fileobj.fileno(), 8192)
            if not chunk:
              selector.unregister(key.fileobj)
              continue
            if key.fileobj is process.stdout:
              output.extend(chunk[:max(0, 65536 - len(output))])
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
      completed = True
      return process.returncode, output.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired as error:
      raise HostError("OUTCOME_UNKNOWN", "Native command did not finish", "UNKNOWN") from error
    finally:
      if not completed:
        # Keep the group ID even if the parent exits first. Children cannot retain
        # inherited pipes indefinitely after cancellation.
        with contextlib.suppress(ProcessLookupError):
          os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
      process.stdout.close()
      process.stderr.close()


class HostDeployment:
  runtime_profile = "host.systemd/v1"

  def __init__(self, descriptor, payload, command, root="/var/lib/ambari-agent/mpack/deployments",
               units="/etc/systemd/system", runner=None, cancel=None, provision=None, runtime_root="/run/ambari-mpack"):
    if descriptor.get("format") != "mpack.ambari.apache.org/host-service/v1":
      raise HostError("CAPABILITY_UNSUPPORTED", "Unsupported installed host-service contract")
    self.descriptor = descriptor
    self.payload = Path(payload).resolve()
    self.command = command
    try:
      self.task_binding = json.loads(command.get("commandParams", {}).get("mpack_task_binding", "null"))
    except (ValueError, TypeError):
      raise HostError("SCHEMA_INVALID", "Invalid persisted task binding") from None
    if self.task_binding is not None and not isinstance(self.task_binding, dict):
      raise HostError("SCHEMA_INVALID", "Invalid persisted task binding")
    cluster = command.get("clusterId")
    if isinstance(cluster, bool) or not str(cluster).isdigit() or int(cluster) <= 0:
      raise HostError("SCHEMA_INVALID", "An existing cluster identity is required")
    self.service = descriptor["service"]
    if command.get("serviceName") != self.service["name"]:
      raise HostError("TARGET_CONFLICT", "Command service does not match installed package")
    role = command.get("role")
    components = {value["name"]: value for value in self.service["components"]}
    if str(command.get("roleCommand", "")).endswith("SERVICE_CHECK") or str(role).endswith("_SERVICE_CHECK"):
      local = set(command.get("localComponents", [])) & set(components)
      if len(local) != 1:
        raise HostError("TARGET_CONFLICT", "Service check requires an explicit local component")
      role = next(iter(local))
    if role not in components:
      raise HostError("TARGET_CONFLICT", "Command component does not match installed package")
    self.component = components[role]
    self.profile = self.component["profiles"][0]
    if len(self.component["profiles"]) != 1 or self.profile["adapter"] != self.runtime_profile:
      raise HostError("CAPABILITY_UNSUPPORTED", "An explicit host profile is required")
    self.identity = {"clusterId": int(cluster), "serviceName": _name(self.service["name"]),
                     "componentName": _name(role), "hostName": command.get("mpackCurrentHost", {}).get("hostName")
                     or command.get("agentLevelParams", {}).get("hostname") or socket.gethostname()}
    incarnation = command.get("commandParams", {}).get("mpack_target_incarnation",
        command.get("serviceLevelParams", {}).get("mpack_target_incarnation"))
    try:
      incarnation = str(uuid.UUID(incarnation))
    except (ValueError, TypeError, AttributeError):
      raise HostError("TARGET_CONFLICT", "A server-owned target incarnation is required") from None
    self.identity["targetIncarnation"] = incarnation
    self.target = "ambari-{}-{}-{}-{}".format(cluster, self.identity["serviceName"], role, incarnation)
    self.root = Path(root) / self.target
    self.runtime_root = Path(runtime_root) / self.target
    self.secret_values = {}
    self.unit = self.target + ".service"
    if len(self.unit) > 255:
      raise HostError("CAPABILITY_UNSUPPORTED", "Service/component names exceed the native unit limit")
    self.unit_path = Path(units) / self.unit
    self.runner = runner or NativeRunner()
    self.cancel = cancel
    self.provision = provision
    self.resources = self.profile.get("resources", {})
    self.package_digest = descriptor["package"]["digest"]
    self.directories = {item["path"]: self.root / "resources" / _name(item["path"])
                        for item in self.resources.get("directories", [])}
    if self.service.get("requires"):
      raise HostError("DEPENDENCY_UNRESOLVED", "No shared binding consumer is configured for this host contract")

  def _source(self, relative):
    candidate = self.payload / relative
    if candidate.is_symlink() or self.payload not in candidate.resolve().parents:
      raise HostError("TARGET_CONFLICT", "Package file escapes its installed boundary")
    return candidate

  def validate_inputs(self, validate_config=True):
    if len(self.descriptor["files"]) > 10000 or sum(entry["size"] for entry in self.descriptor["files"]) > 512 * 1024 * 1024:
      raise HostError("SCHEMA_INVALID", "Host payload exceeds its materialization limit")
    for entry in self.descriptor["files"]:
      path = self._source(entry["path"])
      if not path.is_file() or path.stat().st_size != entry["size"] or _hash(path.read_bytes()) != entry["sha256"]:
        raise HostError("TARGET_CONFLICT", "Installed package content failed digest verification")
    params = self.command.get("commandParams", {})
    metadata = self.command.get("serviceLevelParams", {})
    expected = params.get("mpack_content_digest", metadata.get("mpack_content_digest"))
    if expected != self.package_digest:
      raise HostError("PLAN_STALE", "Task package digest differs from installed definition")
    return self._configurations() if validate_config else {}

  def _configurations(self):
    all_values = self.command.get("configurations", {})
    configurations = {}
    for config in self.service.get("configurations", []):
      schema = json.loads(self._source(config["schema"]).read_text())
      values = dict(config.get("defaults", {}))
      provided = all_values.get(config["name"], {})
      if not isinstance(provided, dict):
        raise HostError("SCHEMA_INVALID", "Configuration must be a field map")
      if self.task_binding is not None:
        expected = self.task_binding.get("configurationHashes", {}).get(config["name"], {})
        actual = {name: _hash(str(value).encode("utf-8")) for name, value in provided.items()}
        if actual != expected:
          raise HostError("PLAN_STALE", "Configuration differs from the persisted task snapshot")
      values.update(provided)
      properties = schema.get("properties", {})
      if set(values) - set(properties):
        raise HostError("SCHEMA_INVALID", "Unknown configuration field")
      for name, field in properties.items():
        if field.get("x-resource"):
          resource = self.directories.get(field["x-resource"])
          if resource is None:
            raise HostError("SCHEMA_INVALID", "Unknown managed directory reference")
          if name in provided and provided[name] != str(resource):
            raise HostError("SCHEMA_INVALID", "Managed directory fields are injected by the runtime")
          values[name] = str(resource)
          continue
        if field.get("x-sensitive"):
          reference = values.get(name, field.get("default"))
          if isinstance(reference, dict) and set(reference) == {"secretRef"}:
            reference = reference["secretRef"]
          if not isinstance(reference, str) or reference not in (self.task_binding or {}).get("secretGenerations", {}):
            raise HostError("DEPENDENCY_UNRESOLVED", "Sensitive configuration requires a resolved scoped reference")
          values[name] = {"secretRef": reference}
          continue
        if field.get("type") not in ("string", "integer", "number", "boolean"):
          raise HostError("CAPABILITY_UNSUPPORTED", "Host scalar config contract does not resolve secrets or objects")
        value = values.get(name, field.get("default"))
        if value is None:
          if name in schema.get("required", []):
            raise HostError("SCHEMA_INVALID", "Required configuration field is missing")
          continue
        try:
          if field["type"] == "integer":
            if isinstance(value, bool) or not re.fullmatch(r"-?[0-9]+", str(value)):
              raise ValueError()
            value = int(value)
          elif field["type"] == "number":
            value = float(value)
            if not math.isfinite(value):
              raise ValueError()
          elif field["type"] == "boolean":
            if str(value).lower() not in ("true", "false"):
              raise ValueError()
            value = str(value).lower() == "true"
          elif not isinstance(value, str) or any(char in value for char in ("\n", "\r", "\0")):
            raise ValueError()
          if "enum" in field and value not in field["enum"]:
            raise ValueError()
          if isinstance(value, (int, float)) and not isinstance(value, bool):
            if value < field.get("minimum", float("-inf")) or value > field.get("maximum", float("inf")):
              raise ValueError()
          if isinstance(value, str) and (len(value) < field.get("minLength", 0) or len(value) > field.get("maxLength", 65536)):
            raise ValueError()
        except (TypeError, ValueError, OverflowError):
          raise HostError("SCHEMA_INVALID", "Configuration value violates its schema") from None
        values[name] = value
      configurations[config["name"]] = values
    return configurations

  def discover(self):
    code, output = self.runner.run(["/usr/bin/systemctl", "--version"], self.cancel, 5)
    if code != 0 or not output.startswith("systemd "):
      raise HostError("CAPABILITY_UNSUPPORTED", "systemd discovery failed")
    return {"profile": "host.systemd/v1", "identity": self.identity, "target": self.unit,
            "version": output.splitlines()[0], "observedAt": time.time(), "validForSeconds": 30,
            "capabilities": sorted(set(self.profile["capabilities"]) & HOST_OPERATIONS)}

  def observe(self):
    receipt = self._receipt()
    self._owned(receipt)
    code, output = self.runner.run(["/usr/bin/systemctl", "show", self.unit,
      "--property=Id,LoadState,ActiveState,SubState,MainPID,FragmentPath,InvocationID,Job", "--no-pager"], self.cancel, 5)
    values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    absent = values.get("LoadState") == "not-found" and values.get("Id") == self.unit
    if (code != 0 and not (code == 1 and absent)) or "LoadState" not in values:
      raise HostError("OUTCOME_UNKNOWN", "Native state could not be observed", "UNKNOWN")
    if not values.get("MainPID", "0").isdigit():
      raise HostError("OUTCOME_UNKNOWN", "Native process identity could not be observed", "UNKNOWN")
    if values["LoadState"] != "not-found" and (values.get("Id") != self.unit or values.get("FragmentPath") != str(self.unit_path)):
      raise HostError("TARGET_CONFLICT", "Native unit identity differs from the bound target")
    return {"identity": self.identity, "target": self.unit, "observedAt": time.time(),
      "receiptState": receipt.get("state"),
      "publishedConfigGeneration": receipt.get("publishedConfigGeneration"),
      "runningConfigGeneration": receipt.get("runningConfigGeneration"),
      "state": values.get("ActiveState", "unknown"), "loadState": values["LoadState"],
      "subState": values.get("SubState"), "pid": values.get("MainPID", "0"),
      "invocationId": values.get("InvocationID", ""), "job": values.get("Job", "")}

  def _receipt(self):
    path = self.root / "receipt.json"
    if not path.exists():
      return {}
    receipt = json.loads(path.read_text())
    if receipt.get("identity") != self.identity:
      raise HostError("TARGET_CONFLICT", "Deployment receipt identity mismatch")
    return receipt

  def _save(self, receipt):
    _atomic(self.root / "receipt.json", json.dumps(receipt, sort_keys=True).encode())

  def _release_layout(self):
    return _json_hash({"resources": {key: value for key, value in self.resources.items()
                                   if key not in ("command", "reloadSignal")},
                       "configurations": sorted(config["name"] for config in self.service.get("configurations", []))})

  def _check_upgrade(self, receipt, current, generation):
    policy = self.profile.get("upgradePolicy", {})
    previous = receipt.get("materializedPackage", {})
    release = self.descriptor["package"]
    source = receipt.get("materializedPackageDigest")
    if source == self.package_digest:
      completed = receipt.get("lastUpgrade", {})
      if completed.get("toDigest") != self.package_digest or receipt.get("publishedConfigGeneration") != generation:
        raise HostError("TARGET_CONFLICT", "No matching artifact update requires recovery")
      source = completed.get("fromDigest")
    if (policy.get("configuration") != "compatible" or policy.get("data") != "unchanged"
        or source not in policy.get("fromPackageDigests", [])
        or not previous.get("name") or previous.get("name") != release.get("name")
        or receipt.get("resourceLayout") != self._release_layout()
        or not any(isinstance(argument, dict) and "artifactRef" in argument
                   for argument in self.resources.get("command", {}).get("arguments", []))):
      raise HostError("CAPABILITY_UNSUPPORTED", "Artifact update requires declared compatibility and unchanged owned resources")
    if current["state"] != "inactive" or current["pid"] != "0" or current["loadState"] != "loaded":
      raise HostError("TARGET_CONFLICT", "Stop the installed target before updating its artifacts")

  def _installed_file_digest(self, generation):
    paths = ["releases/" + self.package_digest + "/" + item["path"] for item in self.descriptor["artifacts"]]
    paths += ["config/g-" + generation + "/" + config["name"] + ".conf"
              for config in self.service.get("configurations", []) if config.get("template")]
    inventory = {}
    for relative in paths:
      path = self.root / relative
      if path.is_symlink() or not path.is_file() or self.root not in path.resolve().parents:
        raise HostError("TARGET_CONFLICT", "Published file identity has changed")
      inventory[relative] = {"sha256": _hash(path.read_bytes()), "mode": path.stat().st_mode & 0o777}
    return _json_hash(inventory)

  def _check_handoff(self, action, receipt, current, configs, generation):
    if (action == "adopt" and not receipt.get("detached") and receipt.get("operation") != "adopt"
        or receipt.get("materializedPackageDigest") != self.package_digest
        or receipt.get("resourceLayout") != self._release_layout()
        or receipt.get("publishedConfigGeneration") != generation
        or not receipt.get("publicationDigest")
        or (self.task_binding or {}).get("secretGenerations")
        or receipt.get("publicationDigest") != self._installed_file_digest(generation)
        or receipt.get("unitHash") != _hash(self._unit_content(configs, generation))):
      raise HostError("TARGET_CONFLICT", "Ownership handoff requires the unchanged verified publication and existing detached identity")
    if current["state"] != "inactive" or current["pid"] != "0" or current["loadState"] != "loaded":
      raise HostError("TARGET_CONFLICT", "Stop the verified target before handing off ownership")

  def _owned(self, receipt):
    if self.unit_path.exists() or self.unit_path.is_symlink():
      hashes = {receipt.get("unitHash")}
      if receipt.get("state") in ("APPLYING", "UNKNOWN"):
        hashes.add(receipt.get("pendingUnitHash"))
      if self.unit_path.is_symlink() or _hash(self.unit_path.read_bytes()) not in hashes:
        raise HostError("TARGET_CONFLICT", "Existing native unit is not owned by this deployment")

  def plan(self, action):
    if action == "observe" or action not in HOST_OPERATIONS or action not in self.profile["capabilities"]:
      raise HostError("CAPABILITY_UNSUPPORTED", "Host operation is unsupported")
    configs = self.validate_inputs(validate_config=action not in ("stop", "uninstall", "purge"))
    discovery = self.discover()
    receipt = self._receipt()
    self._owned(receipt)
    return {"identity": self.identity, "target": discovery["target"], "operation": action,
      "taskId": self.command.get("taskId"), "packageDigest": self.package_digest,
      "configGeneration": self._generation(configs), "configTags": json.loads(json.dumps(self._config_tags())),
      "expectedReceipt": _json_hash(receipt), "observation": self.observe(), "createdAt": time.time(), "expiresAt": time.time() + 30,
      "discovery": discovery}

  def _resolve(self, value, configs, generation):
    if isinstance(value, str):
      return value
    if not isinstance(value, dict) or len(value) != 1:
      raise HostError("SCHEMA_INVALID", "Invalid typed argument")
    kind, reference = next(iter(value.items()))
    if kind == "artifactRef":
      artifact = next((item for item in self.descriptor["artifacts"] if item["id"] == reference), None)
      if artifact is not None:
        return str(self.root / "releases" / self.package_digest / artifact["path"])
    if kind == "directoryRef" and reference in self.directories:
      return str(self.directories[reference])
    if kind == "configurationRef" and reference in configs:
      return str(self.root / "config" / "current" / (reference + ".conf"))
    if kind == "configRef":
      name, _, field = reference.partition(".")
      if name in configs and field in configs[name]:
        if isinstance(configs[name][field], dict):
          raise HostError("CAPABILITY_UNSUPPORTED", "Secret values cannot appear in native arguments or unit files")
        return str(configs[name][field])
    raise HostError("SCHEMA_INVALID", "Unresolved typed argument")

  def _stage(self, configs, generation):
    release = self.root / "releases" / self.package_digest
    for item in self.descriptor["artifacts"]:
      target = release / item["path"]
      source = self._source(item["path"])
      _atomic(target, source.read_bytes(), 0o644)
    directory = self.root / "config" / ("g-" + generation)
    if self.secret_values:
      # Create the generation even if this component has no rendered template.
      self._runtime_file("g-" + generation, ".generation", generation.encode(), root_only=True)
    rendered_bytes = 0
    for config in self.service.get("configurations", []):
      if not config.get("template"):
        continue
      template = self._source(config["template"]).read_text()
      if "{%" in template or "{#" in template:
        raise HostError("CAPABILITY_UNSUPPORTED", "Only scalar template substitutions are supported")
      def substitute(match):
        key = match.group(1)
        if key == "mpack_config_generation":
          return generation
        if key not in configs[config["name"]]:
          raise HostError("SCHEMA_INVALID", "Template references an absent configuration field")
        value = configs[config["name"]][key]
        if isinstance(value, dict) and "secretRef" in value:
          secret = self.secret_values[value["secretRef"]]
          schema = json.loads(self._source(config["schema"]).read_text())
          return secret if schema["properties"][key].get("x-secret-encoding") == "literal" else json.dumps(secret, ensure_ascii=True)
        return str(value)
      rendered = re.sub(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}", substitute, template)
      if "{{" in rendered:
        raise HostError("SCHEMA_INVALID", "Unsupported template expression")
      rendered_bytes += len(rendered.encode())
      if rendered_bytes > 32 * 1024 * 1024:
        raise HostError("SCHEMA_INVALID", "Rendered configuration exceeds 32 MiB")
      if self.secret_values:
        self._runtime_file("g-" + generation, config["name"] + ".conf", rendered.encode())
      else:
        _atomic(directory / (config["name"] + ".conf"), rendered.encode(), 0o644)
    secret_environment = []
    for name, expression in self.resources.get("command", {}).get("environment", {}).items():
      if isinstance(expression, dict) and "secretRef" in expression:
        value = self.secret_values[expression["secretRef"]]
        secret_environment.append(name + "=" + json.dumps(value, ensure_ascii=True))
    if secret_environment:
      self._runtime_file("g-" + generation, "environment", ("\n".join(secret_environment) + "\n").encode(), root_only=True)
    directory.mkdir(parents=True, exist_ok=True)
    current = self.root / "config" / "current"
    temporary = current.with_name("current.pending")
    with contextlib.suppress(FileNotFoundError):
      temporary.unlink()
    temporary.symlink_to(self.runtime_root / ("g-" + generation) if self.secret_values else directory.name)
    os.replace(temporary, current)
    descriptor = os.open(current.parent, os.O_RDONLY)
    try:
      os.fsync(descriptor)
    finally:
      os.close(descriptor)

  def _unit_content(self, configs, generation):
    command = self.resources["command"]
    program = command["program"]
    if not os.path.isabs(program):
      program = shutil.which(program, path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not program or not Path(program).is_file():
      raise HostError("CAPABILITY_UNSUPPORTED", "Declared service executable is unavailable")
    argv = [program] + [self._resolve(value, configs, generation) for value in command.get("arguments", [])]
    def quote(value):
      if any(char in value for char in ("\n", "\r", "\0", "%", "$")):
        raise HostError("SCHEMA_INVALID", "Unsupported systemd argument expansion")
      return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
    user = _name(self.resources["unit"]["user"])
    group = self.resources["unit"].get("group")
    group_line = "\nGroup=" + _name(group) if group else ""
    working = self.resources["unit"].get("workingDirectory")
    directory = self.directories.get(working, self.root)
    environment = ""
    for name, value in command.get("environment", {}).items():
      if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise HostError("SCHEMA_INVALID", "Invalid environment variable name")
      if isinstance(value, dict) and "secretRef" in value:
        continue
      environment += "Environment=" + quote(name + "=" + self._resolve(value, configs, generation)) + "\n"
    if any(isinstance(value, dict) and "secretRef" in value for value in command.get("environment", {}).values()):
      environment += "EnvironmentFile=" + quote(str(self.root / "config" / "current" / "environment")) + "\n"
    reload_command = ""
    if "reload" in self.profile["capabilities"]:
      reload_signal = self.resources.get("reloadSignal")
      if reload_signal not in ("HUP", "USR1", "USR2"):
        raise HostError("SCHEMA_INVALID", "Reload requires an explicit supported signal")
      reload_command = "\nExecReload=/bin/kill -" + reload_signal + " $MAINPID"
    return ("[Unit]\nDescription=Ambari managed service\n[Service]\nType=simple\n" + environment + "User=" + user + group_line
      + "\nWorkingDirectory=" + str(directory) + "\nExecStart=" + " ".join(map(quote, argv))
      + reload_command + "\nRestart=no\n[Install]\nWantedBy=multi-user.target\n").encode()

  def _native(self, action):
    argv = ["/usr/bin/systemctl", action]
    if action != "daemon-reload":
      argv.append(self.unit)
    code, _ = self.runner.run(argv, self.cancel, 60)
    if code != 0:
      raise HostError("OUTCOME_UNKNOWN", "Native mutation result requires observation", "UNKNOWN")

  def _declared_ports(self, configs):
    ports = []
    for declaration in self.resources.get("ports", []):
      name, _, field = declaration["configRef"].partition(".")
      try:
        port = int(configs[name][field])
        protocol = declaration.get("protocol", "tcp")
        if port < 1 or port > 65535 or protocol not in ("tcp", "udp"):
          raise ValueError()
      except (KeyError, TypeError, ValueError):
        raise HostError("SCHEMA_INVALID", "Declared listener requires a valid port") from None
      item = {"port": port, "protocol": protocol}
      if item in ports:
        raise HostError("TARGET_CONFLICT", "Multiple declared listeners use the same port")
      ports.append(item)
    return ports

  def _check_ports(self, configs, observation, receipt):
    owned = receipt.get("runningPorts", []) if observation["state"] == "active" else []
    for listener in self._declared_ports(configs):
      if listener in owned:
        continue
      kind = socket.SOCK_STREAM if listener["protocol"] == "tcp" else socket.SOCK_DGRAM
      try:
        with socket.socket(socket.AF_INET, kind) as probe:
          probe.bind(("0.0.0.0", listener["port"]))
      except OSError:
        raise HostError("TARGET_CONFLICT", "Declared IPv4 listener is unavailable") from None

  def _probe_config(self, configs):
    health = self.profile.get("health", {})
    probe = {"kind": health.get("kind", "process"), "timeoutSeconds": health.get("timeoutSeconds", 5)}
    if probe["kind"] != "process":
      name, _, field = health["portRef"].partition(".")
      probe["port"] = int(configs[name][field])
      if probe["kind"] == "http":
        probe["path"] = health.get("path", "/")
    return probe

  def _healthy(self, configs=None, generation=None):
    health = self._probe_config(configs) if configs is not None else self._receipt().get("runningProbe")
    if not isinstance(health, dict):
      return False
    if health.get("kind") == "process":
      return generation is None
    port = int(health["port"])
    timeout = min(30, float(health.get("timeoutSeconds", 5)))
    try:
      if health["kind"] == "tcp":
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
          return generation is None
      if health["kind"] == "http":
        path = health.get("path", "/")
        if not path.startswith("/") or "\n" in path:
          raise HostError("SCHEMA_INVALID", "Invalid health path")
        # Ignore process proxy environment; probes are scoped to this local target.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _LocalProbeRedirectHandler())
        with opener.open("http://127.0.0.1:{}{}".format(port, path), timeout=timeout) as response:
          return response.status == 200 and (generation is None
            or response.headers.get("X-Ambari-Config-Generation") == generation)
    except (OSError, ValueError):
      return False
    return False

  def verify(self, action, configs):
    deadline = time.monotonic() + 30
    while True:
      observation = self.observe()
      if action == "uninstall" and observation["loadState"] == "not-found" and observation["state"] == "inactive" and observation["pid"] == "0":
        return observation
      if action == "purge" and observation["loadState"] == "not-found" and observation["state"] == "inactive" and observation["pid"] == "0":
        if set(path.name for path in self.root.iterdir()) <= {"receipt.json", "operation.lock"}:
          return observation
      if action in ("detach", "adopt") and observation["loadState"] == "loaded" and observation["state"] == "inactive" and observation["pid"] == "0":
        if self._receipt().get("detached", False) == (action == "detach"):
          return observation
      if action == "stop" and observation["state"] == "inactive":
        return observation
      if action in ("start", "restart") and observation["state"] == "active" and int(observation["pid"]) > 0 and self._healthy(configs):
        return observation
      if action == "reload" and observation["state"] == "active" and int(observation["pid"]) > 0:
        before = self._receipt().get("beforeObservation", {})
        if not before.get("invocationId") or observation["invocationId"] != before["invocationId"]:
          raise HostError("OUTCOME_UNKNOWN", "Process changed during reload", "UNKNOWN")
        if self._healthy(configs, self._generation(configs)):
          return observation
      if action in ("install", "configure") and observation["loadState"] == "loaded":
        return observation
      if action == "upgrade" and observation["loadState"] == "loaded" and observation["state"] == "inactive" and observation["pid"] == "0":
        if self._receipt().get("publishedConfigGeneration") == self._generation(configs):
          return observation
      if self.cancel is not None and self.cancel.is_set():
        raise HostError("OUTCOME_UNKNOWN", "Verification canceled", "UNKNOWN")
      if time.monotonic() >= deadline:
        raise HostError("OUTCOME_UNKNOWN", "Postcondition could not be verified", "UNKNOWN")
      time.sleep(0.2)

  def _config_tags(self):
    return self.task_binding.get("configTags", {}) if self.task_binding is not None else self.command.get("configurationTags", {})

  def _validate_task_binding(self, action):
    expected = {"clusterId": self.identity["clusterId"], "serviceName": self.identity["serviceName"],
      "role": self.command.get("role"), "packageDigest": self.package_digest,
      "hostName": self.identity["hostName"],
      "targetIncarnation": self.identity["targetIncarnation"]}
    if not isinstance(self.task_binding, dict) or any(self.task_binding.get(key) != value for key, value in expected.items()):
      raise HostError("TARGET_CONFLICT", "Mutation requires the matching persisted server task binding")
    if str(self.task_binding.get("operation", "")).lower() != action:
      raise HostError("TARGET_CONFLICT", "Operation differs from the persisted server task")
    membership = self.command.get("mpackCurrentHost", {})
    if (membership.get("hostName") != self.command.get("hostname")
        or self.identity["componentName"] not in membership.get("components", [])):
      raise HostError("TARGET_CONFLICT", "Task target is no longer assigned to this Agent")
    if action not in ("stop", "uninstall", "purge") and membership.get("configurationHashes") != self.task_binding.get("configurationHashes"):
      raise HostError("PLAN_STALE", "Desired configuration superseded the persisted task snapshot")
    metadata = self.command.get("serviceLevelParams", {})
    if (metadata.get("mpack_target_incarnation") != self.identity["targetIncarnation"]
        or metadata.get("mpack_content_digest") != self.package_digest):
      raise HostError("PLAN_STALE", "Service metadata superseded the persisted task binding")

  def _observation_stamp(self, observation):
    return {field: observation.get(field) for field in ("state", "loadState", "invocationId", "job")}

  def apply(self, plan):
    self._validate_task_binding(plan["operation"])
    self.root.mkdir(parents=True, exist_ok=True, mode=0o755)
    with open(self.root / "operation.lock", "a+") as lock:
      try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
      except BlockingIOError as error:
        raise HostError("TARGET_CONFLICT", "Another task owns the deployment mutation") from error
      configs = self.validate_inputs(validate_config=plan["operation"] not in ("stop", "uninstall", "purge"))
      receipt = self._receipt()
      self._owned(receipt)
      if (plan["expiresAt"] < time.time() or plan["expectedReceipt"] != _json_hash(receipt)
          or plan["configGeneration"] != self._generation(configs)
          or plan["configTags"] != self._config_tags()):
        raise HostError("PLAN_STALE", "Task plan no longer matches target or configuration")
      current = self.observe()
      if self._observation_stamp(current) != self._observation_stamp(plan["observation"]):
        raise HostError("PLAN_STALE", "Native state changed after planning")
      action = plan["operation"]
      if receipt.get("detached") and action not in ("detach", "adopt"):
        raise HostError("TARGET_CONFLICT", "Adopt the detached target before managing its resources")
      if (receipt.get("purged") or receipt.get("operation") == "purge") and action != "purge":
        raise HostError("TARGET_CONFLICT", "Purge has begun; finish purge and use a new service incarnation")
      if action not in ("stop", "uninstall", "purge") and current.get("job") not in (None, "", "0", "0 /"):
        raise HostError("OUTCOME_UNKNOWN", "Native job is still pending; observe or explicitly stop", "UNKNOWN")
      materialized_digest = receipt.get("materializedPackageDigest", receipt.get("packageDigest"))
      if materialized_digest not in (None, self.package_digest) and action not in ("stop", "uninstall", "purge", "upgrade"):
        raise HostError("CAPABILITY_UNSUPPORTED", "This host profile does not declare binary/data upgrade compatibility")
      task = str(self.command.get("taskId", ""))
      if not task.isdigit() or int(task) <= 0:
        raise HostError("SCHEMA_INVALID", "Mutation requires an existing Ambari task ID")
      if receipt.get("taskId") and int(task) < int(receipt["taskId"]):
        raise HostError("PLAN_STALE", "A newer task has already superseded this task")
      intent = {key: plan[key] for key in ("identity", "target", "operation", "packageDigest", "configGeneration", "configTags")}
      key = _json_hash(intent)
      if receipt.get("taskId") == task and receipt.get("intentDigest") != key:
        raise HostError("TARGET_CONFLICT", "Task ID was reused with another intent")
      if receipt.get("taskId") == task and receipt.get("state") == "SUCCEEDED":
        return {"state": "SUCCEEDED", "replayed": True, "observation": self.verify(action, configs),
                "configGeneration": receipt.get("configGeneration"),
                "identity": self.identity, "taskId": task, "packageDigest": self.package_digest,
                "materializedPackageDigest": receipt.get("materializedPackageDigest"),
                "retainedResources": receipt.get("retainedResources", []),
                "detached": receipt.get("detached", False),
                "purged": receipt.get("purged", False), "purgedResources": receipt.get("purgedResources", [])}
      interrupted = receipt.get("state") in ("APPLYING", "UNKNOWN")
      if interrupted and receipt.get("intentDigest") != key and action not in ("stop", "uninstall", "purge"):
        raise HostError("OUTCOME_UNKNOWN", "Previous task must be reconciled or explicitly stopped", "UNKNOWN")
      if interrupted and action == "reload":
        # A matching acknowledgement resolves response loss without sending the signal again.
        observed = self.verify("reload", configs)
        receipt.update(state="SUCCEEDED", taskId=task, runningConfigGeneration=plan["configGeneration"],
                       publishedConfigGeneration=plan["configGeneration"])
        self._save(receipt)
        return {"state": "SUCCEEDED", "recovered": True, "observation": observed,
                "identity": self.identity, "taskId": task, "packageDigest": self.package_digest,
                "runningConfigGeneration": plan["configGeneration"],
                "materializedPackageDigest": receipt.get("materializedPackageDigest"),
                "publishedConfigGeneration": plan["configGeneration"]}
      if interrupted and action in ("start", "restart") and receipt.get("intentDigest") == key:
        observed = self.observe()
        before = receipt.get("beforeObservation", {})
        if observed["state"] == "active":
          if observed.get("invocationId") and observed["invocationId"] != before.get("invocationId"):
            verified = self.verify("start", configs)
            receipt.update(state="SUCCEEDED", taskId=task,
              runningConfigGeneration=plan["configGeneration"], runningPackageDigest=self.package_digest,
              materializedPackageDigest=self.package_digest, materializedPackage=dict(self.descriptor["package"]),
              resourceLayout=self._release_layout(),
              runningProbe=self._probe_config(configs), runningPorts=self._declared_ports(configs))
            self._save(receipt)
            return {"state": "SUCCEEDED", "recovered": True, "observation": verified,
                    "identity": self.identity, "taskId": task, "packageDigest": self.package_digest,
                    "materializedPackageDigest": self.package_digest,
                    "publishedConfigGeneration": receipt.get("publishedConfigGeneration"),
                    "runningConfigGeneration": receipt.get("runningConfigGeneration")}
          raise HostError("OUTCOME_UNKNOWN", "Running invocation cannot prove the new intent; explicitly stop before starting again", "UNKNOWN")
        raise HostError("OUTCOME_UNKNOWN", "Interrupted start has no surviving invocation evidence; explicitly stop before retry", "UNKNOWN")
      if action in ("install", "configure", "start", "restart"):
        self._check_ports(configs, current, receipt)
      if action == "upgrade":
        self._check_upgrade(receipt, current, plan["configGeneration"])
      if action in ("detach", "adopt"):
        self._check_handoff(action, receipt, current, configs, plan["configGeneration"])
      if action == "reload":
        if (current["state"] != "active" or not current.get("invocationId")
            or self.profile.get("health", {}).get("kind") != "http"
            or self._declared_ports(configs) != receipt.get("runningPorts", [])
            or any(config.get("changeEffect", "restart") != "reload" for config in self.service.get("configurations", []))
            or any(isinstance(value, dict) and "secretRef" in value for value in self.resources["command"].get("environment", {}).values())
            or _hash(self._unit_content(configs, plan["configGeneration"])) != receipt.get("unitHash")):
          raise HostError("CAPABILITY_UNSUPPORTED", "This change requires restart rather than reload")
      if action == "purge":
        if not receipt.get("retainedResources") or not (
            receipt.get("operation") == "uninstall" and receipt.get("state") == "SUCCEEDED"
            or receipt.get("operation") == "purge"):
          raise HostError("TARGET_CONFLICT", "Purge requires a verified uninstall receipt")
        self.verify("uninstall", configs)
        self._validate_retained_paths(receipt)
      receipt["materializedPackageDigest"] = materialized_digest or self.package_digest
      receipt.update(intent, taskId=task, intentDigest=key, state="APPLYING",
                     beforeObservation=plan["observation"])
      self._save(receipt)
      try:
        if self.cancel is not None and self.cancel.is_set():
          raise HostError("OUTCOME_UNKNOWN", "Task canceled before mutation", "UNKNOWN")
        if action in ("install", "configure", "start", "restart", "upgrade"):
          self._publish(configs, plan["configGeneration"], receipt)
        if action == "reload":
          self._load_secrets()
          self._stage(configs, plan["configGeneration"])
          receipt["publishedConfigGeneration"] = plan["configGeneration"]
          self._save(receipt)
          self._native("reload")
        elif action in ("start", "restart"):
          current = self.observe()
          if current["state"] == "active" and (action == "restart" or receipt.get("runningConfigGeneration") != plan["configGeneration"]
              or receipt.get("runningPackageDigest") != self.package_digest):
            self._native("restart")
          elif current["state"] != "active":
            self._native("start")
          receipt["runningConfigGeneration"] = plan["configGeneration"]
          receipt["runningPackageDigest"] = self.package_digest
        elif action in ("detach", "adopt"):
          receipt["detached"] = action == "detach"
          if action == "detach":
            receipt["retainedResources"] = self._retained_resources()
          self._save(receipt)
        elif action == "purge":
          self._purge_files()
          receipt["purgedResources"] = [dict(resource, disposition="receipt-only" if resource["path"] == str(self.root) else "purged")
                                         for resource in receipt["retainedResources"]]
          receipt["purged"] = True
        elif action == "uninstall":
          self._uninstall(configs, receipt)
        elif action == "stop":
          if self.observe()["state"] != "inactive":
            self._native("stop")
        observation = self.verify(action, configs)
        receipt["state"] = "SUCCEEDED"
        if action in ("install", "configure", "start", "restart", "upgrade"):
          if action == "upgrade" and materialized_digest != self.package_digest:
            receipt["lastUpgrade"] = {"fromDigest": materialized_digest, "toDigest": self.package_digest,
                                      "taskId": task, "data": "unchanged"}
            receipt["releaseHistory"] = (receipt.get("releaseHistory", []) + [receipt.get("materializedPackage", {})])[-10:]
          receipt["materializedPackage"] = dict(self.descriptor["package"])
          receipt["materializedPackageDigest"] = self.package_digest
          receipt["resourceLayout"] = self._release_layout()
        if action in ("stop", "uninstall", "purge"):
          if action == "stop" and receipt.get("pendingUnitHash") and self.unit_path.exists():
            # _owned accepted this exact interrupted publication before STOP.
            # Preserve its evidence after leaving UNKNOWN, without claiming the
            # candidate release is installed or safe to start.
            receipt["unitHash"] = _hash(self.unit_path.read_bytes())
            receipt.pop("pendingUnitHash", None)
          self._clear_runtime_secrets()
        if action in ("start", "restart", "reload"):
          receipt["runningConfigGeneration"] = plan["configGeneration"]
          receipt["runningProbe"] = self._probe_config(configs)
          receipt["runningPorts"] = self._declared_ports(configs)
        self._save(receipt)
        # Retention cleanup must not turn an already verified operation UNKNOWN.
        # A later successful task retries this bounded projection cleanup.
        if action not in ("detach", "adopt"):
          with contextlib.suppress(OSError):
            self._prune_configurations(receipt)
            self._prune_runtime_secrets(receipt)
            self._prune_releases(receipt)
        return {"state": "SUCCEEDED", "observation": observation,
                "publishedConfigGeneration": receipt.get("publishedConfigGeneration"),
                "runningConfigGeneration": receipt.get("runningConfigGeneration"),
                "taskId": task, "packageDigest": self.package_digest, "identity": self.identity,
                "materializedPackageDigest": receipt.get("materializedPackageDigest"),
                "retainedResources": receipt.get("retainedResources", []),
                "detached": receipt.get("detached", False),
                "purged": receipt.get("purged", False), "purgedResources": receipt.get("purgedResources", [])}
      except HostError as error:
        receipt["state"] = error.state
        self._save(receipt)
        raise
      except Exception as error:
        receipt["state"] = "UNKNOWN"
        self._save(receipt)
        raise HostError("OUTCOME_UNKNOWN", "Materialization requires recovery", "UNKNOWN") from error

  def _publish(self, configs, generation, receipt):
    self._load_secrets()
    if self.provision is None:
      raise HostError("CAPABILITY_UNSUPPORTED", "Ambari resource provisioner is required")
    self.provision(self.resources, self.directories, self.root)
    content = self._unit_content(configs, generation)
    self._stage(configs, generation)
    receipt["publicationDigest"] = None if self.secret_values else self._installed_file_digest(generation)
    # Save ownership evidence before publication, so a lost response never
    # adopts a name. The exclusive target lock protects these two writes.
    receipt["pendingUnitHash"] = _hash(content)
    self._save(receipt)
    _atomic(self.unit_path, content, 0o644)
    receipt["unitHash"] = receipt.pop("pendingUnitHash")
    self._save(receipt)
    self._native("daemon-reload")
    receipt["publishedConfigGeneration"] = generation
    self._save(receipt)

  def _uninstall(self, configs, receipt):
    # The receipt is retained even when no unit was ever published. It is
    # the only acceptable evidence for retrying a partial removal.
    if self.observe()["state"] != "inactive":
      self._native("stop")
    self.verify("stop", configs)
    self._owned(receipt)
    receipt["retainedResources"] = self._retained_resources()
    self._save(receipt)
    if self.unit_path.exists():
      self.unit_path.unlink()
      directory = os.open(str(self.unit_path.parent), os.O_RDONLY | os.O_DIRECTORY)
      try:
        os.fsync(directory)
      finally:
        os.close(directory)
    self._native("daemon-reload")

  def _generation(self, configs):
    generations = (self.task_binding or {}).get("secretGenerations", {})
    return _json_hash({"config": configs, "secretGenerations": generations}) if generations else _json_hash(configs)

  def _load_secrets(self):
    self.secret_values.clear()
    if self.command.get("mpackSecretError"):
      code = "PLAN_STALE" if self.command["mpackSecretError"] == "PLAN_STALE" else "DEPENDENCY_UNRESOLVED"
      raise HostError(code, "Scoped credential material is unavailable or superseded")
    generations = (self.task_binding or {}).get("secretGenerations", {})
    if not generations:
      return
    from resource_management.core.encryption import ensure_decrypted, V2_PREFIX
    material = self.command.get("mpackSecretMaterial", {})
    if len(generations) > 32 or set(material) != set(generations):
      raise HostError("DEPENDENCY_UNRESOLVED", "Credential transport does not match the persisted references")
    for reference, generation in generations.items():
      try:
        encrypted = material[reference]
        if not encrypted.startswith(V2_PREFIX):
          raise ValueError()
        value = json.loads(ensure_decrypted(encrypted))
        if value.get("reference") != reference or value.get("generation") != generation:
          raise ValueError()
        secret = value["value"]
        if not isinstance(secret, str) or not secret or len(secret) > 8192 or any(char in secret for char in ("\n", "\r", "\0")):
          raise ValueError()
        self.secret_values[reference] = secret
      except Exception:
        raise HostError("DEPENDENCY_UNRESOLVED", "Credential transport could not be authenticated") from None

  def _runtime_file(self, generation, name, content, root_only=False):
    import pwd
    parent = self.runtime_root.parent
    if parent.is_symlink() or self.runtime_root.is_symlink():
      raise HostError("TARGET_CONFLICT", "Runtime secret path is not owned")
    parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if parent.stat().st_uid != 0 or parent.stat().st_mode & 0o022:
      raise HostError("TARGET_CONFLICT", "Runtime secret parent is not root controlled")
    self.runtime_root.mkdir(mode=0o711, exist_ok=True)
    directory = self.runtime_root / generation
    if directory.is_symlink():
      raise HostError("TARGET_CONFLICT", "Runtime generation path is not owned")
    directory.mkdir(mode=0o711, exist_ok=True)
    if any(path.stat().st_uid != 0 or path.stat().st_mode & 0o022 for path in (self.runtime_root, directory)):
      raise HostError("TARGET_CONFLICT", "Runtime secret directory is not root controlled")
    destination = directory / name
    _atomic(destination, content, 0o600)
    if not root_only:
      account = pwd.getpwnam(self.resources["unit"]["user"])
      os.chown(destination, account.pw_uid, account.pw_gid)

  def _prune_runtime_secrets(self, receipt):
    if not self.runtime_root.exists() or self.runtime_root.is_symlink():
      return
    protected = {"g-" + value for value in (receipt.get("publishedConfigGeneration"),
                 receipt.get("runningConfigGeneration")) if value}
    for path in self.runtime_root.iterdir():
      if path.name not in protected and re.fullmatch(r"g-[a-f0-9]{64}", path.name) and not path.is_symlink():
        shutil.rmtree(path)

  def _clear_runtime_secrets(self):
    if self.runtime_root.is_symlink():
      raise HostError("TARGET_CONFLICT", "Runtime secret directory was replaced")
    if self.runtime_root.exists():
      if self.runtime_root.stat().st_uid != 0 or self.runtime_root.stat().st_mode & 0o022:
        raise HostError("TARGET_CONFLICT", "Runtime secret directory is not root controlled")
      shutil.rmtree(self.runtime_root)
    self.secret_values.clear()

  def _validate_retained_paths(self, receipt):
    allowed = {str(self.root), *(str(path) for path in self.directories.values())}
    seen = set()
    for resource in receipt["retainedResources"]:
      if resource.get("path") not in allowed or resource["path"] in seen:
        raise HostError("TARGET_CONFLICT", "Retained path differs from the installed descriptor")
      seen.add(resource["path"])
      path = Path(resource["path"])
      try:
        info = path.lstat()
      except FileNotFoundError as error:
        if receipt.get("operation") == "purge" and path != self.root:
          continue  # A previous purge may already have removed this exact owned directory.
        raise HostError("TARGET_CONFLICT", "Retained resource disappeared before purge") from error
      except OSError as error:
        raise HostError("TARGET_CONFLICT", "Retained resource cannot be inspected") from error
      if path.is_symlink() or info.st_dev != resource.get("device") or info.st_ino != resource.get("inode"):
        raise HostError("TARGET_CONFLICT", "Retained resource identity changed before purge")
    if not any(item.get("path") == str(self.root) for item in receipt["retainedResources"]):
      raise HostError("TARGET_CONFLICT", "Retained root identity is missing")

  def _purge_files(self):
    # systemd/v1 is Linux-only. Bind mounts can share st_dev, so also consult mountinfo.
    with open("/proc/self/mountinfo", "rb") as mounts:
      data = mounts.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024:
      raise HostError("TARGET_CONFLICT", "Mount inventory exceeds purge limits")
    for line in data.decode("utf-8", errors="strict").splitlines():
      fields = line.split()
      if len(fields) < 6:
        raise HostError("TARGET_CONFLICT", "Mount inventory is invalid")
      mounted = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4])
      if mounted == str(self.root) or mounted.startswith(str(self.root) + "/"):
        raise HostError("TARGET_CONFLICT", "Purge cannot cross a nested mount")
    deadline = time.monotonic() + 30
    remaining = [100000]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(self.root, flags)
    device = os.fstat(descriptor).st_dev
    def remove(parent, depth):
      if depth > 64:
        raise HostError("OUTCOME_UNKNOWN", "Purge depth limit reached", "UNKNOWN")
      with os.scandir(parent) as entries:
        for entry in entries:
          if depth == 0 and entry.name in ("receipt.json", "operation.lock"):
            continue
          remaining[0] -= 1
          if remaining[0] < 0 or time.monotonic() >= deadline or self.cancel is not None and self.cancel.is_set():
            raise HostError("OUTCOME_UNKNOWN", "Purge paused at its bound; inspect and resume", "UNKNOWN")
          if entry.is_dir(follow_symlinks=False):
            child = os.open(entry.name, flags, dir_fd=parent)
            try:
              if os.fstat(child).st_dev != device:
                raise HostError("TARGET_CONFLICT", "Purge cannot cross filesystems")
              remove(child, depth + 1)
            finally:
              os.close(child)
            os.rmdir(entry.name, dir_fd=parent)
          else:
            # Symlinks themselves are removed; their destinations are never followed.
            os.unlink(entry.name, dir_fd=parent)
      os.fsync(parent)
    try:
      remove(descriptor, 0)
    finally:
      os.close(descriptor)

  def _retained_resources(self):
    # Keep config and receipt evidence together with all declared directories.
    # Never remove shared OS packages/users, or traverse user-controlled data.
    result = []
    for path in [self.root] + list(self.directories.values()):
      if path.is_symlink():
        raise HostError("TARGET_CONFLICT", "Retained resource identity is a symlink")
      if path.exists():
        state = path.stat()
        result.append({"path": str(path), "device": state.st_dev, "inode": state.st_ino,
                       "ownership": "managed", "retention": "retain"})
    return result

  def _prune_configurations(self, receipt):
    config_root = self.root / "config"
    if not config_root.exists():
      return
    protected = {"g-" + value for value in (receipt.get("publishedConfigGeneration"),
                 receipt.get("runningConfigGeneration")) if value}
    histories = sorted((path for path in config_root.iterdir()
      if re.fullmatch(r"g-[a-f0-9]{64}", path.name) and path.is_dir() and not path.is_symlink()),
      key=lambda path: path.stat().st_mtime, reverse=True)
    for path in histories[10:]:
      if path.name not in protected:
        # These are compiler-generated config generations, never data directories.
        shutil.rmtree(path)

  def _prune_releases(self, receipt):
    release_root = self.root / "releases"
    if not release_root.exists():
      return
    protected = {self.package_digest, receipt.get("materializedPackageDigest"),
                 receipt.get("runningPackageDigest")}
    protected.update(release.get("digest") for release in receipt.get("releaseHistory", []))
    for path in release_root.iterdir():
      if (re.fullmatch(r"[a-f0-9]{64}", path.name) and path.name not in protected
          and path.is_dir() and not path.is_symlink()):
        # Only root-owned, compiler-staged artifacts; never declared data paths.
        shutil.rmtree(path)
