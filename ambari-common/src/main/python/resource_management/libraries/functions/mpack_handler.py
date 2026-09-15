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

"""Bounded transport for signed package code; no package-specific lifecycle logic."""

import contextlib
import json
import os
import pwd
import selectors
import signal
import subprocess
import time

from resource_management.libraries.functions.mpack_host import HostError, _hash, _json_hash


class PackageHandler:
  def __init__(self, deployment, declaration, user):
    self.deployment = deployment
    self.declaration = declaration
    try:
      self.account = pwd.getpwnam(user)
    except (KeyError, TypeError):
      raise HostError("DEPENDENCY_UNRESOLVED", "Package handler account is unavailable") from None
    if self.account.pw_uid == 0:
      raise HostError("CAPABILITY_UNSUPPORTED", "Package handlers cannot run as root")
    artifact = next((value for value in deployment.descriptor["artifacts"]
                     if value["id"] == declaration.get("artifactRef")), None)
    if artifact is None:
      raise HostError("SCHEMA_INVALID", "Package handler artifact is undeclared")
    self.path = deployment._source(artifact["path"])
    if not self.path.name.endswith(".py") or _hash(self.path.read_bytes()) != artifact["sha256"]:
      raise HostError("TARGET_CONFLICT", "Package handler artifact is invalid")
    for path in (self.path, *self.path.parents):
      info = path.stat()
      if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022 and not info.st_mode & 0o1000:
        raise HostError("TARGET_CONFLICT", "Package handler code is not root controlled")
    self.timeout = declaration.get("timeoutSeconds", 60)
    if type(self.timeout) is not int or not 1 <= self.timeout <= 300:
      raise HostError("SCHEMA_INVALID", "Package handler timeout is invalid")

  def call(self, phase, operation, key, configs, precondition=None):
    deployment = self.deployment
    target = _json_hash(deployment.identity)
    request = {"protocol": "mpack.handler/v1", "phase": phase, "operation": operation,
      "operationKey": key, "targetIdentity": target, "serviceRef": deployment.identity,
      "packageDigest": deployment.package_digest, "configurations": configs,
      "directories": {name: str(path) for name, path in deployment.directories.items()},
      "nativeIdentity": deployment.resources.get("nativeIdentity"), "preconditionDigest": precondition}
    data = json.dumps(request, sort_keys=True).encode()
    if len(data) > 1024 * 1024 or deployment.cancel is not None and deployment.cancel.is_set():
      raise HostError("OUTCOME_UNKNOWN", "Package handler request canceled or oversized", "UNKNOWN")
    # A private pipe carries context. No stdout/stderr is forwarded to task logs.
    try:
      process = subprocess.Popen(["/usr/bin/python3", "-I", str(self.path)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        user=self.account.pw_uid, group=self.account.pw_gid, extra_groups=[], cwd="/",
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": self.account.pw_dir})
    except OSError:
      raise HostError("CAPABILITY_UNSUPPORTED", "Package handler interpreter is unavailable") from None
    output = bytearray()
    emitted = 0
    position = 0
    deadline = time.monotonic() + self.timeout
    try:
      with selectors.DefaultSelector() as selector:
        for stream in (process.stdin, process.stdout, process.stderr):
          os.set_blocking(stream.fileno(), False)
          selector.register(stream, selectors.EVENT_WRITE if stream is process.stdin else selectors.EVENT_READ)
        while selector.get_map():
          if time.monotonic() >= deadline or deployment.cancel is not None and deployment.cancel.is_set():
            raise HostError("OUTCOME_UNKNOWN", "Package handler canceled or timed out; verify its durable result", "UNKNOWN")
          for event, _ in selector.select(0.1):
            stream = event.fileobj
            if stream is process.stdin:
              try:
                position += os.write(stream.fileno(), data[position:position + 4096])
              except BrokenPipeError:
                position = len(data)
              if position == len(data):
                selector.unregister(stream)
                stream.close()
            else:
              chunk = os.read(stream.fileno(), 8192)
              if not chunk:
                selector.unregister(stream)
                continue
              emitted += len(chunk)
              if emitted > 65536:
                raise HostError("OUTCOME_UNKNOWN", "Package handler output exceeded its bound", "UNKNOWN")
              if stream is process.stdout:
                output.extend(chunk)
      if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
        raise HostError("OUTCOME_UNKNOWN", "Package handler requires outcome verification", "UNKNOWN")
      result = json.loads(output)
      allowed = {"protocol", "phase", "operationKey", "targetIdentity", "result", "evidenceDigest", "nativeIdentity"}
      if (not isinstance(result, dict) or set(result) - allowed or result.get("protocol") != "mpack.handler/v1"
          or result.get("phase") != phase or result.get("operationKey") != key or result.get("targetIdentity") != target
          or result.get("result") not in ("READY", "SUCCEEDED", "UNKNOWN", "NOT_APPLIED")
          or not isinstance(result.get("evidenceDigest"), str) or len(result["evidenceDigest"]) != 64
          or any(char not in "0123456789abcdef" for char in result["evidenceDigest"])):
        raise ValueError()
      # Only bounded digest/result evidence crosses the task persistence boundary.
      return result
    except (ValueError, TypeError, OSError, subprocess.TimeoutExpired):
      raise HostError("OUTCOME_UNKNOWN", "Package handler returned no valid bound evidence", "UNKNOWN") from None
    finally:
      with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
      process.wait(timeout=5)
      for stream in (process.stdin, process.stdout, process.stderr):
        stream.close()
