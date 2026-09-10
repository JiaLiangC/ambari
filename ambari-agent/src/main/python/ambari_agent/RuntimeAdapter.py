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

"""Runtime adapter dispatch for V2 execution commands.

The server supplies a JSON runtime context through commandParams.  This module
keeps the adapter boundary explicit while using the agent's existing command
status and cancellation path.  Adapters never infer an Ambari identity: the
cluster/service/component references are carried through every operation.
"""

import json
import logging
import os
import subprocess
import time


logger = logging.getLogger(__name__)


class RuntimeAdapterError(Exception):
  def __init__(self, code, message, retryable=False, state="FAILED"):
    super().__init__(message)
    self.code = code
    self.retryable = retryable
    self.state = state


class RuntimeTarget:
  def __init__(self, context):
    if not isinstance(context, dict):
      raise RuntimeAdapterError("SCHEMA_INVALID", "runtime_context must be an object")
    self.cluster_id = context.get("clusterId")
    self.service_name = context.get("serviceName")
    self.component_name = context.get("componentName")
    self.profile = context.get("profile")
    self.package_digest = context.get("packageDigest")
    self.operation_id = context.get("operationId")
    self.idempotency_key = context.get("idempotencyKey")
    self.desired_revision = context.get("desiredRevision")
    self.observed_revision = context.get("observedRevision")
    self.parameters = context.get("parameters") or {}
    if self.cluster_id is None or not self.service_name or not self.component_name:
      raise RuntimeAdapterError(
        "SCHEMA_INVALID",
        "runtime_context requires clusterId, serviceName and componentName",
      )
    if not self.profile:
      raise RuntimeAdapterError("SCHEMA_INVALID", "runtime_context requires profile")
    if not self.operation_id or not self.idempotency_key:
      raise RuntimeAdapterError(
        "SCHEMA_INVALID", "runtime_context requires operationId and idempotencyKey"
      )
    if not isinstance(self.parameters, dict):
      raise RuntimeAdapterError("SCHEMA_INVALID", "runtime_context parameters must be an object")

  def identity(self):
    return {
      "clusterId": self.cluster_id,
      "serviceName": self.service_name,
      "componentName": self.component_name,
    }


class RuntimeAdapter:
  profile = ""
  capabilities = frozenset()

  def describe(self, target):
    return {
      "profile": self.profile,
      "contractVersion": "runtime-adapter/v1",
      "capabilities": sorted(self.capabilities),
      "identity": target.identity(),
    }

  def discover(self, target):
    result = self.describe(target)
    result["observedRevision"] = target.observed_revision
    result["target"] = self._target_facts(target)
    return result

  def plan(self, target, operation):
    if operation not in self.capabilities:
      raise RuntimeAdapterError(
        "CAPABILITY_UNSUPPORTED",
        "{} does not support {}".format(self.profile, operation),
      )
    if target.desired_revision is not None and target.observed_revision is not None:
      if str(target.desired_revision) != str(target.observed_revision) and operation in {
        "configure", "start", "stop", "install"
      }:
        raise RuntimeAdapterError(
          "PLAN_STALE",
          "desired and observed revisions differ",
          retryable=True,
        )
    return {
      "operationId": target.operation_id,
      "idempotencyKey": target.idempotency_key,
      "profile": self.profile,
      "identity": target.identity(),
      "operation": operation,
      "steps": self._steps(target, operation),
    }

  def apply(self, target, operation, cancel_event):
    raise RuntimeAdapterError(
      "CAPABILITY_UNSUPPORTED",
      "{} does not provide mutation for {}".format(self.profile, operation),
    )

  def observe(self, target):
    return {"state": "UNKNOWN", "identity": target.identity()}

  def verify(self, target, operation, observation):
    return {
      "verified": observation.get("state") not in {"UNKNOWN", "ERROR"},
      "operation": operation,
      "observation": observation,
    }

  def recover(self, target, operation, cancel_event):
    return self.apply(target, "recover", cancel_event)

  def _steps(self, target, operation):
    return [{"id": "{}-1".format(operation), "action": operation,
             "identity": target.identity()}]

  def _target_facts(self, target):
    return {"profile": self.profile, "parameters": _redact(target.parameters)}


class CommandRuntimeAdapter(RuntimeAdapter):
  command_names = {}

  def apply(self, target, operation, cancel_event):
    argv = self._command(target, operation)
    if not argv:
      raise RuntimeAdapterError(
        "CAPABILITY_UNSUPPORTED",
        "No command configured for {}".format(operation),
      )
    return _run_argv(argv, target, cancel_event)

  def observe(self, target):
    argv = self._command(target, "observe")
    if not argv:
      return {"state": "UNKNOWN", "identity": target.identity()}
    try:
      result = _run_argv(argv, target, None)
      return {"state": "HEALTHY" if result["exitcode"] == 0 else "ERROR",
              "identity": target.identity(), "stdout": result["stdout"],
              "stderr": result["stderr"], "exitcode": result["exitcode"]}
    except RuntimeAdapterError as error:
      return {"state": error.state, "code": error.code,
              "message": str(error), "identity": target.identity()}

  def _command(self, target, operation):
    configured = target.parameters.get("commands") or {}
    command = configured.get(operation, self.command_names.get(operation))
    if command is None:
      return None
    if isinstance(command, str):
      raise RuntimeAdapterError("SCHEMA_INVALID", "runtime commands must be argv arrays")
    if not isinstance(command, (list, tuple)) or not command:
      raise RuntimeAdapterError("SCHEMA_INVALID", "runtime command must be a non-empty argv array")
    if not all(isinstance(part, str) and part for part in command):
      raise RuntimeAdapterError("SCHEMA_INVALID", "runtime command arguments must be strings")
    return list(command)


class HostSystemdAdapter(CommandRuntimeAdapter):
  profile = "host.systemd/v1"
  capabilities = frozenset({"install", "configure", "start", "stop", "observe", "recover"})

  def _command(self, target, operation):
    configured = super()._command(target, operation)
    if configured:
      return configured
    unit = target.parameters.get("unit")
    if not unit or not isinstance(unit, str) or "/" in unit or ".." in unit:
      return None
    if operation in {"start", "stop", "observe", "recover"}:
      action = "is-active" if operation == "observe" else ("restart" if operation == "recover" else operation)
      return ["systemctl", action, unit]
    return None


class OciContainerAdapter(CommandRuntimeAdapter):
  profile = "oci.container/v1"
  capabilities = frozenset({"install", "configure", "start", "stop", "observe", "recover"})

  def _command(self, target, operation):
    configured = super()._command(target, operation)
    if configured:
      return configured
    name = target.parameters.get("container")
    engine = target.parameters.get("engine", "podman")
    if not name or not isinstance(name, str) or not isinstance(engine, str):
      return None
    if operation in {"start", "stop", "observe", "recover"}:
      action = "inspect" if operation == "observe" else ("restart" if operation == "recover" else operation)
      return [engine, action, name]
    return None


class KubernetesWorkloadAdapter(CommandRuntimeAdapter):
  profile = "kubernetes.workload/v1"
  capabilities = frozenset({"install", "configure", "start", "stop", "observe", "recover"})

  def _command(self, target, operation):
    configured = super()._command(target, operation)
    if configured:
      return configured
    name = target.parameters.get("name")
    namespace = target.parameters.get("namespace", "default")
    if not name or not isinstance(name, str) or not isinstance(namespace, str):
      return None
    if operation in {"start", "stop", "observe", "recover"}:
      if operation == "observe":
        return ["kubectl", "get", "deployment", name, "--namespace", namespace]
      replicas = "0" if operation == "stop" else target.parameters.get("replicas", "1")
      return ["kubectl", "scale", "deployment", name, "--replicas", str(replicas),
              "--namespace", namespace]
    return None


class ExternalDatabaseAdapter(CommandRuntimeAdapter):
  profile = "external.database/v1"
  capabilities = frozenset({"observe"})


ADAPTERS = {
  HostSystemdAdapter.profile: HostSystemdAdapter(),
  OciContainerAdapter.profile: OciContainerAdapter(),
  KubernetesWorkloadAdapter.profile: KubernetesWorkloadAdapter(),
  ExternalDatabaseAdapter.profile: ExternalDatabaseAdapter(),
}


class RuntimeAdapterExecutor:
  """Translate one V2 command into discover/plan/apply/observe/verify."""

  def execute(self, command, cancel_event=None):
    params = command.get("commandParams") or {}
    profile = params.get("runtime_profile")
    operation = params.get("runtime_operation")
    if not profile and not operation:
      return None
    if not profile or not operation:
      return _failure("SCHEMA_INVALID", "runtime_profile and runtime_operation are required")
    adapter = ADAPTERS.get(profile)
    if adapter is None:
      return _failure("CAPABILITY_UNSUPPORTED", "Unknown runtime profile {}".format(profile))
    try:
      context = json.loads(params.get("runtime_context", "{}"))
      # Preserve the authoritative Ambari command identity when callers only
      # provide adapter-specific fields. Explicit context values win.
      context.setdefault("clusterId", command.get("clusterId"))
      context.setdefault("serviceName", command.get("serviceName"))
      context.setdefault("componentName", command.get("role"))
      context.setdefault("operationId", params.get("runtime_operation_id") or
                         str(command.get("taskId")))
      context.setdefault("idempotencyKey", params.get("runtime_idempotency_key") or
                         "ambari:{}:{}".format(command.get("clusterId"), command.get("taskId")))
      target = RuntimeTarget(context)
      discovery = adapter.discover(target)
      if operation == "discover":
        return _success({"state": "DISCOVERED", "discovery": discovery})
      plan = adapter.plan(target, operation)
      if operation == "observe":
        observation = adapter.observe(target)
        verification = adapter.verify(target, operation, observation)
        return _result_from_observation(discovery, plan, observation, verification)
      if operation == "recover":
        applied = adapter.recover(target, operation, cancel_event)
      else:
        applied = adapter.apply(target, operation, cancel_event)
      observation = adapter.observe(target)
      verification = adapter.verify(target, operation, observation)
      state = "SUCCEEDED" if verification.get("verified") and applied["exitcode"] == 0 else "FAILED"
      return _success({"state": state, "discovery": discovery, "plan": plan,
                       "apply": applied, "observation": observation,
                       "verification": verification}, exitcode=0 if state == "SUCCEEDED" else 1)
    except RuntimeAdapterError as error:
      return _failure(error.code, str(error), error.retryable, error.state)
    except (ValueError, TypeError, json.JSONDecodeError) as error:
      return _failure("SCHEMA_INVALID", str(error))


def _run_argv(argv, target, cancel_event):
  env = os.environ.copy()
  env["AMBARI_CLUSTER_ID"] = str(target.cluster_id)
  env["AMBARI_SERVICE_NAME"] = target.service_name
  env["AMBARI_COMPONENT_NAME"] = target.component_name
  env["AMBARI_OPERATION_ID"] = target.operation_id
  env["AMBARI_IDEMPOTENCY_KEY"] = target.idempotency_key
  try:
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, env=env)
  except OSError as error:
    raise RuntimeAdapterError("TARGET_CONFLICT", str(error), retryable=True)
  while process.poll() is None:
    if cancel_event is not None and cancel_event.is_set():
      process.terminate()
      try:
        process.wait(timeout=5)
      except subprocess.TimeoutExpired:
        process.kill()
      raise RuntimeAdapterError("OUTCOME_UNKNOWN", "Runtime command canceled", retryable=True,
                                state="UNKNOWN")
    time.sleep(0.05)
  stdout, stderr = process.communicate()
  return {"exitcode": process.returncode, "stdout": stdout or "", "stderr": stderr or ""}


def _redact(value):
  if not isinstance(value, dict):
    return value
  return {key: "[PROTECTED]" if any(token in key.lower() for token in
          ("password", "secret", "token", "credential")) else item
          for key, item in value.items()}


def _success(payload, exitcode=0):
  return {"exitcode": exitcode, "stdout": json.dumps(payload, sort_keys=True),
          "stderr": "", "structuredOut": payload, "runtimeState": payload.get("state")}


def _failure(code, message, retryable=False, state="FAILED"):
  payload = {"state": state, "code": code, "message": message,
             "retryable": retryable}
  return {"exitcode": 1, "stdout": "", "stderr": message,
          "structuredOut": payload, "runtimeState": state}


def _result_from_observation(discovery, plan, observation, verification):
  state = "SUCCEEDED" if verification.get("verified") else observation.get("state", "UNKNOWN")
  return _success({"state": state, "discovery": discovery, "plan": plan,
                   "observation": observation, "verification": verification},
                  exitcode=0 if state == "SUCCEEDED" else 1)
