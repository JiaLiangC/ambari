"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

from .operation import plan_operation
from .runtime import RuntimeContext


class RuntimeAdapter:
  """Non-mutating adapter boundary used by offline plans."""

  profile = ""

  def describe(self):
    raise NotImplementedError

  def plan(self, context: RuntimeContext, requested_steps):
    if context.profile_id != self.profile:
      raise ValueError("Context profile does not match adapter")
    return plan_operation(context, requested_steps)


class HostSystemdAdapter(RuntimeAdapter):
  profile = "host.systemd/v1"

  def describe(self):
    return {"profile": self.profile, "mutating": False,
            "capabilities": ["install", "configure", "start", "stop", "observe"]}


class OciContainerAdapter(RuntimeAdapter):
  profile = "oci.container/v1"

  def describe(self):
    return {"profile": self.profile, "mutating": False,
            "capabilities": ["install", "configure", "start", "stop", "observe"]}


class KubernetesWorkloadAdapter(RuntimeAdapter):
  profile = "kubernetes.workload/v1"

  def describe(self):
    return {"profile": self.profile, "mutating": False,
            "capabilities": ["install", "configure", "start", "stop", "observe"]}


class ExternalDatabaseAdapter(RuntimeAdapter):
  profile = "external.database/v1"

  def describe(self):
    return {"profile": self.profile, "mutating": False, "capabilities": ["observe"]}
