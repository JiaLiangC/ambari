"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

from dataclasses import dataclass

from .runtime import ServiceRef


@dataclass(frozen=True)
class DependencyRequirement:
  slot: str
  interface: str
  version_range: str


@dataclass(frozen=True)
class BindingSnapshot:
  binding_id: str
  provider: ServiceRef
  revision: int
  values: dict


class DependencyAdapter:
  """Versioned boundary for shared-platform dependency binding."""

  protocol_version = "binding/v1"

  def preview(self, requirement, provider):
    if not isinstance(requirement, DependencyRequirement):
      raise ValueError("Invalid dependency requirement")
    if not isinstance(provider, ServiceRef):
      raise ValueError("Provider must use the current ServiceRef identity")
    return {"protocol": self.protocol_version, "slot": requirement.slot,
            "provider": {"clusterId": provider.cluster_id,
                         "serviceName": provider.service_name}}

  def approve(self, preview, snapshot):
    if preview.get("protocol") != self.protocol_version:
      raise ValueError("Unsupported dependency binding protocol")
    if not isinstance(snapshot, BindingSnapshot):
      raise ValueError("A reviewed binding snapshot is required")
    return snapshot

  def detach(self, snapshot):
    if not isinstance(snapshot, BindingSnapshot):
      raise ValueError("A binding snapshot is required")
    return {"bindingId": snapshot.binding_id, "revision": snapshot.revision,
            "state": "DETACH_REQUESTED"}
