"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

from dataclasses import dataclass
import uuid

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
  authorized: bool = False
  incarnation: str = ""
  fenced: bool = False

  def __post_init__(self):
    if not isinstance(self.binding_id, str) or not self.binding_id.strip():
      raise ValueError("binding_id must be a non-empty UUID")
    try:
      uuid.UUID(self.binding_id)
    except ValueError as error:
      raise ValueError("binding_id must be a UUID") from error
    if not isinstance(self.provider, ServiceRef):
      raise ValueError("provider must use the current ServiceRef identity")
    if not isinstance(self.revision, int) or self.revision < 0:
      raise ValueError("binding revision must be a non-negative integer")
    if not isinstance(self.values, dict):
      raise ValueError("binding values must be an object")
    if self.incarnation and not isinstance(self.incarnation, str):
      raise ValueError("binding incarnation must be a string")

  def as_dict(self):
    return {"bindingId": self.binding_id,
            "provider": {"clusterId": self.provider.cluster_id,
                          "serviceName": self.provider.service_name},
            "revision": self.revision,
            "values": dict(self.values),
            "authorized": self.authorized,
            "incarnation": self.incarnation,
            "fenced": self.fenced}


class DependencyAdapter:
  """Versioned boundary for shared-platform dependency binding."""

  protocol_version = "binding/v1"

  def __init__(self, authorizer=None):
    self.authorizer = authorizer

  def preview(self, requirement, provider):
    if not isinstance(requirement, DependencyRequirement):
      raise ValueError("Invalid dependency requirement")
    if not isinstance(provider, ServiceRef):
      raise ValueError("Provider must use the current ServiceRef identity")
    return {"protocol": self.protocol_version, "slot": requirement.slot,
            "provider": {"clusterId": provider.cluster_id,
                         "serviceName": provider.service_name},
            "bindingId": str(uuid.uuid4()), "expectedRevision": None}

  def approve(self, preview, snapshot, authorization=None):
    if preview.get("protocol") != self.protocol_version:
      raise ValueError("Unsupported dependency binding protocol")
    if not isinstance(snapshot, BindingSnapshot):
      raise ValueError("A reviewed binding snapshot is required")
    if preview.get("bindingId") != snapshot.binding_id:
      raise ValueError("Binding snapshot UUID does not match the preview")
    if preview.get("provider") != {"clusterId": snapshot.provider.cluster_id,
                                   "serviceName": snapshot.provider.service_name}:
      raise ValueError("Binding provider does not match the preview")
    if self.authorizer is not None and not self.authorizer(preview, authorization):
      raise PermissionError("AUTHORIZATION_DENIED")
    if not snapshot.authorized and authorization is not True:
      raise PermissionError("AUTHORIZATION_DENIED")
    return snapshot

  def apply(self, snapshot, expected_revision, authorization=True):
    """Return a fenced mutation envelope without changing provider state."""
    if not isinstance(snapshot, BindingSnapshot) or snapshot.fenced:
      raise ValueError("A live binding snapshot is required")
    if not authorization:
      raise PermissionError("AUTHORIZATION_DENIED")
    if expected_revision is not None and expected_revision != snapshot.revision:
      raise RuntimeError("TARGET_CONFLICT")
    return {"protocol": self.protocol_version, "bindingId": snapshot.binding_id,
            "incarnation": snapshot.incarnation or snapshot.binding_id,
            "expectedRevision": snapshot.revision, "fence": snapshot.revision + 1}

  def observe(self, snapshot):
    if not isinstance(snapshot, BindingSnapshot):
      raise ValueError("A binding snapshot is required")
    return {"bindingId": snapshot.binding_id, "revision": snapshot.revision,
            "incarnation": snapshot.incarnation or snapshot.binding_id,
            "state": "FENCED" if snapshot.fenced else "READY"}

  def detach(self, snapshot):
    if not isinstance(snapshot, BindingSnapshot):
      raise ValueError("A binding snapshot is required")
    return {"bindingId": snapshot.binding_id, "revision": snapshot.revision,
            "incarnation": snapshot.incarnation or snapshot.binding_id,
            "state": "DETACH_REQUESTED", "fence": snapshot.revision + 1}

  def fence(self, snapshot, revision):
    if not isinstance(snapshot, BindingSnapshot):
      raise ValueError("A binding snapshot is required")
    if revision < snapshot.revision:
      raise RuntimeError("PLAN_STALE")
    return {"bindingId": snapshot.binding_id, "revision": revision,
            "state": "FENCED"}
