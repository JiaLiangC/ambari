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
  """Forward to an injected shared-platform client; never manufacture authority.

  The client owns authentication, approval, persistence, incarnation, revision,
  operation epoch and readiness. There is deliberately no default local backend.
  Test doubles must be supplied explicitly by fixtures.
  """

  protocol_version = "binding/v1"

  def __init__(self, client=None):
    self.client = client

  def _call(self, operation, *args, **kwargs):
    if self.client is None:
      raise RuntimeError("DEPENDENCY_UNRESOLVED: shared binding client is unavailable")
    if getattr(self.client, "protocol_version", None) != self.protocol_version:
      raise RuntimeError("CAPABILITY_UNSUPPORTED: shared binding protocol mismatch")
    return getattr(self.client, operation)(*args, **kwargs)

  def preview(self, requirement, provider, consumer):
    if not isinstance(requirement, DependencyRequirement) or not all(
        isinstance(value, ServiceRef) for value in (provider, consumer)):
      raise ValueError("Requirement and existing provider/consumer ServiceRefs are required")
    return self._call("preview", requirement, provider, consumer)

  def approve(self, preview, snapshot):
    return self._call("approve", preview, snapshot)

  def apply(self, snapshot, expected_revision):
    return self._call("apply", snapshot, expected_revision)

  def observe(self, snapshot):
    return self._call("observe", snapshot)

  def detach(self, snapshot):
    return self._call("detach", snapshot)

  def fence(self, snapshot, revision):
    return self._call("fence", snapshot, revision)
