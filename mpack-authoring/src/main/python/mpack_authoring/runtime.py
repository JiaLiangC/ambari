"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceRef:
  cluster_id: int
  service_name: str


@dataclass(frozen=True)
class PackageRef:
  name: str
  version: str
  digest: str


@dataclass(frozen=True)
class RuntimeContext:
  service: ServiceRef
  package: PackageRef
  profile_id: str
  package_capabilities: frozenset
  adapter_capabilities: frozenset
  target_capabilities: frozenset
  policy_capabilities: frozenset

  def effective_capabilities(self):
    return (self.package_capabilities & self.adapter_capabilities
            & self.target_capabilities & self.policy_capabilities)

  def unsupported(self, requested):
    return frozenset(requested) - self.effective_capabilities()

  def require(self, requested):
    unsupported = self.unsupported(requested)
    if unsupported:
      raise ValueError("Unsupported runtime capabilities: {}".format(
          ", ".join(sorted(unsupported))))
    return frozenset(requested)
