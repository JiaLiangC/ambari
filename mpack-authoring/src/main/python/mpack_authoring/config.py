"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class SecretRef:
  name: str


@dataclass(frozen=True)
class ConfigValue:
  name: str
  value: object
  source: str
  generation: int
  sensitive: bool = False
  effect: str = "none"

  def redacted(self):
    if self.sensitive or isinstance(self.value, SecretRef):
      return "<secret-ref>"
    return self.value


def effective_config(values, generation):
  """Build an immutable effective configuration with provenance preserved."""
  result = {}
  for value in values:
    if not isinstance(value, ConfigValue):
      raise ValueError("Configuration values must be ConfigValue instances")
    if value.generation > generation:
      raise ValueError("Configuration generation is newer than requested state")
    if value.name in result:
      raise ValueError("Duplicate configuration field {}".format(value.name))
    result[value.name] = value
  return result
