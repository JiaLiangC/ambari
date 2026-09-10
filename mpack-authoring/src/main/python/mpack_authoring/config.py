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

  def __post_init__(self):
    if self.sensitive and not isinstance(self.value, SecretRef):
      raise ValueError("Sensitive configuration requires a secret reference")
    if self.effect not in {"none", "reload", "restart", "migration"}:
      raise ValueError("Unsupported configuration change effect")

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
