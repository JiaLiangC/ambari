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

import unittest

from mpack_authoring.config import ConfigValue, SecretRef, effective_config
from mpack_authoring.dependency import (BindingSnapshot, DependencyAdapter,
                                         DependencyRequirement)
from mpack_authoring.profiles import profile_capabilities
from mpack_authoring.runtime import ServiceRef


class ContractTest(unittest.TestCase):
  def test_secret_values_are_redacted_and_provenance_is_retained(self):
    value = ConfigValue("password", SecretRef("db-password"), "user", 4, True)
    effective = effective_config([value], 4)
    self.assertEqual("user", effective["password"].source)
    self.assertEqual("<secret-ref>", effective["password"].redacted())

  def test_dependency_adapter_requires_shared_authority(self):
    adapter = DependencyAdapter()
    with self.assertRaisesRegex(RuntimeError, "DEPENDENCY_UNRESOLVED"):
      adapter.preview(DependencyRequirement("database", "jdbc", ">=1"),
                      ServiceRef(9, "DATABASE"), ServiceRef(10, "CLIENT"))
    with self.assertRaisesRegex(RuntimeError, "DEPENDENCY_UNRESOLVED"):
      adapter.apply(object(), 3)

  def test_dependency_adapter_preserves_provider_results(self):
    from unittest.mock import Mock
    client = Mock(protocol_version="binding/v1")
    client.observe.return_value = {"state": "UNKNOWN", "epoch": 17}
    client.apply.side_effect = PermissionError("AUTHORIZATION_DENIED")
    adapter = DependencyAdapter(client)
    snapshot = object()
    self.assertEqual({"state": "UNKNOWN", "epoch": 17}, adapter.observe(snapshot))
    with self.assertRaises(PermissionError):
      adapter.apply(snapshot, 3)
    client.apply.assert_called_once_with(snapshot, 3)

  def test_external_profile_is_observation_only(self):
    self.assertEqual(frozenset({"observe"}), profile_capabilities("external.database/v1"))


if __name__ == "__main__":
  unittest.main()
