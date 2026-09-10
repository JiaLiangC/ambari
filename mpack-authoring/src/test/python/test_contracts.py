"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

import unittest

from mpack_authoring.config import ConfigValue, SecretRef, effective_config
from mpack_authoring.dependency import (BindingSnapshot, DependencyAdapter,
                                         DependencyRequirement)
from mpack_authoring.profiles import profile_capabilities
from mpack_authoring.recovery import OperationRecord
from mpack_authoring.runtime import ServiceRef


class ContractTest(unittest.TestCase):
  def test_secret_values_are_redacted_and_provenance_is_retained(self):
    value = ConfigValue("password", SecretRef("db-password"), "user", 4, True)
    effective = effective_config([value], 4)
    self.assertEqual("user", effective["password"].source)
    self.assertEqual("<secret-ref>", effective["password"].redacted())

  def test_dependency_adapter_requires_current_service_ref(self):
    adapter = DependencyAdapter()
    requirement = DependencyRequirement("database", "jdbc", ">=1")
    provider = ServiceRef(9, "DATABASE")
    preview = adapter.preview(requirement, provider)
    snapshot = BindingSnapshot(preview["bindingId"], provider, 3,
                               {"url": "redacted"}, authorized=True)
    self.assertEqual(snapshot, adapter.approve(preview, snapshot))

  def test_dependency_adapter_enforces_revision_and_fencing(self):
    adapter = DependencyAdapter()
    provider = ServiceRef(9, "DATABASE")
    requirement = DependencyRequirement("database", "jdbc", ">=1")
    preview = adapter.preview(requirement, provider)
    snapshot = BindingSnapshot(preview["bindingId"], provider, 3, {}, authorized=True)
    envelope = adapter.apply(snapshot, 3)
    self.assertEqual(4, envelope["fence"])
    with self.assertRaisesRegex(RuntimeError, "TARGET_CONFLICT"):
      adapter.apply(snapshot, 2)
    self.assertEqual("FENCED", adapter.fence(snapshot, 4)["state"])

  def test_recovery_requires_real_state_transition(self):
    record = OperationRecord("op-1", 2, "PENDING", "key-1")
    self.assertEqual("RUNNING", record.transition("RUNNING").state)
    with self.assertRaises(ValueError):
      record.transition("SUCCEEDED")

  def test_external_profile_is_observation_only(self):
    self.assertEqual(frozenset({"observe"}), profile_capabilities("external.database/v1"))


if __name__ == "__main__":
  unittest.main()
