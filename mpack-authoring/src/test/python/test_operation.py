"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

import unittest

from mpack_authoring.operation import plan_operation
from mpack_authoring.runtime import PackageRef, RuntimeContext, ServiceRef


class OperationPlanTest(unittest.TestCase):
  def context(self):
    capabilities = frozenset({"install", "observe"})
    return RuntimeContext(ServiceRef(3, "ECHO"), PackageRef("echo", "1", "a" * 64),
                          "linux", capabilities, capabilities, capabilities, capabilities)

  def test_plan_is_ordered_and_non_mutating(self):
    steps = plan_operation(self.context(), [{"action": "install"}, {"action": "observe"}])
    self.assertEqual(["step-1", "step-2"], [step.id for step in steps])
    self.assertEqual("service_ref_exists", steps[0].preconditions[0])
    self.assertEqual("install:requested", steps[0].effects[0])

  def test_plan_rejects_unsupported_capability(self):
    with self.assertRaisesRegex(ValueError, "Unsupported"):
      plan_operation(self.context(), [{"action": "delete"}])


if __name__ == "__main__":
  unittest.main()
