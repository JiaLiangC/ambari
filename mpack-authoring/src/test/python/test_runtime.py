"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

import unittest

from mpack_authoring.runtime import PackageRef, RuntimeContext, ServiceRef


class RuntimeContextTest(unittest.TestCase):
  def context(self):
    return RuntimeContext(
      ServiceRef(12, "ECHO"), PackageRef("echo", "1.0.0", "a" * 64), "linux",
      frozenset({"install", "observe"}), frozenset({"install", "observe"}),
      frozenset({"observe"}), frozenset({"observe"}))

  def test_intersection_preserves_authoritative_service_ref(self):
    context = self.context()
    self.assertEqual(frozenset({"observe"}), context.effective_capabilities())
    self.assertEqual((12, "ECHO"), (context.service.cluster_id, context.service.service_name))

  def test_require_reports_unsupported_capability(self):
    with self.assertRaisesRegex(ValueError, "install"):
      self.context().require({"install"})


if __name__ == "__main__":
  unittest.main()
