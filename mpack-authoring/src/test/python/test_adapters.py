"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

import unittest

from mpack_authoring.adapters import ExternalDatabaseAdapter, HostSystemdAdapter
from mpack_authoring.runtime import PackageRef, RuntimeContext, ServiceRef


class AdapterTest(unittest.TestCase):
  def test_host_adapter_describes_without_mutation(self):
    adapter = HostSystemdAdapter()
    self.assertFalse(adapter.describe()["mutating"])
    capabilities = frozenset(adapter.describe()["capabilities"])
    context = RuntimeContext(ServiceRef(1, "ECHO"), PackageRef("echo", "1", "a" * 64),
                             adapter.profile, capabilities, capabilities, capabilities, capabilities)
    self.assertEqual("install", adapter.plan(context, [{"action": "install"}])[0].capability)

  def test_external_database_is_observation_only(self):
    self.assertEqual(["observe"], ExternalDatabaseAdapter().describe()["capabilities"])


if __name__ == "__main__":
  unittest.main()
