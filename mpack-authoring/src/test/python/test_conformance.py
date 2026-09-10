"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

import os
import unittest

from mpack_authoring.conformance import validate_fixture_directory


class ConformanceTest(unittest.TestCase):
  def test_reference_fixtures_are_valid(self):
    directory = os.path.join(os.path.dirname(__file__), "..", "..", "..", "fixtures", "conformance")
    summaries = validate_fixture_directory(os.path.realpath(directory))
    self.assertEqual(5, len(summaries))
    self.assertTrue(all(item["valid"] for item in summaries))


if __name__ == "__main__":
  unittest.main()
