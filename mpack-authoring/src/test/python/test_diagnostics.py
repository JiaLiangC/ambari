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

from mpack_authoring.diagnostics import validate_with_diagnostics


class DiagnosticsTest(unittest.TestCase):
  def test_schema_failure_is_structured(self):
    result = validate_with_diagnostics({"apiVersion": "wrong"})
    self.assertFalse(result["valid"])
    self.assertEqual("SCHEMA_INVALID", result["diagnostics"][0]["code"])
    self.assertEqual("ERROR", result["diagnostics"][0]["severity"])
    self.assertFalse(result["diagnostics"][0]["retryable"])


if __name__ == "__main__":
  unittest.main()
