"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

import unittest

from mpack_authoring.diagnostics import make_diagnostic


class ExecutionDiagnosticsTest(unittest.TestCase):
  def test_runtime_codes_are_stable(self):
    diagnostic = make_diagnostic("OUTCOME_UNKNOWN", "remote response was lost", retryable=True)
    self.assertTrue(diagnostic.retryable)
    self.assertEqual("OUTCOME_UNKNOWN", diagnostic.code)


if __name__ == "__main__":
  unittest.main()
