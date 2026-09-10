"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

import os
import tempfile
import unittest

from mpack_authoring.executor import CommandSpec, DryRunExecutor, InjectedExecutor
from mpack_authoring.journal import OperationJournal


class ExecutionTest(unittest.TestCase):
  def test_dry_run_never_executes(self):
    result = DryRunExecutor().run(CommandSpec("echo", ("hello",)), "key")
    self.assertEqual("PLANNED", result.state)
    self.assertEqual("echo hello", result.output)

  def test_injected_timeout_is_unknown(self):
    def timeout(_, __):
      raise TimeoutError("lost response")
    self.assertEqual("UNKNOWN", InjectedExecutor(timeout).run(CommandSpec("x"), "key").state)

  def test_journal_is_idempotent_and_recoverable(self):
    with tempfile.TemporaryDirectory() as root:
      journal = OperationJournal(os.path.join(root, "operations.json"))
      journal.record("op-1", "key", "RUNNING")
      self.assertEqual("RUNNING", journal.find("key")["state"])
      with self.assertRaises(ValueError):
        journal.record("op-2", "key", "RUNNING")


if __name__ == "__main__":
  unittest.main()
