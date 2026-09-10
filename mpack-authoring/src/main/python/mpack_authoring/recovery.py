"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class OperationRecord:
  operation_id: str
  generation: int
  state: str
  idempotency_key: str
  outcome: str = ""

  def transition(self, state, outcome=""):
    allowed = {
      "PENDING": {"RUNNING", "CANCELLED"},
      "RUNNING": {"VERIFYING", "FAILED", "CANCEL_REQUESTED", "UNKNOWN"},
      "VERIFYING": {"SUCCEEDED", "FAILED", "UNKNOWN"},
      "CANCEL_REQUESTED": {"CANCELLED", "UNKNOWN"},
      "UNKNOWN": {"RUNNING", "VERIFYING", "FAILED", "SUCCEEDED"},
      "FAILED": set(), "SUCCEEDED": set(), "CANCELLED": set(),
    }
    if state not in allowed.get(self.state, set()):
      raise ValueError("Invalid operation transition {} -> {}".format(self.state, state))
    return OperationRecord(self.operation_id, self.generation, state,
                           self.idempotency_key, outcome)
