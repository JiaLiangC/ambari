"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

import json
import os


class OperationJournal:
  """Append-only local journal for idempotent operation recovery."""

  def __init__(self, path):
    self.path = path

  def _read(self):
    if not os.path.exists(self.path):
      return {}
    with open(self.path, "r", encoding="utf-8") as stream:
      return json.load(stream)

  def record(self, operation_id, idempotency_key, state, payload=None):
    entries = self._read()
    existing = entries.get(idempotency_key)
    if existing is not None and existing["operationId"] != operation_id:
      raise ValueError("Idempotency key belongs to another operation")
    entries[idempotency_key] = {"operationId": operation_id, "state": state,
                                "payload": payload or {}}
    os.makedirs(os.path.dirname(os.path.realpath(self.path)), exist_ok=True)
    temporary = self.path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as stream:
      json.dump(entries, stream, sort_keys=True, indent=2)
      stream.write("\n")
    os.replace(temporary, self.path)
    return entries[idempotency_key]

  def find(self, idempotency_key):
    return self._read().get(idempotency_key)
