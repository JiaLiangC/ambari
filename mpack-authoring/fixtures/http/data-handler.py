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

import hashlib
import json
import os
from pathlib import Path
import re
import sys


def digest(data):
  return hashlib.sha256(data).hexdigest()


def read(path):
  if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
    raise ValueError("Invalid data file")
  return path.read_bytes()


def atomic(path, data):
  pending = path.with_name(path.name + ".pending")
  descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
  with os.fdopen(descriptor, "wb") as stream:
    stream.write(data)
    stream.flush()
    os.fsync(stream.fileno())
  os.replace(pending, path)
  directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
  try:
    os.fsync(directory)
  finally:
    os.close(directory)


def procedure(request):
  key = request["operationKey"]
  if not re.fullmatch(r"[a-f0-9]{64}", key) or request["operation"] not in ("backup", "migrate", "restore"):
    raise ValueError("Invalid data operation")
  root = Path(request["directories"]["data"])
  history = root / ".mpack-history"
  if root.is_symlink() or history.is_symlink():
    raise ValueError("Invalid data directory")
  source = root / "records.json"
  journal = history / (key + ".intent.json")
  result = "UNKNOWN"
  evidence = "0" * 64
  if request["phase"] == "verify":
    value = json.loads(read(journal))
    if value["targetIdentity"] != request["targetIdentity"] or value["operation"] != request["operation"]:
      raise ValueError("Another data operation owns the evidence")
    target = history / (key + ".backup.json") if request["operation"] == "backup" else source
    if digest(read(target)) == value["outputDigest"]:
      result, evidence = "SUCCEEDED", digest(read(journal))
  else:
    original = read(source)
    document = json.loads(original)
    if document.get("version") not in (1, 2) or not isinstance(document.get("records"), list):
      raise ValueError("Unsupported HTTP example data format")
    evidence = digest(original)
    output = original
    if request["operation"] in ("migrate", "restore"):
      backup = request["configurations"]["http"].get("restore_backup", "")
      if not re.fullmatch(r"[a-f0-9]{64}", backup):
        raise ValueError("A verified backup operation key is required")
      snapshot = read(history / (backup + ".backup.json"))
      saved = json.loads(read(history / (backup + ".intent.json")))
      if saved["targetIdentity"] != request["targetIdentity"] or saved["operation"] != "backup" or digest(snapshot) != saved["outputDigest"]:
        raise ValueError("Backup identity or digest differs")
      if request["operation"] == "restore":
        output = snapshot
      else:
        if digest(snapshot) != evidence or document["version"] != 1:
          raise ValueError("Migration requires a current version-one backup")
        document["version"] = 2
        output = json.dumps(document, sort_keys=True).encode()
    if request["phase"] == "prepare":
      result = "READY"
    elif request["phase"] == "apply":
      if request["preconditionDigest"] != evidence:
        raise ValueError("Data changed after preparation")
      history.mkdir(mode=0o700, exist_ok=True)
      if len(list(history.iterdir())) >= 64 or journal.exists():
        raise ValueError("History capacity or operation conflict; inspect existing evidence")
      target = history / (key + ".backup.json") if request["operation"] == "backup" else source
      # Durable intent precedes the data write; verify can resolve lost responses.
      intent = {"targetIdentity": request["targetIdentity"], "operation": request["operation"], "outputDigest": digest(output)}
      atomic(journal, json.dumps(intent, sort_keys=True).encode())
      atomic(target, output)
      result, evidence = "SUCCEEDED", digest(read(journal))
    else:
      raise ValueError("Unsupported data operation phase")
  return {"protocol": "mpack.handler/v1", "phase": request["phase"], "operationKey": key,
    "targetIdentity": request["targetIdentity"], "result": result, "evidenceDigest": evidence}


if __name__ == "__main__":
  try:
    print(json.dumps(procedure(json.loads(sys.stdin.buffer.read(1024 * 1024 + 1)))))
  except Exception:
    sys.exit(1)
