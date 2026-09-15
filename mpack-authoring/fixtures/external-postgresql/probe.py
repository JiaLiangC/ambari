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
import re
import subprocess
import sys


def probe(request):
  # The OS account's administrator-managed libpq service file owns connection/TLS
  # and read-only credentials. Neither package config nor task input contains them.
  service = request["configurations"]["database"]["connection_service"]
  if request["phase"] not in ("discover", "observe") or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", service):
    raise ValueError("Invalid probe contract")
  query = ("SELECT system_identifier::text || '/' || "
    "(SELECT oid::text FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database()) "
    "FROM pg_catalog.pg_control_system()")
  completed = subprocess.run(["/usr/bin/psql", "--no-psqlrc", "--no-password", "--quiet", "--tuples-only", "--no-align",
    "--set", "ON_ERROR_STOP=1", "--dbname", "service=" + service, "--command", query],
    capture_output=True, text=True, timeout=10)
  identity = completed.stdout.strip()
  if completed.returncode or not re.fullmatch(r"[0-9]{1,20}/[0-9]{1,10}", identity):
    raise ValueError("Identity probe unavailable")
  return {"protocol": "mpack.handler/v1", "phase": request["phase"], "operationKey": request["operationKey"],
    "targetIdentity": request["targetIdentity"], "nativeIdentity": identity,
    "result": "SUCCEEDED", "evidenceDigest": hashlib.sha256(identity.encode()).hexdigest()}


if __name__ == "__main__":
  try:
    request = json.loads(sys.stdin.buffer.read(1024 * 1024 + 1))
    print(json.dumps(probe(request)))
  except Exception:
    # Driver diagnostics may contain connection details. Never forward them.
    sys.exit(1)
