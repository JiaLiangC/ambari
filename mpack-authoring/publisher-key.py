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

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys


def main(argv=None):
  parser = argparse.ArgumentParser(description="Create an external Ed25519 publisher key and public trust entry")
  parser.add_argument("--publisher", required=True)
  parser.add_argument("--private-key", required=True)
  parser.add_argument("--trust-entry", required=True)
  args = parser.parse_args(argv)
  try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", args.publisher):
      raise ValueError()
    private_path = Path(args.private_key).resolve()
    trust_path = Path(args.trust_entry).resolve()
    repository = Path(__file__).resolve().parent.parent
    if private_path == trust_path or repository in private_path.parents or private_path.exists() or trust_path.exists():
      raise ValueError()
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_id = hashlib.sha256(public).hexdigest()
    entry = {"version": 1, "publishers": {args.publisher: {"keys": {
      key_id: {"publicKey": base64.b64encode(public).decode("ascii"), "status": "active"}
    }}}}
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
      output.write(private)
      output.flush()
      os.fsync(output.fileno())
    with trust_path.open("x") as output:
      json.dump(entry, output, indent=2, sort_keys=True)
      output.write("\n")
    print(json.dumps({"publisher": args.publisher, "keyId": key_id, "created": True}))
    return 0
  except (ImportError, OSError, ValueError):
    print("Publisher key creation failed. Install authoring requirements and use new external output paths.", file=sys.stderr)
    return 2


if __name__ == "__main__":
  sys.exit(main())
