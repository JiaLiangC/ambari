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

import base64
import hashlib
import json
import re

from .compiler import CompileError


def catalog_name(name, publisher=None):
  if publisher is None:
    if name.startswith("publisher-"):
      raise CompileError("The publisher catalog prefix requires a signed publisher identity")
    return name
  if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", publisher) or len(name) > 100:
    raise CompileError("Invalid publisher or package name")
  # Length-prefix the namespace to avoid ambiguous joins without changing ServiceRef.
  return "publisher-{}-{}-{}".format(len(publisher), publisher, name)


def signature_bytes(metadata):
  unsigned = {key: value for key, value in metadata.items() if key != "signature"}
  return b"mpack-publisher/v1\n" + json.dumps(unsigned, sort_keys=True,
      ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"


def sign_release(metadata, private_key):
  """Sign all registration metadata; the administrator separately provisions trust."""
  try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = serialization.load_pem_private_key(private_key, password=None)
    if not isinstance(key, Ed25519PrivateKey):
      raise ValueError("Wrong key algorithm")
  except (ImportError, ValueError, TypeError) as error:
    raise CompileError("Ed25519 export requires cryptography and an external PEM private key",
                       code="AUTHORIZATION_DENIED") from error
  public = key.public_key().public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
  metadata["signatureAlgorithm"] = "Ed25519"
  metadata["signatureKeyId"] = hashlib.sha256(public).hexdigest()
  metadata["signatureFormat"] = "mpack-publisher/v1"
  metadata["signature"] = base64.b64encode(key.sign(signature_bytes(metadata))).decode("ascii")
  return {"id": metadata["signatureKeyId"], "publicKey": base64.b64encode(public).decode("ascii"),
          "status": "active"}
