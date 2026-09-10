"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

import hashlib
import json
import os

from .manifest import load_manifest


def _sha256(path):
  digest = hashlib.sha256()
  with open(path, "rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
      digest.update(chunk)
  return digest.hexdigest()


def build_lock(manifest_path):
  """Return a deterministic offline lock for the manifest package directory."""
  result = load_manifest(manifest_path)
  root = os.path.dirname(os.path.realpath(manifest_path))
  files = []
  for directory, _, names in os.walk(root):
    for name in names:
      path = os.path.join(directory, name)
      relative = os.path.relpath(path, root).replace(os.sep, "/")
      if relative == os.path.basename(manifest_path):
        continue
      files.append({"path": relative, "sha256": _sha256(path), "size": os.path.getsize(path)})
  files.sort(key=lambda entry: entry["path"])
  return {
    "format": "mpack.ambari.apache.org/lock/v1",
    "manifestDigest": result["digest"],
    "files": files,
  }


def write_lock(manifest_path, output_path):
  lock = build_lock(manifest_path)
  with open(output_path, "w", encoding="utf-8") as stream:
    json.dump(lock, stream, sort_keys=True, indent=2)
    stream.write("\n")
  return lock
