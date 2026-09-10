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

import json
import os

def build_lock(manifest_path):
  """Return a deterministic offline lock for the manifest package directory."""
  from .compiler import compile_manifest
  compiled = compile_manifest(manifest_path)
  return {"format": "mpack.ambari.apache.org/lock/v1",
          "manifestDigest": compiled["manifestDigest"],
          "packageDigest": compiled["packageDigest"],
          "files": compiled["files"]}


def write_lock(manifest_path, output_path):
  lock = build_lock(manifest_path)
  root = os.path.dirname(os.path.realpath(manifest_path))
  inputs = {os.path.realpath(manifest_path)} | {os.path.realpath(os.path.join(root, item["path"])) for item in lock["files"]}
  if os.path.realpath(output_path) in inputs:
    raise ValueError("Lock output must not overwrite a package input")
  with open(output_path, "w", encoding="utf-8") as stream:
    json.dump(lock, stream, sort_keys=True, indent=2)
    stream.write("\n")
  return lock
