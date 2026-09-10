"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file to you under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain a
copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
"""

import hashlib
import json
import os
import tempfile
import unittest
import zipfile

from mpack_authoring.compiler import (build_package, compile_manifest,
                                      sign_bytes)
from mpack_authoring.diagnostics import compile_with_diagnostics


class CompilerTest(unittest.TestCase):
  def setUp(self):
    self.root = tempfile.TemporaryDirectory()
    with open(os.path.join(self.root.name, "server.py"), "w", encoding="utf-8") as stream:
      stream.write("print('ok')\n")
    with open(os.path.join(self.root.name, "config.json"), "w", encoding="utf-8") as stream:
      json.dump({"type": "object"}, stream)

  def tearDown(self):
    self.root.cleanup()

  def manifest(self):
    return {
      "apiVersion": "mpack.ambari.apache.org/v2alpha1",
      "kind": "Mpack",
      "metadata": {"name": "echo", "version": "1.0.0"},
      "spec": {
        "artifacts": [{"id": "server", "source": {"kind": "file", "path": "server.py"}}],
        "dependencies": [{"slot": "database", "interface": "jdbc", "versionRange": ">=1"}],
        "services": [{"name": "ECHO", "requires": [], "configurations": [
          {"name": "echo", "schema": "config.json", "changeEffect": "restart"}],
          "components": [{"name": "SERVER", "profiles": [{
            "id": "linux", "adapter": "host.systemd/v1",
            "capabilities": ["install", "observe"],
            "resources": {"command": {"artifactRef": "server"}}}]}]}],
      },
    }

  def write_manifest(self, suffix=".json"):
    path = os.path.join(self.root.name, "manifest" + suffix)
    with open(path, "w", encoding="utf-8") as stream:
      if suffix == ".json":
        json.dump(self.manifest(), stream)
      else:
        stream.write("apiVersion: mpack.ambari.apache.org/v2alpha1\n")
        stream.write("kind: Mpack\nmetadata:\n  name: echo\n  version: 1.0.0\n")
        stream.write("spec:\n  artifacts:\n    - id: server\n      source:\n        kind: file\n        path: server.py\n")
        stream.write("  services:\n    - name: ECHO\n      components:\n        - name: SERVER\n          profiles:\n            - id: linux\n              adapter: host.systemd/v1\n              capabilities: [observe]\n")
    return path

  def test_yaml_compile_and_legacy_projection(self):
    result = compile_manifest(self.write_manifest(".yaml"))
    self.assertEqual("yaml", result["sourceFormat"])
    self.assertEqual("ECHO", result["legacy"]["services"][0]["name"])
    self.assertEqual("server", result["artifacts"][0]["id"])

  def test_export_is_deterministic_and_signed(self):
    manifest = self.write_manifest()
    first_path = os.path.join(self.root.name, "first.zip")
    second_path = os.path.join(self.root.name, "second.zip")
    first = build_package(manifest, first_path, b"test-key")
    second = build_package(manifest, second_path, b"test-key")
    with open(first_path, "rb") as stream:
      first_bytes = stream.read()
    with open(second_path, "rb") as stream:
      second_bytes = stream.read()
    self.assertEqual(first_bytes, second_bytes)
    self.assertEqual(first["sha256"], second["sha256"])
    self.assertEqual(sign_bytes(first_bytes, b"test-key"), first["signature"])
    with zipfile.ZipFile(first_path) as archive:
      self.assertIn("mpack/dependencies.lock.json", archive.namelist())
      self.assertIn("mpack/legacy/stack.json", archive.namelist())
      self.assertIn("payload/server.py", archive.namelist())

  def test_semantic_failures_have_stable_codes(self):
    manifest = self.manifest()
    manifest["spec"]["services"][0]["components"][0]["profiles"][0]["capabilities"] = ["delete"]
    path = os.path.join(self.root.name, "bad.json")
    with open(path, "w", encoding="utf-8") as stream:
      json.dump(manifest, stream)
    result = compile_with_diagnostics(path)
    self.assertFalse(result["valid"])
    self.assertEqual("CAPABILITY_UNSUPPORTED", result["diagnostics"][0]["code"])

  def test_service_group_is_rejected_without_identity_migration(self):
    manifest = self.manifest()
    manifest["spec"]["serviceGroups"] = [{"name": "legacy"}]
    path = os.path.join(self.root.name, "group.json")
    with open(path, "w", encoding="utf-8") as stream:
      json.dump(manifest, stream)
    result = compile_with_diagnostics(path)
    self.assertFalse(result["valid"])
    self.assertEqual("TARGET_CONFLICT", result["diagnostics"][0]["code"])


if __name__ == "__main__":
  unittest.main()
