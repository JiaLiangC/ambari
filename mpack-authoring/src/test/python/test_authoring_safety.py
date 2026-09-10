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

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

from mpack_authoring.compiler import CompileError, build_package, compile_manifest, verify_package
from mpack_authoring.manifest import validate_manifest, ManifestError
from mpack_authoring.build import build_lock


class AuthoringSafetyTest(unittest.TestCase):
  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.root = Path(self.tmp.name)
    (self.root / "payload.tar.gz").write_bytes(b"fixture artifact, not a runtime distribution")
    self.manifest = {"apiVersion": "mpack.ambari.apache.org/v2alpha1", "kind": "Mpack",
      "metadata": {"name": "example", "version": "1"}, "spec": {
        "artifacts": [{"id": "binary", "source": {"kind": "file", "path": "payload.tar.gz"}}],
        "services": [{"name": "EXAMPLE", "components": [{"name": "SERVER", "profiles": [{
          "id": "host", "adapter": "host.systemd/v1", "capabilities": ["observe"]}]}]}]}}

  def write(self):
    path = self.root / "manifest.json"
    path.write_text(json.dumps(self.manifest))
    return str(path)

  def test_export_inventory_excludes_neighbors_and_includes_root_archive(self):
    (self.root / "private.key").write_text("test-only marker")
    source = self.write()
    before = build_lock(source)
    result = build_package(source, str(self.root / "one.zip"), b"fixture-key")
    build_package(source, str(self.root / "two.zip"), b"fixture-key")
    self.assertEqual((self.root / "one.zip").read_bytes(), (self.root / "two.zip").read_bytes())
    self.assertEqual(before, build_lock(source))
    with zipfile.ZipFile(self.root / "one.zip") as archive:
      self.assertIn("payload/payload.tar.gz", archive.namelist())
      self.assertNotIn("payload/private.key", archive.namelist())
    verify_package(result["path"], result["sha256"], b"fixture-key", result["signature"])
    with self.assertRaises(CompileError):
      verify_package(result["path"], result["sha256"], b"incorrect-key", result["signature"])
    with self.assertRaises(CompileError):
      verify_package(result["path"], "0" * 64)

  def test_offline_export_rejects_remote_and_overwriting_inputs(self):
    source = self.write()
    with self.assertRaises(CompileError):
      build_package(source, str(self.root / "payload.tar.gz"))
    self.manifest["spec"]["artifacts"][0]["source"] = {
      "kind": "url", "uri": "https://example.invalid/release.tar.gz", "sha256": "0" * 64}
    source = self.write()
    compile_manifest(source)
    with self.assertRaisesRegex(CompileError, "vendored"):
      build_package(source, str(self.root / "remote.zip"))

  def test_symlink_input_and_unknown_capability_rejected_by_all_entrypoints(self):
    (self.root / "alias").symlink_to(self.root / "payload.tar.gz")
    self.manifest["spec"]["artifacts"][0]["source"]["path"] = "alias"
    with self.assertRaises(ManifestError):
      validate_manifest(self.manifest, str(self.root))
    self.manifest["spec"]["artifacts"][0]["source"]["path"] = "payload.tar.gz"
    self.manifest["spec"]["services"][0]["components"][0]["profiles"][0]["capabilities"] = ["purge"]
    with self.assertRaises(CompileError):
      validate_manifest(self.manifest, str(self.root))

  def test_dependency_slots_are_scoped_to_consumers(self):
    first = self.manifest["spec"]["services"][0]
    first["requires"] = [{"slot": "database", "interface": "jdbc", "version": "1"}]
    second = copy.deepcopy(first)
    second["name"] = "SECOND"
    self.manifest["spec"]["services"].append(second)
    dependencies = compile_manifest(self.write())["dependencies"]
    self.assertEqual(["EXAMPLE", "SECOND"], [item["consumer"] for item in dependencies])
    first["requires"].append({"slot": "database", "interface": "other", "version": "1"})
    with self.assertRaises(CompileError):
      compile_manifest(self.write())

  def test_config_defaults_references_and_secret_diagnostics(self):
    schema = {"type": "object", "properties": {"port": {"type": "integer", "minimum": 1, "maximum": 65535}}}
    (self.root / "config.json").write_text(json.dumps(schema))
    service = self.manifest["spec"]["services"][0]
    service["configurations"] = [{"name": "main", "schema": "config.json", "defaults": {"port": 70000}}]
    with self.assertRaises(ManifestError):
      compile_manifest(self.write())
    service["configurations"][0]["defaults"] = {"port": 1234}
    profile = service["components"][0]["profiles"][0]
    profile["health"] = {"kind": "tcp", "portRef": "main.absent"}
    with self.assertRaises(ManifestError):
      compile_manifest(self.write())
    profile["health"]["portRef"] = "main.port"
    compile_manifest(self.write())

  def test_declared_listener_requires_a_bounded_integer_schema(self):
    schema = {"type": "object", "properties": {"port": {"type": "string", "default": "service"}}}
    (self.root / "config.json").write_text(json.dumps(schema))
    service = self.manifest["spec"]["services"][0]
    service["configurations"] = [{"name": "main", "schema": "config.json"}]
    service["components"][0]["profiles"][0]["resources"] = {
      "ports": [{"name": "listener", "configRef": "main.port"}]}
    with self.assertRaises(ManifestError):
      compile_manifest(self.write())

  def test_network_health_cannot_omit_its_target(self):
    profile = self.manifest["spec"]["services"][0]["components"][0]["profiles"][0]
    for kind in ("tcp", "http"):
      profile["health"] = {"kind": kind}
      with self.assertRaises(ManifestError):
        compile_manifest(self.write())

  def test_reference_packages_build_as_authoring_bundles(self):
    fixtures = Path(__file__).resolve().parents[3] / "fixtures"
    for name in ("http", "redis", "kyuubi"):
      result = build_package(str(fixtures / name / "manifest.json"), str(self.root / (name + ".zip")))
      verify_package(result["path"], result["sha256"])
