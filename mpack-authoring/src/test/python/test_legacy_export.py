#!/usr/bin/env python3
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
import hmac
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET

from mpack_authoring.compiler import CompileError, compile_manifest
from mpack_authoring.legacy import export_legacy


class LegacyExportTest(unittest.TestCase):
  def test_signed_export_matches_actual_registration_layout(self):
    fixture = Path(__file__).resolve().parents[3] / "fixtures/http/manifest.json"
    with tempfile.TemporaryDirectory() as root:
      first = Path(root) / "one"
      second = Path(root) / "two"
      result = export_legacy(str(fixture), str(first), b"fixture-key")
      export_legacy(str(fixture), str(second), b"fixture-key")
      metadata = json.loads((first / "mpack.json").read_text())
      archive = (first / "definition.tar.gz").read_bytes()
      self.assertEqual(archive, (second / "definition.tar.gz").read_bytes())
      self.assertEqual(hashlib.sha256(archive).hexdigest(), metadata["definitionSha256"])
      envelope = "mpack-legacy/v1\n{}\n{}\n{}\n{}\n{}\n".format(metadata["name"], metadata["version"],
        metadata["definitionSha256"], metadata["manifestDigest"], metadata["packageDigest"]).encode()
      self.assertEqual(hmac.new(b"fixture-key", envelope, hashlib.sha256).hexdigest(), metadata["signature"])
      with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as outer:
        module = outer.extractfile("definition/modules/HTTP_ECHO.tar.gz").read()
      with tarfile.open(fileobj=io.BytesIO(module), mode="r:gz") as inner:
        xml = ET.fromstring(inner.extractfile("metainfo.xml").read())
        self.assertEqual("HTTP_ECHO", xml.findtext("services/service/name"))
        self.assertEqual("scripts/manifest_service.py", xml.findtext("services/service/components/component/commandScript/script"))
        self.assertIn("configuration/http.xml", inner.getnames())
        self.assertIn("package/payload/server.py", inner.getnames())
        descriptor = json.loads(inner.extractfile("package/manifest-service.json").read())
        self.assertEqual(compile_manifest(str(fixture))["packageDigest"], descriptor["package"]["digest"])

  def test_changed_source_after_compilation_cannot_receive_a_valid_signature(self):
    import shutil
    from unittest.mock import patch
    fixture = Path(__file__).resolve().parents[3] / "fixtures/http"
    with tempfile.TemporaryDirectory() as root:
      source = Path(root) / "source"
      shutil.copytree(fixture, source)
      compiled = compile_manifest(str(source / "manifest.json"))
      (source / "server.py").write_text("changed after compilation")
      output = Path(root) / "output"
      with patch("mpack_authoring.legacy.compile_manifest", return_value=compiled):
        with self.assertRaises(CompileError) as result:
          export_legacy(str(source / "manifest.json"), str(output), b"fixture-key")
      self.assertEqual("PACKAGE_CONTENT_CONFLICT", result.exception.code)
      self.assertFalse(output.exists())

  def test_export_rejects_unsigned_and_unavailable_dependency_contracts(self):
    fixtures = Path(__file__).resolve().parents[3] / "fixtures"
    with tempfile.TemporaryDirectory() as root:
      with self.assertRaises(CompileError):
        export_legacy(str(fixtures / "http/manifest.json"), root, None)
      with self.assertRaises(CompileError) as result:
        export_legacy(str(fixtures / "kyuubi/manifest.json"), root, b"fixture-key")
      self.assertEqual("DEPENDENCY_UNRESOLVED", result.exception.code)

  def test_host_export_cannot_promise_no_effect_for_changed_configuration(self):
    import shutil
    fixture = Path(__file__).resolve().parents[3] / "fixtures/http"
    with tempfile.TemporaryDirectory() as root:
      source = Path(root) / "source"
      shutil.copytree(fixture, source)
      manifest = json.loads((source / "manifest.json").read_text())
      manifest["spec"]["services"][0]["configurations"][0]["changeEffect"] = "none"
      (source / "manifest.json").write_text(json.dumps(manifest))
      with self.assertRaises(CompileError) as result:
        export_legacy(str(source / "manifest.json"), str(Path(root) / "output"), b"fixture-key")
      self.assertEqual("CAPABILITY_UNSUPPORTED", result.exception.code)

  def test_host_export_rejects_constraints_templates_and_secret_execution(self):
    import shutil
    fixture = Path(__file__).resolve().parents[3] / "fixtures/http"
    with tempfile.TemporaryDirectory() as root:
      source = Path(root) / "source"
      shutil.copytree(fixture, source)
      schema_path = source / "config.schema.json"
      original_schema = schema_path.read_text()
      schema = json.loads(original_schema)
      schema["allOf"] = [{"properties": {"port": {"maximum": 20000}}}]
      schema_path.write_text(json.dumps(schema))
      with self.assertRaises(CompileError):
        export_legacy(str(source / "manifest.json"), str(Path(root) / "output"), b"fixture-key")
      schema_path.write_text(original_schema)
      (source / "config.conf.j2").write_text("{{ missing_field }}")
      with self.assertRaises(CompileError):
        export_legacy(str(source / "manifest.json"), str(Path(root) / "output"), b"fixture-key")
