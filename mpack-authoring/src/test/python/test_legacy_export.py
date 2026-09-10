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
  def test_oci_export_uses_shared_script_and_declares_external_image_prerequisite(self):
    import shutil
    with tempfile.TemporaryDirectory() as root:
      source = Path(root) / "source"
      shutil.copytree(Path(__file__).resolve().parents[3] / "fixtures/http", source)
      manifest = source / "manifest.json"
      value = json.loads(manifest.read_text())
      service = value["spec"]["services"][0]
      service["configurations"][0]["changeEffect"] = "restart"
      profile = service["components"][0]["profiles"][0]
      image = "localhost/example@sha256:" + "a" * 64
      profile.update(adapter="oci.container/v1", capabilities=["install", "configure", "start", "stop", "uninstall", "purge", "observe"],
        resources={"engine": "podman", "image": image, "runAsUser": "http",
          "users": [{"name": "http"}],
          "directories": [{"path": "data", "owner": "http", "persistent": True, "retention": "retain"}],
          "mounts": [{"directoryRef": "data", "containerPath": "/data"}],
          "ports": [{"name": "listener", "configRef": "http.port", "protocol": "tcp"}]})
      manifest.write_text(json.dumps(value))
      output = Path(root) / "export"
      export_legacy(str(manifest), str(output), b"fixture-key")
      metadata = json.loads((output / "mpack.json").read_text())
      self.assertEqual([image], metadata["installationPrerequisites"]["containerImages"])
      with tarfile.open(output / "definition.tar.gz") as archive:
        module = archive.extractfile("definition/modules/HTTP_ECHO.tar.gz").read()
      with tarfile.open(fileobj=io.BytesIO(module), mode="r:gz") as archive:
        descriptor = json.loads(archive.extractfile("package/manifest-service.json").read())
        self.assertEqual("oci.container/v1", descriptor["service"]["components"][0]["profiles"][0]["adapter"])
      for invalid in ("/etc", "/proc/sys"):
        profile["resources"]["mounts"][0]["containerPath"] = invalid
        manifest.write_text(json.dumps(value))
        with self.assertRaises(CompileError):
          export_legacy(str(manifest), str(Path(root) / "invalid"), b"fixture-key")

  def test_schema_projects_existing_ambari_types_constraints_and_enum_entries(self):
    from mpack_authoring.legacy import _config_xml
    schema = {"type": "object", "additionalProperties": False, "properties": {
      "port": {"type": "integer", "default": 18080, "minimum": 1, "maximum": 65535},
      "mode": {"type": "string", "enum": ["safe", "fast"], "default": "safe"},
      "label": {"type": "string", "minLength": 1, "maxLength": 128},
    }}
    document = ET.fromstring(_config_xml({"schema": "config.json"}, {"config.json": json.dumps(schema).encode()}))
    properties = {item.findtext("name"): item for item in document.findall("property")}
    self.assertEqual("int", properties["port"].findtext("value-attributes/type"))
    self.assertEqual("65535", properties["port"].findtext("value-attributes/maximum"))
    self.assertEqual("false", properties["port"].findtext("value-attributes/empty-value-valid"))
    self.assertEqual(["safe", "fast"], [item.findtext("value") for item in properties["mode"].findall("value-attributes/entries/entry")])
    self.assertEqual("false", properties["mode"].findtext("value-attributes/entries_editable"))
    self.assertIn("1..128 Unicode characters", properties["label"].findtext("description"))

  def test_observability_projects_fixed_existing_providers_and_rejects_foreign_components(self):
    import shutil
    with tempfile.TemporaryDirectory() as root:
      source = Path(root) / "source"
      shutil.copytree(Path(__file__).resolve().parents[3] / "fixtures/http", source)
      manifest = source / "manifest.json"
      value = json.loads(manifest.read_text())
      observability = {"logs": {"HTTP_ECHO_SERVER": "mpack_http_echo"}, "metrics": {"HTTP_ECHO_SERVER": {
        "portRef": "http.port", "path": "/metrics", "fields": {"requests": ["http", "requests"]}}}}
      value["spec"]["services"][0]["observability"] = observability
      manifest.write_text(json.dumps(value))
      output = Path(root) / "export"
      export_legacy(str(manifest), str(output), b"fixture-key")
      with tarfile.open(output / "definition.tar.gz") as outer:
        module = outer.extractfile("definition/modules/HTTP_ECHO.tar.gz").read()
      with tarfile.open(fileobj=io.BytesIO(module), mode="r:gz") as inner:
        metrics = json.loads(inner.extractfile("metrics.json").read())
        provider = metrics["HTTP_ECHO_SERVER"]["HostComponent"][0]
        self.assertEqual("org.apache.ambari.server.controller.metrics.RestMetricsPropertyProvider", provider["type"])
        self.assertEqual("true", provider["properties"]["numeric_only"])
        self.assertEqual("metrics##http#requests", provider["metrics"]["default"]["metrics/mpack/requests"]["metric"])
        xml = ET.fromstring(inner.extractfile("metainfo.xml").read())
        self.assertEqual("mpack_http_echo", xml.findtext("services/service/components/component/logs/log/logId"))
      observability["logs"] = {"FOREIGN_SERVER": "another"}
      manifest.write_text(json.dumps(value))
      with self.assertRaises(CompileError):
        compile_manifest(str(manifest))
      observability["logs"] = {}
      observability["metrics"]["HTTP_ECHO_SERVER"]["portRef"] = "http.message"
      manifest.write_text(json.dumps(value))
      with self.assertRaises(CompileError):
        compile_manifest(str(manifest))

  def test_client_projection_reuses_script_and_declares_only_file_lifecycle(self):
    fixture = Path(__file__).resolve().parents[3] / "fixtures/multi-service/manifest.yaml"
    with tempfile.TemporaryDirectory() as root:
      export_legacy(str(fixture), str(Path(root) / "export"), b"fixture-key")
      with tarfile.open(Path(root) / "export/definition.tar.gz") as outer:
        module = outer.extractfile("definition/modules/STATIC_WEB.tar.gz").read()
      with tarfile.open(fileobj=io.BytesIO(module), mode="r:gz") as inner:
        xml = ET.fromstring(inner.extractfile("metainfo.xml").read())
        clients = [component for component in xml.findall("services/service/components/component")
                   if component.findtext("category") == "CLIENT"]
        self.assertEqual(1, len(clients))
        self.assertEqual("scripts/manifest_service.py", clients[0].findtext("commandScript/script"))
        self.assertEqual({"UNINSTALL", "PURGE"}, {command.findtext("name") for command in clients[0].findall("customCommands/customCommand")})
        self.assertIn("package/payload/client.py", inner.getnames())

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
    import shutil
    fixtures = Path(__file__).resolve().parents[3] / "fixtures"
    with tempfile.TemporaryDirectory() as root:
      with self.assertRaises(CompileError):
        export_legacy(str(fixtures / "http/manifest.json"), root, None)
      source = Path(root) / "dependent-source"
      shutil.copytree(fixtures / "http", source)
      document = json.loads((source / "manifest.json").read_text())
      document["spec"]["services"][0]["requires"] = [
          {"slot": "storage", "interface": "filesystem.hdfs", "versionRange": "*"}]
      (source / "manifest.json").write_text(json.dumps(document))
      with self.assertRaises(CompileError) as result:
        export_legacy(str(source / "manifest.json"), str(Path(root) / "output"), b"fixture-key")
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
