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
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET

from mpack_authoring.compiler import build_package
from mpack_authoring.legacy import export_legacy

ROOT = Path(__file__).resolve().parents[3]


class UserValidationTest(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory(prefix="mpack user validation ")
    self.addCleanup(self.temporary.cleanup)
    self.work = Path(self.temporary.name)

  def run_check(self, *args, expected=0):
    process = subprocess.run([sys.executable, str(ROOT / "validate.py"), "--json", *map(str, args)],
      cwd=self.work, capture_output=True, text=True, timeout=60,
      env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    self.assertEqual(expected, process.returncode, process.stdout + process.stderr)
    self.assertEqual("", process.stderr)
    return json.loads(process.stdout)

  def test_host_source_check_is_portable_and_leaves_sources_unchanged(self):
    source = self.work / "source with spaces"
    shutil.copytree(ROOT / "fixtures/http", source)
    before = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    report = self.run_check("source", source / "manifest.json")
    after = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    self.assertEqual(before, after)
    self.assertEqual("host", report["scope"])
    self.assertEqual(3, len(report["checks"]))
    self.assertTrue(all(item["status"] == "passed" for item in report["checks"]))
    self.assertNotIn("compiled", report)
    self.assertNotIn("signature", report)

  def test_example_suite_checks_all_three_deployable_source_exports(self):
    report = self.run_check("examples")
    self.assertTrue(report["valid"])
    cases = {item["example"]: item for item in report["examples"]}
    self.assertEqual({"http", "redis", "multi-service"}, set(cases))
    for case in cases.values():
      self.assertTrue(case["expectationMet"])
      self.assertTrue(case["result"]["valid"])
      self.assertEqual("host", case["result"]["scope"])
      self.assertEqual(3, len(case["result"]["checks"]))

  def test_review_reports_field_and_payload_changes_without_values_or_source_mutation(self):
    baseline = self.work / "baseline"
    candidate = self.work / "candidate"
    shutil.copytree(ROOT / "fixtures/http", baseline)
    shutil.copytree(baseline, candidate)
    manifest = candidate / "manifest.json"
    document = json.loads(manifest.read_text())
    marker = "synthetic-review-value-must-not-appear"
    document["metadata"]["description"] = marker
    document["spec"]["services"][0]["configurations"][0].setdefault("defaults", {})["port"] = 18081
    manifest.write_text(json.dumps(document))
    template = candidate / "config.conf.j2"
    template.write_text(template.read_text() + "\n# revised configuration template\n")
    before = {str(path.relative_to(candidate)): path.read_bytes() for path in candidate.rglob("*") if path.is_file()}
    report = self.run_check("review", baseline / "manifest.json", manifest)
    after = {str(path.relative_to(candidate)): path.read_bytes() for path in candidate.rglob("*") if path.is_file()}
    self.assertEqual(before, after)
    self.assertEqual("source-review", report["scope"])
    self.assertNotEqual(report["beforePackageDigest"], report["candidatePackageDigest"])
    self.assertIn("/metadata/description", {item["path"] for item in report["changes"]})
    self.assertIn("config.conf.j2", {item["path"] for item in report["files"]})
    self.assertNotIn(marker, json.dumps(report))
    unchanged = self.run_check("review", manifest, manifest)
    self.assertEqual([], unchanged["changes"])
    self.assertEqual([], unchanged["files"])

  def test_review_rejects_an_invalid_repair_without_exposing_input(self):
    candidate = self.work / "invalid candidate"
    shutil.copytree(ROOT / "fixtures/http", candidate)
    manifest = candidate / "manifest.json"
    document = json.loads(manifest.read_text())
    marker = "synthetic-invalid-repair-value"
    document["spec"]["services"][0]["configurations"][0].setdefault("defaults", {})["port"] = marker
    manifest.write_text(json.dumps(document))
    report = self.run_check("review", ROOT / "fixtures/http/manifest.json", manifest, expected=2)
    self.assertEqual("candidate-source", report["diagnostics"][0]["stage"])
    self.assertNotIn(marker, json.dumps(report))
    self.assertNotIn("changes", report)

  def test_source_errors_and_missing_inputs_fail_without_echoing_values(self):
    source = self.work / "source"
    shutil.copytree(ROOT / "fixtures/http", source)
    manifest = source / "manifest.json"
    document = json.loads(manifest.read_text())
    marker = "synthetic-sensitive-value-must-not-appear"
    document["spec"]["services"][0]["configurations"][0]["defaults"] = {"port": marker}
    manifest.write_text(json.dumps(document))
    invalid = self.run_check("source", manifest, expected=2)
    self.assertEqual("SCHEMA_INVALID", invalid["diagnostics"][0]["code"])
    self.assertNotIn(marker, json.dumps(invalid))
    missing = self.run_check("source", source / marker, expected=2)
    self.assertNotIn(marker, json.dumps(missing))
    self.assertFalse(missing["valid"])

  def test_bundle_requires_trusted_digest_and_detects_tampering(self):
    archive = self.work / "source.zip"
    built = build_package(str(ROOT / "fixtures/http/manifest.json"), str(archive))
    report = self.run_check("bundle", archive, "--sha256", built["sha256"])
    self.assertEqual("source-bundle", report["scope"])
    self.assertEqual(built["sha256"], report["sha256"])
    archive.write_bytes(archive.read_bytes() + b"tampered")
    rejected = self.run_check("bundle", archive, "--sha256", built["sha256"], expected=2)
    self.assertEqual("PACKAGE_CONTENT_CONFLICT", rejected["diagnostics"][0]["code"])
    self.run_check("bundle", archive, "--sha256", "not-a-digest", expected=2)

  def test_non_source_archive_is_rejected_without_traceback(self):
    archive = self.work / "not-a-source.zip"
    archive.write_bytes(b"not a ZIP")
    report = self.run_check("bundle", archive, "--sha256",
                           hashlib.sha256(archive.read_bytes()).hexdigest(), expected=2)
    self.assertFalse(report["valid"])
    self.assertEqual("bundle-verification", report["diagnostics"][0]["stage"])

  def test_multi_service_export_preserves_distinct_configs_with_a_shared_schema(self):
    output = self.work / "host"
    export_legacy(str(ROOT / "fixtures/multi-service/manifest.yaml"), str(output), os.urandom(32))
    metadata = json.loads((output / "mpack.json").read_text())
    self.assertEqual({"STATIC_WEB", "STATUS_WEB"}, {item["name"] for item in metadata["modules"]})
    with tarfile.open(output / "definition.tar.gz", "r:gz") as outer:
      for service, config, port in (("STATIC_WEB", "website", "18100"), ("STATUS_WEB", "status", "18101")):
        payload = outer.extractfile("definition/modules/" + service + ".tar.gz").read()
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as inner:
          xml = ET.fromstring(inner.extractfile("configuration/" + config + ".xml").read())
          properties = {item.findtext("name"): item.findtext("value") for item in xml.findall("property")}
          self.assertEqual(port, properties["port"])
          self.assertEqual(1, inner.getnames().count("package/payload/config.schema.json"))

  def test_missing_dependencies_report_environment_failure(self):
    process = subprocess.run([sys.executable, "-S", str(ROOT / "validate.py"), "--json", "examples"],
      cwd=self.work, capture_output=True, text=True, timeout=30,
      env=dict(os.environ, PYTHONPATH="", PYTHONDONTWRITEBYTECODE="1"))
    self.assertEqual(3, process.returncode, process.stdout + process.stderr)
    self.assertEqual("", process.stderr)
    self.assertEqual("TOOLING_UNAVAILABLE", json.loads(process.stdout)["diagnostics"][0]["code"])


if __name__ == "__main__":
  unittest.main()
