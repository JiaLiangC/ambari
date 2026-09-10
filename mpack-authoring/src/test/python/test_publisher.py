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
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mpack_authoring.compiler import CompileError
from mpack_authoring.legacy import export_legacy, export_deployable
from mpack_authoring.trust import catalog_name, signature_bytes


class PublisherTest(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory()
    self.addCleanup(self.temporary.cleanup)
    self.root = Path(self.temporary.name)
    self.source = self.root / "source"
    shutil.copytree(Path(__file__).resolve().parents[3] / "fixtures/http", self.source)
    self.manifest = json.loads((self.source / "manifest.json").read_text())
    self.manifest["metadata"].update(publisher="team", displayName="Example \u4e2d\u6587")
    self.manifest["spec"]["compatibility"] = {"ambari": ">=3.1,<4", "agentSdk": "1"}
    self.manifest["spec"]["services"][0]["components"][0]["softwareVersion"] = "1.0.0"
    (self.source / "manifest.json").write_text(json.dumps(self.manifest))
    self.key = Ed25519PrivateKey.generate()
    self.private = self.key.private_bytes(serialization.Encoding.PEM,
      serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

  def test_public_release_authenticates_all_metadata(self):
    export_legacy(str(self.source / "manifest.json"), str(self.root / "output"), self.private, "Ed25519")
    metadata = json.loads((self.root / "output/mpack.json").read_text())
    self.assertEqual("publisher-4-team-http-authoring-example", metadata["name"])
    self.key.public_key().verify(base64.b64decode(metadata["signature"]), signature_bytes(metadata))
    for field, changed in (("publisher", "other"), ("compatibility", {}), ("softwareVersions", {}),
                           ("modules", []), ("displayName", "different"), ("installationPrerequisites", {})):
      modified = dict(metadata, **{field: changed})
      with self.assertRaises(InvalidSignature):
        self.key.public_key().verify(base64.b64decode(metadata["signature"]), signature_bytes(modified))

  def test_namespaces_are_unambiguous_and_cannot_downgrade_to_hmac(self):
    self.assertNotEqual(catalog_name("c", "a-b"), catalog_name("b-c", "a"))
    with self.assertRaises(CompileError):
      catalog_name("publisher-4-team-package")
    with self.assertRaises(CompileError):
      export_legacy(str(self.source / "manifest.json"), str(self.root / "output"), b"local-fixture-key")
    with self.assertRaises(CompileError):
      export_legacy(str(self.source / "manifest.json"), str(self.root / "output"), b"invalid", "Ed25519")

  def test_artifact_upgrade_exports_only_explicit_data_unchanged_transitions(self):
    profile = self.manifest["spec"]["services"][0]["components"][0]["profiles"][0]
    profile["capabilities"].append("upgrade")
    manifest_path = self.source / "manifest.json"
    manifest_path.write_text(json.dumps(self.manifest))
    with self.assertRaises(CompileError):
      export_legacy(str(manifest_path), str(self.root / "missing-policy"), self.private, "Ed25519")
    profile["upgradePolicy"] = {"fromPackageDigests": ["a" * 64], "configuration": "compatible", "data": "unchanged"}
    manifest_path.write_text(json.dumps(self.manifest))
    export_legacy(str(manifest_path), str(self.root / "compatible"), self.private, "Ed25519")
    profile["upgradePolicy"]["data"] = "migration"
    manifest_path.write_text(json.dumps(self.manifest))
    from mpack_authoring.manifest import ManifestError
    with self.assertRaises(ManifestError):
      export_legacy(str(manifest_path), str(self.root / "migration"), self.private, "Ed25519")
    profile["upgradePolicy"]["data"] = "unchanged"
    profile["resources"]["command"]["arguments"] = []
    manifest_path.write_text(json.dumps(self.manifest))
    with self.assertRaises(CompileError):
      export_legacy(str(manifest_path), str(self.root / "external-binary"), self.private, "Ed25519")

  def test_reload_requires_native_signal_and_generation_capable_health(self):
    profile = self.manifest["spec"]["services"][0]["components"][0]["profiles"][0]
    profile["health"] = {"kind": "process"}
    (self.source / "manifest.json").write_text(json.dumps(self.manifest))
    with self.assertRaisesRegex(CompileError, "acknowledgement"):
      export_legacy(str(self.source / "manifest.json"), str(self.root / "rejected"), self.private, "Ed25519")

  def test_secret_reference_export_keeps_credentials_out_of_artifacts(self):
    import tarfile
    reference = "secret://mpack.HTTP_ECHO.password"
    schema_path = self.source / "config.schema.json"
    schema = json.loads(schema_path.read_text())
    schema["properties"]["password"] = {"type": "object", "x-sensitive": True,
      "properties": {"secretRef": {"type": "string"}}, "required": ["secretRef"],
      "additionalProperties": False, "default": {"secretRef": reference}}
    schema_path.write_text(json.dumps(schema))
    export_legacy(str(self.source / "manifest.json"), str(self.root / "output"), self.private, "Ed25519")
    metadata = json.loads((self.root / "output/mpack.json").read_text())
    self.assertEqual({"http.password": reference}, metadata["secretConfigurationDefaults"]["HTTP_ECHO"])
    self.assertNotIn("HTTP_ECHO", metadata["secretReferences"])
    with tarfile.open(self.root / "output/definition.tar.gz") as archive:
      module = archive.extractfile("definition/modules/HTTP_ECHO.tar.gz")
      with tarfile.open(fileobj=module, mode="r:gz") as service:
        xml = service.extractfile("configuration/http.xml").read().decode()
        self.assertIn("SECRET_REFERENCE", xml)
        self.assertIn(reference, xml)
    self.manifest["spec"]["services"][0]["components"][0]["profiles"][0]["resources"]["command"]["arguments"].append({"secretRef": reference})
    (self.source / "manifest.json").write_text(json.dumps(self.manifest))
    with self.assertRaisesRegex(CompileError, "process arguments"):
      export_legacy(str(self.source / "manifest.json"), str(self.root / "rejected"), self.private, "Ed25519")

  def test_deployable_transport_preserves_signed_release_and_is_reproducible(self):
    import tarfile
    outputs = [self.root / "one.mpack", self.root / "two.mpack"]
    for output in outputs:
      export_deployable(str(self.source / "manifest.json"), str(output), self.private, "Ed25519")
    self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
    with tarfile.open(outputs[0]) as archive:
      self.assertEqual({"mpack.json", "definition.tar.gz"}, set(archive.getnames()))
      metadata = json.load(archive.extractfile("mpack.json"))
      self.key.public_key().verify(base64.b64decode(metadata["signature"]), signature_bytes(metadata))
    with self.assertRaises(CompileError):
      export_deployable(str(self.source / "manifest.json"), str(outputs[0]), self.private, "Ed25519")

  def test_signature_and_export_are_reproducible(self):
    for name in ("one", "two"):
      export_legacy(str(self.source / "manifest.json"), str(self.root / name), self.private, "Ed25519")
    for name in ("mpack.json", "definition.tar.gz"):
      self.assertEqual((self.root / "one" / name).read_bytes(), (self.root / "two" / name).read_bytes())


if __name__ == "__main__":
  unittest.main()
