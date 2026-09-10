"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

import os
import tempfile
import unittest

from mpack_authoring.manifest import ManifestError, validate_manifest


class ManifestTest(unittest.TestCase):
  def setUp(self):
    self.root = tempfile.TemporaryDirectory()
    with open(os.path.join(self.root.name, "server.py"), "w", encoding="utf-8") as output:
      output.write("print('ok')\n")

  def tearDown(self):
    self.root.cleanup()

  def manifest(self):
    return {
      "apiVersion": "mpack.ambari.apache.org/v2alpha1",
      "kind": "Mpack",
      "metadata": {"name": "echo", "version": "1.0.0"},
      "spec": {
        "artifacts": [{"id": "server", "source": {"kind": "file", "path": "server.py"}}],
        "services": [{"name": "ECHO", "components": [{"name": "SERVER"}]}],
      },
    }

  def test_valid_manifest_has_stable_digest(self):
    first = validate_manifest(self.manifest(), self.root.name)
    second = validate_manifest(self.manifest(), self.root.name)
    self.assertEqual(first["digest"], second["digest"])

  def test_rejects_traversal_and_duplicate_identity(self):
    manifest = self.manifest()
    manifest["spec"]["artifacts"][0]["source"]["path"] = "../secret"
    with self.assertRaises(ManifestError):
      validate_manifest(manifest, self.root.name)
    manifest = self.manifest()
    manifest["spec"]["services"].append({"name": "ECHO", "components": []})
    with self.assertRaises(ManifestError):
      validate_manifest(manifest, self.root.name)


if __name__ == "__main__":
  unittest.main()
