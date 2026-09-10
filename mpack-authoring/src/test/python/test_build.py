"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

import json
import os
import tempfile
import unittest

from mpack_authoring.build import build_lock


class BuildLockTest(unittest.TestCase):
  def test_lock_orders_files_and_excludes_manifest(self):
    with tempfile.TemporaryDirectory() as root:
      manifest_path = os.path.join(root, "mpack.json")
      manifest = {
        "apiVersion": "mpack.ambari.apache.org/v2alpha1",
        "kind": "Mpack",
        "metadata": {"name": "echo", "version": "1.0.0"},
        "spec": {"artifacts": [], "services": [{"name": "ECHO", "components": [{
          "name": "SERVER",
          "profiles": [{"id": "linux", "adapter": "host.systemd/v1", "capabilities": ["observe"]}],
        }]}]},
      }
      with open(manifest_path, "w", encoding="utf-8") as output:
        json.dump(manifest, output)
      os.mkdir(os.path.join(root, "payload"))
      with open(os.path.join(root, "payload", "server.py"), "w", encoding="utf-8") as output:
        output.write("print('ok')\n")
      lock = build_lock(manifest_path)
      self.assertEqual(["payload/server.py"], [entry["path"] for entry in lock["files"]])
      self.assertEqual(64, len(lock["files"][0]["sha256"]))


if __name__ == "__main__":
  unittest.main()
