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

import argparse
import json
import os
import sys

from mpack_authoring.build import write_lock
from mpack_authoring.compiler import build_package, compile_manifest, load_source
from mpack_authoring.diagnostics import (compile_with_diagnostics,
                                         validate_with_diagnostics)
from mpack_authoring.manifest import ManifestError, validate_manifest


def main(argv=None):
  parser = argparse.ArgumentParser(description="Validate an Ambari mpack v2alpha1 manifest")
  parser.add_argument("manifest")
  parser.add_argument("--lock", dest="lock_path", help="write a deterministic package lock")
  parser.add_argument("--diagnostics", action="store_true", help="emit structured diagnostics")
  parser.add_argument("--compile", action="store_true", help="emit the normalized compiled model")
  parser.add_argument("--export", dest="export_path", help="write a deterministic offline package ZIP")
  parser.add_argument("--legacy-export", dest="legacy_export", help="write signed legacy V2 host service definitions")
  parser.add_argument("--signing-key", dest="signing_key", help="read an external HMAC signing key")
  args = parser.parse_args(argv)
  try:
    key = None
    if args.signing_key:
      if not args.export_path and not args.legacy_export:
        raise ManifestError("--signing-key requires --export or --legacy-export")
      root = os.path.dirname(os.path.realpath(args.manifest))
      if os.path.commonpath((root, os.path.realpath(args.signing_key))) == root:
        raise ManifestError("Signing key must be outside the package directory")
      with open(args.signing_key, "rb") as stream:
        key = stream.read()
    result = compile_manifest(args.manifest)
    if args.lock_path:
      write_lock(args.manifest, args.lock_path)
    if args.export_path:
      result = build_package(args.manifest, args.export_path, key)
    if args.legacy_export:
      from mpack_authoring.legacy import export_legacy
      result = export_legacy(args.manifest, args.legacy_export, key)
    if args.compile or args.export_path or args.legacy_export:
      output = {"valid": True, **result}
    else:
      output = {"valid": True, "digest": result["manifestDigest"]}
    if args.diagnostics:
      output["diagnostics"] = []
    print(json.dumps(output, sort_keys=True, default=str))
    return 0
  except (ManifestError, OSError, ValueError) as error:
    output = {"valid": False}
    if args.diagnostics:
      output["diagnostics"] = [{"code": getattr(error, "code", "SCHEMA_INVALID"),
        "severity": "ERROR", "message": str(error), "path": getattr(error, "path", ""),
        "retryable": False, "correction": "Correct the source and validate again."}]
    else:
      output["error"] = str(error)
    print(json.dumps(output), file=sys.stdout if args.diagnostics else sys.stderr)
    return 2


if __name__ == "__main__":
  sys.exit(main())
