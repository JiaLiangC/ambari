#!/usr/bin/env python3
"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
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
  parser.add_argument("--signing-key", dest="signing_key", help="read an external HMAC signing key")
  args = parser.parse_args(argv)
  if args.diagnostics and (args.compile or args.export_path):
    result = compile_with_diagnostics(args.manifest)
    if result["valid"] and args.export_path:
      key = None
      if args.signing_key:
        with open(args.signing_key, "rb") as stream:
          key = stream.read()
      result = build_package(args.manifest, args.export_path, key)
      result = {"valid": True, "path": result["path"],
                "sha256": result["sha256"], "signature": result["signature"]}
    print(json.dumps(result, sort_keys=True, default=str))
    return 0 if result.get("valid", True) else 2
  if args.diagnostics:
    try:
      document, _ = load_source(args.manifest)
      result = validate_with_diagnostics(
          document, os.path.dirname(os.path.realpath(args.manifest)))
    except (OSError, ValueError, json.JSONDecodeError) as error:
      result = {"valid": False, "diagnostics": [{"code": "SCHEMA_INVALID",
        "severity": "ERROR", "message": str(error), "path": "", "retryable": False,
        "correction": "Provide a readable JSON manifest."}]}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["valid"] else 2
  try:
    document, _ = load_source(args.manifest)
    result = validate_manifest(document, os.path.dirname(os.path.realpath(args.manifest)))
    if args.lock_path:
      write_lock(args.manifest, args.lock_path)
    if args.compile:
      result = compile_manifest(args.manifest)
    if args.export_path:
      key = None
      if args.signing_key:
        with open(args.signing_key, "rb") as stream:
          key = stream.read()
      result = build_package(args.manifest, args.export_path, key)
  except (ManifestError, OSError, ValueError, json.JSONDecodeError) as error:
    print(json.dumps({"valid": False, "error": str(error)}), file=sys.stderr)
    return 2
  if args.compile or args.export_path:
    print(json.dumps({"valid": True, **result}, sort_keys=True, default=str))
  else:
    print(json.dumps({"valid": True, "digest": result["digest"]}, sort_keys=True))
  return 0


if __name__ == "__main__":
  sys.exit(main())
