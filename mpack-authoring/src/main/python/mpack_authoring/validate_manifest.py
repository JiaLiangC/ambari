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
from mpack_authoring.diagnostics import validate_with_diagnostics
from mpack_authoring.manifest import ManifestError, load_manifest


def main(argv=None):
  parser = argparse.ArgumentParser(description="Validate an Ambari mpack v2alpha1 manifest")
  parser.add_argument("manifest")
  parser.add_argument("--lock", dest="lock_path", help="write a deterministic package lock")
  parser.add_argument("--diagnostics", action="store_true", help="emit structured diagnostics")
  args = parser.parse_args(argv)
  if args.diagnostics:
    try:
      with open(args.manifest, "r", encoding="utf-8") as stream:
        result = validate_with_diagnostics(json.load(stream),
                                          os.path.dirname(os.path.realpath(args.manifest)))
    except (OSError, ValueError, json.JSONDecodeError) as error:
      result = {"valid": False, "diagnostics": [{"code": "SCHEMA_INVALID",
        "severity": "ERROR", "message": str(error), "path": "", "retryable": False,
        "correction": "Provide a readable JSON manifest."}]}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["valid"] else 2
  try:
    result = load_manifest(args.manifest)
    if args.lock_path:
      write_lock(args.manifest, args.lock_path)
  except (ManifestError, OSError, ValueError, json.JSONDecodeError) as error:
    print(json.dumps({"valid": False, "error": str(error)}), file=sys.stderr)
    return 2
  print(json.dumps({"valid": True, "digest": result["digest"]}, sort_keys=True))
  return 0


if __name__ == "__main__":
  sys.exit(main())
