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
import sys

from manifest import ManifestError, load_manifest


def main(argv=None):
  parser = argparse.ArgumentParser(description="Validate an Ambari mpack v2alpha1 manifest")
  parser.add_argument("manifest")
  args = parser.parse_args(argv)
  try:
    result = load_manifest(args.manifest)
  except (ManifestError, OSError, ValueError, json.JSONDecodeError) as error:
    print(json.dumps({"valid": False, "error": str(error)}), file=sys.stderr)
    return 2
  print(json.dumps({"valid": True, "digest": result["digest"]}, sort_keys=True))
  return 0


if __name__ == "__main__":
  sys.exit(main())
