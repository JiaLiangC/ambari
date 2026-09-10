"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

import glob
import os

from .manifest import load_manifest


def validate_fixture_directory(directory):
  """Validate every JSON fixture in a directory and return stable summaries."""
  summaries = []
  for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
    result = load_manifest(path)
    summaries.append({"path": os.path.basename(path), "digest": result["digest"], "valid": True})
  return summaries
