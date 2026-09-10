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

import json

from .compiler import compile_manifest
from .manifest import ManifestError


def _changes(before, after, path=""):
  if type(before) is type(after) and before == after:
    return []
  if isinstance(before, dict) and isinstance(after, dict):
    result = []
    for key in sorted(set(before) | set(after)):
      pointer = path + "/" + key.replace("~", "~0").replace("/", "~1")
      if key not in before:
        result.append({"operation": "add", "path": pointer})
      elif key not in after:
        result.append({"operation": "remove", "path": pointer})
      else:
        result.extend(_changes(before[key], after[key], pointer))
    return result
  if isinstance(before, list) and isinstance(after, list):
    result = []
    for index in range(max(len(before), len(after))):
      pointer = path + "/" + str(index)
      if index >= len(before):
        result.append({"operation": "add", "path": pointer})
      elif index >= len(after):
        result.append({"operation": "remove", "path": pointer})
      else:
        result.extend(_changes(before[index], after[index], pointer))
    return result
  return [{"operation": "replace", "path": path or "/"}]


def review_changes(before, candidate):
  """Validate both sources and report changed fields/files without exposing values."""
  result = {"valid": False, "scope": "source-review", "checks": [], "diagnostics": [],
    "limitations": ["Source review does not prove host export, deployment compatibility or data rollback.",
      "Values are omitted. Inspect the source diff locally before signing or importing.",
      "Human and AI edits require the same validation, publisher signing and Ambari authorization."]}
  stage = "baseline-source"
  try:
    baseline = compile_manifest(str(before))
    result["checks"].append({"name": stage, "status": "passed"})
    stage = "candidate-source"
    proposed = compile_manifest(str(candidate))
    result["checks"].append({"name": stage, "status": "passed"})
    result["changes"] = _changes(baseline["manifest"], proposed["manifest"])
    old_files = {item["path"]: item for item in baseline["files"]}
    new_files = {item["path"]: item for item in proposed["files"]}
    result["files"] = [{"path": path, "operation": "add" if path not in old_files else "remove" if path not in new_files else "replace",
      "beforeSha256": old_files.get(path, {}).get("sha256"), "afterSha256": new_files.get(path, {}).get("sha256")}
      for path in sorted(set(old_files) | set(new_files)) if old_files.get(path) != new_files.get(path)]
    result["beforePackageDigest"] = baseline["packageDigest"]
    result["candidatePackageDigest"] = proposed["packageDigest"]
    result["valid"] = True
  except (ManifestError, OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
    result["checks"].append({"name": stage, "status": "failed"})
    result["diagnostics"] = [{"code": getattr(error, "code", "SCHEMA_INVALID"),
      "message": "Source review failed; input values are omitted.", "stage": stage}]
  return result


def main(argv=None):
  import argparse
  parser = argparse.ArgumentParser(description="Review human or AI source changes without applying them")
  parser.add_argument("baseline")
  parser.add_argument("candidate")
  args = parser.parse_args(argv)
  result = review_changes(args.baseline, args.candidate)
  print(json.dumps(result, sort_keys=True))
  return 0 if result["valid"] else 2


if __name__ == "__main__":
  raise SystemExit(main())
