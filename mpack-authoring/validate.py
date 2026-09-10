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
from pathlib import Path
import re
import sys
import tempfile
import zipfile
import zlib

# Work from any directory without installing or modifying the source checkout.
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src/main/python"))

from mpack_authoring.compiler import CompileError, build_package, compile_manifest, verify_package
from mpack_authoring.legacy import export_legacy
from mpack_authoring.manifest import ManifestError


CORRECTIONS = {
  "SCHEMA_INVALID": "Check manifest types, configuration defaults and references against the authoring schema.",
  "PACKAGE_CONTENT_CONFLICT": "Check declared files, hashes and archive inventory; vendor remote artifacts for offline builds.",
  "CAPABILITY_UNSUPPORTED": "Use the documented host subset or select --target source for authoring-only packages.",
  "DEPENDENCY_UNRESOLVED": "Host export requires real shared dependency integration; source validation cannot approve bindings.",
  "TARGET_CONFLICT": "Use existing Ambari service identity and remove conflicting declarations.",
  "AUTHORIZATION_DENIED": "Check the trusted digest and authentication requirements.",
}
LIMITS = [
  "No runtime execution, installation, network download or dependency authorization was performed.",
  "OS packages, runtimes, live health and server-Agent compatibility require separate target acceptance.",
  "Source ZIP verification does not authenticate a publisher without an independently trusted digest.",
]


def _same(condition):
  if not condition:
    raise CompileError("Build inputs or outputs changed", code="PACKAGE_CONTENT_CONFLICT")


def check(path, target="host", expected_digest=None):
  """Reuse canonical validation; write disposable build products outside the source."""
  result = {"valid": False, "scope": "source-bundle" if expected_digest is not None else target,
            "checks": [], "diagnostics": [], "limitations": LIMITS}
  stage = "bundle-verification" if expected_digest is not None else "compile"
  try:
    if expected_digest is not None:
      _same(bool(re.fullmatch(r"[0-9a-fA-F]{64}", expected_digest)))
      result.update(verify_package(str(path), expected_digest.lower()))
      result["checks"].append({"name": stage, "status": "passed"})
    else:
      compiled = compile_manifest(str(path))
      result.update({key: compiled[key] for key in ("manifestDigest", "packageDigest")})
      result["checks"].append({"name": stage, "status": "passed"})
      stage = "source-build-and-reproducibility"
      with tempfile.TemporaryDirectory(prefix="mpack-check-") as directory:
        output = Path(directory)
        first = build_package(str(path), str(output / "first.zip"))
        second = build_package(str(path), str(output / "second.zip"))
        _same(first["compiled"]["packageDigest"] == compiled["packageDigest"]
              == second["compiled"]["packageDigest"])
        _same(first["sha256"] == second["sha256"])
        # build_package verifies inventory and source locks before publishing either ZIP.
        result["checks"].append({"name": stage, "status": "passed"})
        if target == "host":
          stage = "host-export-and-reproducibility"
          # Validation only: an ephemeral key never leaves memory or grants import trust.
          key = os.urandom(32)
          algorithm = "HMAC-SHA256"
          if compiled["manifest"]["metadata"].get("publisher"):
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            key = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            algorithm = "Ed25519"
          for name in ("host-first", "host-second"):
            export_legacy(str(path), str(output / name), key, algorithm)
            metadata = json.loads((output / name / "mpack.json").read_text())
            _same(metadata["packageDigest"] == compiled["packageDigest"])
          for name in ("mpack.json", "definition.tar.gz"):
            _same((output / "host-first" / name).read_bytes()
                  == (output / "host-second" / name).read_bytes())
          result["checks"].append({"name": stage, "status": "passed"})
      if target == "source":
        result["limitations"] = LIMITS + ["Host deployable export was not checked."]
    result["valid"] = True
  except (ManifestError, OSError, ValueError, KeyError, TypeError, RuntimeError, ImportError,
          zipfile.BadZipFile, EOFError, zlib.error) as error:
    code = getattr(error, "code", "SCHEMA_INVALID")
    if code not in CORRECTIONS:
      code = "SCHEMA_INVALID"
    result["checks"].append({"name": stage, "status": "failed"})
    # Exceptions can contain manifest values, paths or credentials; do not echo them.
    result["diagnostics"].append({"code": code, "stage": stage,
      "message": "Validation failed; input values are omitted.", "correction": CORRECTIONS[code]})
  return result


def check_examples():
  results = []
  for name, manifest, target, expected in (
      ("http", "http/manifest.json", "host", None),
      ("redis", "redis/manifest.json", "host", None),
      ("multi-service", "multi-service/manifest.yaml", "host", None)):
    result = check(ROOT / "fixtures" / manifest, target)
    codes = [item["code"] for item in result["diagnostics"]]
    matched = result["valid"] if expected is None else not result["valid"] and codes == [expected]
    results.append({"example": name, "expectedDiagnostic": expected,
                    "expectationMet": matched, "result": result})
  return {"valid": all(item["expectationMet"] for item in results), "scope": "example-suite",
          "examples": results, "limitations": LIMITS}


def main(argv=None):
  parser = argparse.ArgumentParser(description="Validate Mpack source or an offline source ZIP without executing software.")
  parser.add_argument("--json", action="store_true", help="emit a machine-readable report")
  commands = parser.add_subparsers(dest="command", required=True)
  source = commands.add_parser("source", help="compile, build and check reproducibility")
  source.add_argument("manifest", help="path to manifest.json, manifest.yaml or manifest.yml")
  source.add_argument("--target", choices=("host", "source"), default="host",
                      help="host checks deployable export; source checks authoring only (default: host)")
  bundle = commands.add_parser("bundle", help="verify a source ZIP, not legacy mpack.json/definition.tar.gz")
  bundle.add_argument("archive")
  bundle.add_argument("--sha256", required=True, help="SHA-256 obtained through an independently trusted channel")
  commands.add_parser("examples", help="check included HTTP, Redis and multi-service examples")
  review = commands.add_parser("review", help="validate baseline/candidate sources and report changes without applying them")
  review.add_argument("baseline")
  review.add_argument("candidate")
  args = parser.parse_args(argv)
  try:
    import jsonschema  # noqa: F401 -- fail clearly before validating user content
    if args.command in ("examples", "review") or (args.command == "source" and Path(args.manifest).suffix.lower() in (".yaml", ".yml")):
      import yaml  # noqa: F401
  except ImportError:
    result = {"valid": False, "scope": "environment", "diagnostics": [{"code": "TOOLING_UNAVAILABLE",
      "message": "Install mpack-authoring/requirements.txt using this Python interpreter."}]}
    code = 3
  else:
    if args.command == "examples":
      result = check_examples()
    elif args.command == "review":
      from mpack_authoring.review import review_changes
      result = review_changes(args.baseline, args.candidate)
    elif args.command == "bundle":
      result = check(args.archive, expected_digest=args.sha256)
    else:
      result = check(args.manifest, args.target)
    code = 0 if result["valid"] else 2
  if args.json:
    print(json.dumps(result, sort_keys=True))
  else:
    print("{}: {}".format("PASS" if result["valid"] else "FAIL", result["scope"]))
    reports = [(item["example"], item["result"]) for item in result.get("examples", [])] or [("validation", result)]
    for label, report in reports:
      print("{}: {}".format(label, "valid" if report["valid"] else "rejected"))
      for item in report.get("checks", []):
        print("  {}: {}".format(item["name"], item["status"]))
      for diagnostic in report.get("diagnostics", []):
        print("  {}: {}".format(diagnostic["code"], diagnostic.get("correction", diagnostic["message"])))
    for limit in result.get("limitations", []):
      print(limit)
    for change in result.get("changes", []):
      print("{} field {}".format(change["operation"], json.dumps(change["path"])))
    for change in result.get("files", []):
      print("{} file {}".format(change["operation"], json.dumps(change["path"])))
  return code


if __name__ == "__main__":
  sys.exit(main())
