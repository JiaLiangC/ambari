"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

from dataclasses import asdict, dataclass

from .compiler import CompileError, compile_manifest
from .manifest import ManifestError, validate_manifest

DIAGNOSTIC_CODES = {
  "CAPABILITY_UNSUPPORTED", "DEPENDENCY_UNRESOLVED", "PLAN_STALE",
  "TARGET_CONFLICT", "AUTHORIZATION_DENIED", "OUTCOME_UNKNOWN", "SCHEMA_INVALID",
  "PACKAGE_CONTENT_CONFLICT",
}


@dataclass(frozen=True)
class Diagnostic:
  code: str
  severity: str
  message: str
  path: str = ""
  retryable: bool = False
  correction: str = ""

  def as_dict(self):
    return asdict(self)


def make_diagnostic(code, message, path="", severity="ERROR", retryable=False,
                    correction=""):
  if code not in DIAGNOSTIC_CODES:
    raise ValueError("Unknown diagnostic code {}".format(code))
  return Diagnostic(code, severity, message, path, retryable, correction)


def validate_with_diagnostics(manifest, package_root=None):
  """Return a validation result with stable structured diagnostics."""
  try:
    result = validate_manifest(manifest, package_root)
    return {"valid": True, "diagnostics": [], **result}
  except ManifestError as error:
    message = str(error)
    path = message.split(" must ", 1)[0] if " must " in message else ""
    diagnostic = make_diagnostic("SCHEMA_INVALID", message, path=path,
                                 correction="Correct the manifest field and validate again.")
    return {"valid": False, "diagnostics": [diagnostic.as_dict()]}


def compile_with_diagnostics(path):
  """Compile a source manifest while preserving stable machine diagnostics."""
  try:
    result = compile_manifest(path)
    return {"valid": True, "diagnostics": [], **result}
  except (CompileError, ManifestError, OSError, ValueError) as error:
    code = getattr(error, "code", "SCHEMA_INVALID")
    if code not in DIAGNOSTIC_CODES:
      code = "SCHEMA_INVALID"
    diagnostic = make_diagnostic(
        code, str(error), path=getattr(error, "path", ""),
        correction="Correct the source field and compile again.")
    return {"valid": False, "diagnostics": [diagnostic.as_dict()]}
