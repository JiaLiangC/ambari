"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

from dataclasses import asdict, dataclass

from .manifest import ManifestError, validate_manifest


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


def validate_with_diagnostics(manifest, package_root=None):
  """Return a validation result with stable structured diagnostics."""
  try:
    result = validate_manifest(manifest, package_root)
    return {"valid": True, "diagnostics": [], **result}
  except ManifestError as error:
    message = str(error)
    path = message.split(" must ", 1)[0] if " must " in message else ""
    diagnostic = Diagnostic(
      code="SCHEMA_INVALID",
      severity="ERROR",
      message=message,
      path=path,
      correction="Correct the manifest field and validate again.",
    )
    return {"valid": False, "diagnostics": [diagnostic.as_dict()]}
