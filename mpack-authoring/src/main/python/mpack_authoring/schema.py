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
from pathlib import Path

from .manifest import ManifestError


def validate_schema(manifest, root):
  """Validate source shape, config schemas/defaults and scoped references offline."""
  try:
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError
  except ImportError as error:
    raise ManifestError("Authoring requires jsonschema; see mpack-authoring/requirements.txt") from error
  from .compiler import _relative, CompileError
  schema_path = Path(__file__).with_name("manifest-v2alpha1.json")
  if not schema_path.is_file():
    schema_path = Path(__file__).resolve().parents[4] / "schema/manifest-v2alpha1.json"
  schema = json.loads(schema_path.read_text(encoding="utf-8"))
  error = next(Draft202012Validator(schema).iter_errors(manifest), None)
  if error:
    # Do not copy input values into diagnostics (including secrets).
    raise CompileError("Invalid field type or constraint", path=".".join(map(str, error.absolute_path)))
  for service in manifest["spec"]["services"]:
    configs = {}
    for config in service.get("configurations", []):
      if config["name"] in configs:
        raise ManifestError("Duplicate configuration name")
      with open(_relative(root, config["schema"], "configuration.schema"), encoding="utf-8") as stream:
        definition = json.load(stream)
      if not isinstance(definition, dict):
        raise ManifestError("Configuration schema must describe an object")
      _local_schema(definition)
      try:
        Draft202012Validator.check_schema(definition)
      except SchemaError as error:
        raise ManifestError("Invalid configuration schema") from error
      if definition.get("type") != "object":
        raise ManifestError("Configuration schema must describe an object")
      defaults = dict(config.get("defaults", {}))
      for name, field in definition.get("properties", {}).items():
        if "default" in field:
          defaults.setdefault(name, field["default"])
        if field.get("x-sensitive") and name in defaults:
          value = defaults[name]
          if not isinstance(value, dict) or set(value) != {"secretRef"} or not isinstance(value["secretRef"], str) or not value["secretRef"]:
            raise ManifestError("Sensitive defaults require a secret reference")
      # Required fields may be supplied at deployment; supplied defaults must
      # already meet types/ranges/nested constraints.
      partial = dict(definition, required=[])
      if next(Draft202012Validator(partial).iter_errors(defaults), None):
        raise ManifestError("Configuration defaults violate schema")
      configs[config["name"]] = definition
    for component in service["components"]:
      for profile in component["profiles"]:
        resources = profile.get("resources", {})
        health = profile.get("health", {})
        if health.get("kind") in ("tcp", "http") and not health.get("portRef"):
          raise ManifestError("Network health checks require a scoped port reference")
        if health.get("kind") == "http" and (not health.get("path", "/").startswith("/")
            or any(char in health.get("path", "/") for char in ("\r", "\n", "\0"))):
          raise ManifestError("HTTP health path must be an absolute local path")
        for collection, key in (("directories", "path"), ("users", "name"), ("ports", "name")):
          names = [item[key] for item in resources.get(collection, [])]
          if len(names) != len(set(names)):
            raise ManifestError("Duplicate resource declaration")
        directories = {item["path"] for item in resources.get("directories", [])}
        references = list(_references(profile))
        references.extend(("portRef", port["configRef"]) for port in resources.get("ports", []))
        for kind, reference in references:
          if kind == "directoryRef":
            if reference not in directories:
              raise ManifestError("Unknown directory reference")
            continue
          if kind == "configurationRef":
            if reference not in configs or not any(value["name"] == reference and value.get("template")
                for value in service.get("configurations", [])):
              raise ManifestError("Configuration file reference requires a declared template")
            continue
          parts = reference.split(".")
          if len(parts) < 2 or parts[0] not in configs:
            raise ManifestError("Unknown configuration reference")
          field = configs[parts[0]]
          for part in parts[1:]:
            field = field.get("properties", {}).get(part)
            if not isinstance(field, dict):
              raise ManifestError("Unknown configuration field reference")
          if kind == "portRef" and (field.get("type") != "integer" or field.get("minimum", 0) < 1 or field.get("maximum", 65536) > 65535):
            raise ManifestError("Port reference requires an integer in 1..65535")


def _references(value):
  if isinstance(value, dict):
    for key, child in value.items():
      if key in ("configRef", "portRef", "directoryRef", "configurationRef"):
        yield key, child
      else:
        yield from _references(child)
  elif isinstance(value, list):
    for child in value:
      yield from _references(child)


def _local_schema(value):
  if isinstance(value, dict):
    for key, child in value.items():
      if key in ("$ref", "$dynamicRef") and (not isinstance(child, str) or not child.startswith("#")):
        raise ManifestError("Configuration schemas must use local references")
      if key == "$id":
        raise ManifestError("Configuration schemas cannot change reference scope")
      _local_schema(child)
  elif isinstance(value, list):
    for child in value:
      _local_schema(child)
