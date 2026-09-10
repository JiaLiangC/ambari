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

import gzip
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import tarfile
import xml.etree.ElementTree as ET

from .compiler import CompileError, compile_manifest, package_files


FORMAT = "mpack.ambari.apache.org/host-service/v1"


def _has_secret_reference(value):
  if isinstance(value, dict):
    return "secretRef" in value or any(_has_secret_reference(child) for child in value.values())
  if isinstance(value, list):
    return any(_has_secret_reference(child) for child in value)
  return False


def _xml(parent, tag, text=None):
  child = ET.SubElement(parent, tag)
  if text is not None:
    child.text = str(text)
  return child


def _archive(entries):
  output = io.BytesIO()
  with gzip.GzipFile(fileobj=output, mode="wb", mtime=0, filename="") as compressed:
    with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
      for name, data in sorted(entries.items()):
        entry = tarfile.TarInfo(name)
        entry.size = len(data)
        entry.mode = 0o644
        entry.mtime = 0
        archive.addfile(entry, io.BytesIO(data))
  return output.getvalue()


def _config_xml(config, payload):
  definition = json.loads(payload[config["schema"]])
  if set(definition) - {"$schema", "title", "description", "type", "additionalProperties", "properties", "required"} or definition.get("additionalProperties") is not False:
    raise CompileError("Host configuration requires a closed scalar schema",
                       code="CAPABILITY_UNSUPPORTED")
  # This version exposes the scalar Ambari property model. Complex or sensitive
  # schemas remain authorable, but cannot be exported to an unsupported runtime.
  document = ET.Element("configuration")
  for name, field in definition.get("properties", {}).items():
    if field.get("x-resource"):
      if field.get("type") != "string" or set(field) - {"type", "description", "x-resource"}:
        raise CompileError("Managed directory fields cannot declare user defaults or constraints",
                           code="CAPABILITY_UNSUPPORTED")
      continue
    if field.get("type") not in ("string", "integer", "number", "boolean") or field.get("x-sensitive"):
      raise CompileError("Host export supports non-secret scalar configuration only",
                         code="CAPABILITY_UNSUPPORTED")
    if set(field) - {"type", "default", "description", "minimum", "maximum", "enum", "minLength", "maxLength"}:
      raise CompileError("Configuration constraint is unsupported by host-service/v1",
                         code="CAPABILITY_UNSUPPORTED")
    prop = _xml(document, "property")
    _xml(prop, "name", name)
    default = config.get("defaults", {}).get(name, field.get("default", ""))
    _xml(prop, "value", str(default).lower() if isinstance(default, bool) else default)
    _xml(prop, "description", field.get("description", name))
    attributes = _xml(prop, "value-attributes")
    _xml(attributes, "type", {"integer": "int", "number": "float", "boolean": "boolean"}.get(field["type"], "string"))
    if "minimum" in field:
      _xml(attributes, "minimum", field["minimum"])
    if "maximum" in field:
      _xml(attributes, "maximum", field["maximum"])
  return ET.tostring(document, encoding="utf-8", xml_declaration=True)


def _service_xml(service, version):
  document = ET.Element("metainfo")
  _xml(document, "schemaVersion", "2.0")
  node = _xml(_xml(document, "services"), "service")
  _xml(node, "name", service["name"])
  _xml(node, "displayName", service["name"])
  _xml(node, "comment", service.get("description", "Declarative host service"))
  _xml(node, "version", version)
  components = _xml(node, "components")
  for component in service["components"]:
    child = _xml(components, "component")
    _xml(child, "name", component["name"])
    _xml(child, "displayName", component["name"])
    _xml(child, "category", component.get("category", "SLAVE"))
    bounds = component.get("cardinality", {"min": 1, "max": 1})
    cardinality = str(bounds["min"]) if bounds["min"] == bounds["max"] else (str(bounds["min"]) + "+" if bounds["max"] == "*" else "{}-{}".format(bounds["min"], bounds["max"]))
    _xml(child, "cardinality", cardinality)
    _xml(child, "versionAdvertised", "false")
    _xml(child, "recovery_enabled", "false")
    script = _xml(child, "commandScript")
    _xml(script, "script", "scripts/manifest_service.py")
    _xml(script, "scriptType", "PYTHON")
    _xml(script, "timeout", "600")
    dependencies = _xml(child, "configuration-dependencies")
    for config in service.get("configurations", []):
      _xml(dependencies, "config-type", config["name"])
  script = _xml(node, "commandScript")
  _xml(script, "script", "scripts/manifest_service.py")
  _xml(script, "scriptType", "PYTHON")
  _xml(script, "timeout", "120")
  return ET.tostring(document, encoding="utf-8", xml_declaration=True)


def export_legacy(manifest_path, output_directory, signing_key):
  """Emit the actual legacy V2 registration format with one shared host Script.

  The caller supplies the signing key used by the server's configured trust file.
  No package/runtime operation is performed during export.
  """
  if not isinstance(signing_key, bytes) or not signing_key:
    raise CompileError("Host-service export requires an external signing key")
  compiled = compile_manifest(manifest_path)
  if compiled["dependencies"]:
    raise CompileError("Host export requires an integrated shared dependency client",
                       code="DEPENDENCY_UNRESOLVED")
  if any(item["kind"] != "file" for item in compiled["artifacts"]):
    raise CompileError("Host export requires vendored artifacts", code="PACKAGE_CONTENT_CONFLICT")
  root = Path(manifest_path).resolve().parent
  output = Path(output_directory).resolve()
  if output == root or root in output.parents:
    raise CompileError("Legacy export directory must be outside the source package")
  if output.exists() and any(output.iterdir()):
    raise CompileError("Legacy export directory must be empty")
  manifest = compiled["manifest"]
  metadata = {"id": manifest["metadata"]["name"], "name": manifest["metadata"]["name"],
    "version": manifest["metadata"]["version"], "definition": "definition.tar.gz", "modules": [],
    "authoringFormat": FORMAT, "manifestDigest": compiled["manifestDigest"], "packageDigest": compiled["packageDigest"]}
  inventory = compiled["files"]
  if len(inventory) > 10000 or sum(item["size"] for item in inventory) > 512 * 1024 * 1024:
    raise CompileError("Declared payload exceeds size limit", code="PACKAGE_CONTENT_CONFLICT")
  locked = {item["path"]: item for item in inventory}
  payload = {}
  for name, path in package_files(compiled, str(root)):
    data = Path(path).read_bytes()
    if len(data) != locked[name]["size"] or hashlib.sha256(data).hexdigest() != locked[name]["sha256"]:
      raise CompileError("Package input changed during export", code="PACKAGE_CONTENT_CONFLICT")
    if data == signing_key:
      raise CompileError("Signing key cannot be a declared payload")
    payload[name] = data
  entries = {}
  for service in manifest["spec"]["services"]:
    for component in service["components"]:
      if component.get("category") == "CLIENT":
        raise CompileError("Host-service/v1 requires a foreground server component",
                           code="CAPABILITY_UNSUPPORTED")
      if len(component["profiles"]) != 1 or component["profiles"][0]["adapter"] != "host.systemd/v1":
        raise CompileError("Host export requires one explicit host profile per component",
                           code="CAPABILITY_UNSUPPORTED")
      profile = component["profiles"][0]
      resources = profile.get("resources", {})
      if _has_secret_reference(resources):
        raise CompileError("Host-service/v1 does not resolve execution secrets", code="CAPABILITY_UNSUPPORTED")
      if not resources.get("command", {}).get("program") or not resources.get("unit", {}).get("user"):
        raise CompileError("Host export requires a program and unit user")
      for directory in resources.get("directories", []):
        if directory["path"].startswith("/") or "/" in directory["path"] or directory["path"] in (".", ".."):
          raise CompileError("Host directories must be single names scoped to the deployment")
      directories = {item["path"] for item in resources.get("directories", [])}
      working = resources.get("unit", {}).get("workingDirectory")
      if working and working not in directories:
        raise CompileError("Working directory must reference a declared directory")
      for config in service.get("configurations", []):
        schema = json.loads(payload[config["schema"]])
        if any(field.get("x-resource") and field["x-resource"] not in directories
               for field in schema.get("properties", {}).values()):
          raise CompileError("Configuration references an undeclared managed directory")
        if config.get("template"):
          template = payload[config["template"]].decode("utf-8")
          references = re.findall(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}", template)
          remainder = re.sub(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}", "", template)
          if "{{" in remainder or "{%" in template or "{#" in template or set(references) - set(schema.get("properties", {})):
            raise CompileError("Host templates support declared scalar fields only", code="CAPABILITY_UNSUPPORTED")
      if any(config.get("changeEffect", "restart") != "restart" for config in service.get("configurations", [])):
        raise CompileError("Host-service/v1 configuration changes require restart semantics",
                           code="CAPABILITY_UNSUPPORTED")
    module_entries = {"metainfo.xml": _service_xml(service, metadata["version"])}
    descriptor = {"format": FORMAT, "package": {"name": metadata["name"], "version": metadata["version"],
      "digest": compiled["packageDigest"]}, "service": service,
      "artifacts": compiled["artifacts"], "files": inventory}
    module_entries["package/manifest-service.json"] = json.dumps(descriptor, sort_keys=True).encode()
    module_entries["package/scripts/manifest_service.py"] = (
      '"""\n' + __doc__ + '\n"""\n'
      + "from resource_management.libraries.script.manifest_service import ManifestService\n"
      "ManifestService().execute()\n").encode()
    for name, data in payload.items():
      module_entries["package/payload/" + name] = data
    for config in service.get("configurations", []):
      module_entries["configuration/" + config["name"] + ".xml"] = _config_xml(config, payload)
    module_name = service["name"] + ".tar.gz"
    entries["modules/" + module_name] = _archive(module_entries)
    metadata["modules"].append({"id": service["name"], "name": service["name"], "category": "SERVER",
      "version": metadata["version"], "definition": module_name, "components": [
        {"id": component["name"], "name": component["name"], "category": component.get("category", "SLAVE"),
         "version": metadata["version"]} for component in service["components"]]})
  archive = _archive({"definition/" + name: data for name, data in entries.items()})
  metadata["definitionSha256"] = hashlib.sha256(archive).hexdigest()
  signed = "mpack-legacy/v1\n{}\n{}\n{}\n{}\n{}\n".format(metadata["name"], metadata["version"],
             metadata["definitionSha256"], metadata["manifestDigest"], metadata["packageDigest"]).encode()
  metadata["signature"] = hmac.new(signing_key, signed, hashlib.sha256).hexdigest()
  metadata["signatureAlgorithm"] = "HMAC-SHA256"
  output.mkdir(parents=True, exist_ok=True)
  (output / metadata["definition"]).write_bytes(archive)
  (output / "mpack.json").write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
  return {"metadata": str(output / "mpack.json"), "definitionSha256": metadata["definitionSha256"],
          "manifestDigest": metadata["manifestDigest"]}
