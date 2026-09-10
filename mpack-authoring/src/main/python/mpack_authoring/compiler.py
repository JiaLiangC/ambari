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

import hashlib
import hmac
import io
import json
import os
import posixpath
import re
import tempfile
import urllib.parse
import zipfile
from pathlib import Path

from .manifest import ManifestError, validate_manifest
from .profiles import profile_capabilities


class CompileError(ManifestError):
  """The source cannot be compiled into a validated authoring bundle."""

  def __init__(self, message, code="SCHEMA_INVALID", path=""):
    super().__init__(message)
    self.code = code
    self.path = path


def load_source(path):
  """Load JSON or YAML source and return the document plus source format."""
  if os.path.getsize(path) > 1024 * 1024:
    raise CompileError("Manifest exceeds size limit")
  with open(path, "r", encoding="utf-8") as stream:
    content = stream.read()
  suffix = os.path.splitext(path)[1].lower()
  if suffix == ".json":
    try:
      return json.loads(content), "json"
    except ValueError as error:
      raise CompileError("invalid JSON source: {}".format(error)) from error
  if suffix not in (".yaml", ".yml"):
    try:
      return json.loads(content), "json"
    except ValueError:
      suffix = ".yaml"
  try:
    import yaml
  except ImportError as error:
    raise CompileError("YAML input requires the optional PyYAML package",
                       code="SCHEMA_INVALID") from error
  try:
    document = yaml.safe_load(content)
  except yaml.YAMLError as error:
    raise CompileError("invalid YAML source") from error
  return document, "yaml"


def _canonical(value):
  return json.dumps(value, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False)


def _sha256(path):
  digest = hashlib.sha256()
  with open(path, "rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
      digest.update(chunk)
  return digest.hexdigest()


def _relative(root, value, field):
  if not isinstance(value, str) or not value or os.path.isabs(value):
    raise CompileError("{} must be a relative package path".format(field),
                       code="PACKAGE_CONTENT_CONFLICT", path=field)
  root = os.path.realpath(root)
  if "\\" in value or any(part in ("", ".", "..") for part in value.split("/")):
    raise CompileError("{} must be a canonical package path".format(field),
                       code="PACKAGE_CONTENT_CONFLICT", path=field)
  lexical = root
  for part in value.split("/"):
    lexical = os.path.join(lexical, part)
    if os.path.islink(lexical):
      raise CompileError("symbolic links are not package inputs",
                         code="PACKAGE_CONTENT_CONFLICT", path=field)
  candidate = os.path.realpath(os.path.join(root, value))
  if os.path.commonpath((root, candidate)) != root:
    raise CompileError("{} escapes the package boundary".format(field),
                       code="PACKAGE_CONTENT_CONFLICT", path=field)
  return candidate


def _artifact_lock(manifest, root):
  entries = []
  for index, artifact in enumerate(manifest["spec"].get("artifacts", [])):
    source = artifact["source"]
    item = {"id": artifact["id"], "kind": source["kind"]}
    if source["kind"] == "file":
      field = "spec.artifacts[{}].source.path".format(index)
      resolved = _relative(root, source.get("path"), field)
      if not os.path.isfile(resolved) or os.path.islink(resolved):
        raise CompileError("{} must reference a regular file".format(field),
                           code="PACKAGE_CONTENT_CONFLICT", path=field)
      if source.get("sha256") and source["sha256"] != _sha256(resolved):
        raise CompileError("Local artifact digest mismatch", code="PACKAGE_CONTENT_CONFLICT", path=field)
      item.update({"path": posixpath.normpath(source["path"]),
                   "sha256": _sha256(resolved),
                   "size": os.path.getsize(resolved)})
    else:
      field = "spec.artifacts[{}].source.uri".format(index)
      uri = source.get("uri", source.get("url"))
      if not isinstance(uri, str) or not uri.strip():
        raise CompileError("{} requires a URI".format(field),
                           code="PACKAGE_CONTENT_CONFLICT",
                           path="spec.artifacts[{}].source".format(index))
      parsed = urllib.parse.urlparse(uri)
      if parsed.username or parsed.password:
        raise CompileError("remote artifact credentials must use a reference",
                           code="PACKAGE_CONTENT_CONFLICT",
                           path="spec.artifacts[{}].source".format(index))
      item["uri"] = uri
      if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.query or parsed.fragment:
        raise CompileError("remote artifacts require an HTTP(S) URI without query credentials",
                           code="PACKAGE_CONTENT_CONFLICT", path=field)
      if not re.fullmatch(r"[a-f0-9]{64}", source.get("sha256", "")):
        raise CompileError("remote artifacts require a lowercase SHA-256 digest",
                           code="PACKAGE_CONTENT_CONFLICT", path=field)
      item["sha256"] = source["sha256"]
    entries.append(item)
  return sorted(entries, key=lambda entry: entry["id"])


def _dependency_lock(manifest):
  requirements = []
  spec = manifest["spec"]
  declared = spec.get("dependencies", [])
  if not isinstance(declared, list):
    raise CompileError("spec.dependencies must be a list", path="spec.dependencies")
  for index, requirement in enumerate(declared):
    requirements.append(_dependency(requirement, "spec.dependencies[{}]".format(index)))
  for service_index, service in enumerate(spec.get("services", [])):
    declared = service.get("requires", [])
    if not isinstance(declared, list):
      raise CompileError("service requires must be a list", path="spec.services[{}].requires".format(service_index))
    for index, requirement in enumerate(declared):
      item = _dependency(requirement, "spec.services[{}].requires[{}]".format(service_index, index))
      item["consumer"] = service["name"]
      requirements.append(item)
  keys = set()
  for requirement in requirements:
    key = (requirement.get("consumer"), requirement["slot"])
    if key in keys:
      raise CompileError("duplicate dependency slot {}".format(requirement["slot"]),
                         code="DEPENDENCY_UNRESOLVED")
    keys.add(key)
  return sorted(requirements, key=lambda item: (item.get("consumer", ""), item["slot"]))


def _dependency(value, path):
  if not isinstance(value, dict):
    raise CompileError("{} must be an object".format(path), path=path)
  slot = value.get("slot", value.get("name"))
  interface = value.get("interface")
  version = value.get("versionRange", value.get("version", "*"))
  if not all(isinstance(item, str) and item.strip() for item in (slot, interface, version)):
    raise CompileError("{} requires slot, interface and versionRange".format(path),
                       code="DEPENDENCY_UNRESOLVED", path=path)
  return {"slot": slot, "interface": interface, "versionRange": version}


def _references(manifest, root):
  """Validate config/profile references and known adapter capability bounds."""
  _check_keys(manifest, {"apiVersion", "kind", "metadata", "spec"}, "manifest")
  _check_keys(manifest["metadata"], {"name", "version", "displayName", "description", "publisher"},
              "metadata")
  _check_keys(manifest["spec"], {"compatibility", "artifacts", "services",
                                  "dependencies", "serviceGroups", "service_groups"}, "spec")
  for field, value in manifest["spec"].get("compatibility", {}).items():
    if field in ("ambari", "agentSdk") and value != "*" and any(
        not re.fullmatch(r"(?:>=|<=|>|<|=)?[0-9]+(?:\.[0-9]+){0,3}", item.strip())
        for item in value.split(",")):
      raise CompileError("Compatibility uses comma-separated numeric version comparisons",
                         path="spec.compatibility." + field)
  known = {"artifacts": {item["id"] for item in manifest["spec"].get("artifacts", [])}}
  for service_index, service in enumerate(manifest["spec"].get("services", [])):
    service_path = "spec.services[{}]".format(service_index)
    _check_keys(service, {"name", "description", "configurations", "components",
                          "requires", "provides", "operations", "observability"}, service_path)
    configurations = service.get("configurations", [])
    if not isinstance(configurations, list):
      raise CompileError("configurations must be a list", path="spec.services[{}].configurations".format(service_index))
    for config_index, config in enumerate(configurations):
      if not isinstance(config, dict):
        raise CompileError("configuration must be an object", path="spec.services[{}].configurations[{}]".format(service_index, config_index))
      _check_keys(config, {"name", "schema", "template", "changeEffect", "defaults",
                           "description"}, "spec.services[{}].configurations[{}]".format(service_index, config_index))
      for field in ("schema", "template"):
        if config.get(field) is not None:
          field_path = "spec.services[{}].configurations[{}].{}".format(service_index, config_index, field)
          resolved = _relative(root, config[field], field_path)
          if not os.path.isfile(resolved) or os.path.islink(resolved):
            raise CompileError("{} must reference a regular file".format(field_path),
                               code="PACKAGE_CONTENT_CONFLICT", path=field_path)
    observability = service.get("observability", {})
    _check_keys(observability, {"logs", "metrics"}, service_path + ".observability")
    components = {component["name"]: component for component in service.get("components", [])}
    for kind, entries in observability.items():
      if not isinstance(entries, dict):
        raise CompileError("Observability entries must be component mappings", path=service_path + ".observability")
      for component, definition in entries.items():
        if component not in components or components[component].get("category") == "CLIENT":
          raise CompileError("Observability must reference an assigned server component", path=service_path + ".observability")
        if kind == "metrics":
          if not isinstance(definition, dict) or not isinstance(definition.get("portRef"), str):
            raise CompileError("Metric declaration requires a port reference", path=service_path + ".observability.metrics")
          config_name, _, field_name = definition["portRef"].partition(".")
          config = next((item for item in configurations if item["name"] == config_name), None)
          schema = json.loads(Path(_relative(root, config["schema"], service_path)).read_text()) if config else {}
          field = schema.get("properties", {}).get(field_name, {})
          if (field.get("type") != "integer" or field.get("minimum", 0) < 1
              or field.get("maximum", 65536) > 65535 or field.get("x-sensitive") or field.get("x-resource")):
            raise CompileError("Metric port must reference an integer configuration bounded to 1..65535", path=service_path + ".observability.metrics")
    for component_index, component in enumerate(service.get("components", [])):
      component_path = "{}.components[{}]".format(service_path, component_index)
      _check_keys(component, {"name", "category", "role", "cardinality", "profiles", "softwareVersion"}, component_path)
      for profile_index, profile in enumerate(component.get("profiles", [])):
        path = "spec.services[{}].components[{}].profiles[{}]".format(service_index, component_index, profile_index)
        _check_keys(profile, {"id", "adapter", "capabilities", "resources", "health", "upgradePolicy"}, path)
        try:
          supported = profile_capabilities(profile["adapter"])
        except (KeyError, ValueError) as error:
          raise CompileError("unsupported runtime adapter {}".format(profile.get("adapter")),
                             code="CAPABILITY_UNSUPPORTED", path=path) from error
        requested = set(profile.get("capabilities", []))
        unsupported = requested - supported
        if unsupported:
          raise CompileError("{} declares unsupported capabilities: {}".format(
              path, ", ".join(sorted(unsupported))), code="CAPABILITY_UNSUPPORTED", path=path)
        resources = profile.get("resources", {})
        for artifact_ref in _find_artifact_refs(resources):
          if artifact_ref not in known["artifacts"]:
            raise CompileError("unknown artifact reference {}".format(artifact_ref),
                               code="PACKAGE_CONTENT_CONFLICT", path=path)
  if manifest["spec"].get("serviceGroups") or manifest["spec"].get("service_groups"):
    raise CompileError("ServiceGroup identity is outside the current service contract",
                       code="TARGET_CONFLICT", path="spec.serviceGroups")


def _check_keys(mapping, allowed, path):
  if not isinstance(mapping, dict):
    return
  unknown = sorted(set(mapping) - allowed)
  if unknown:
    raise CompileError("{} contains unknown field(s): {}".format(
        path, ", ".join(unknown)), path=path)


def _find_artifact_refs(value):
  if isinstance(value, dict):
    for key, child in value.items():
      if key == "artifactRef" and isinstance(child, str):
        yield child
      else:
        yield from _find_artifact_refs(child)
  elif isinstance(value, list):
    for child in value:
      yield from _find_artifact_refs(child)


def legacy_projection(manifest):
  """Project compatible service metadata without changing service identity."""
  services = []
  for service in manifest["spec"].get("services", []):
    components = []
    for component in service.get("components", []):
      item = {"name": component["name"],
              "category": component.get("category", "SLAVE"),
              "role": component.get("role", "service")}
      components.append(item)
    services.append({"name": service["name"], "components": components})
  return {"format": "ambari-legacy-mpack-projection/v1", "services": services}


def compile_manifest(path):
  document, source_format = load_source(path)
  root = os.path.dirname(os.path.realpath(path))
  validated = validate_manifest(document, root)
  artifacts = validated["artifacts"]
  dependencies = validated["dependencies"]
  compiled = {
      "format": "mpack.ambari.apache.org/compiled/v1",
      "sourceFormat": source_format,
      "manifest": document,
      "canonical": validated["canonical"],
      "manifestDigest": validated["digest"],
      "artifacts": artifacts,
      "dependencies": dependencies,
      "legacy": legacy_projection(document),
      "provenance": {"source": os.path.basename(path), "compiler": "mpack-authoring/v1"},
  }

  compiled["files"] = payload_lock(compiled, root)
  compiled["packageDigest"] = hashlib.sha256(_canonical({
      "manifest": document, "artifacts": artifacts, "dependencies": dependencies,
      "files": compiled["files"]}).encode("utf-8")).hexdigest()
  return compiled


def package_files(compiled, root):
  """Return only declared payloads; directory neighbors are never build inputs."""
  paths = {item["path"] for item in compiled["artifacts"] if item["kind"] == "file"}
  for service in compiled["manifest"]["spec"]["services"]:
    for config in service.get("configurations", []):
      paths.update(config[field] for field in ("schema", "template") if config.get(field))
  return [(relative, _relative(root, relative, relative)) for relative in sorted(paths)]


def payload_lock(compiled, root):
  return [{"path": relative, "sha256": _sha256(path), "size": os.path.getsize(path)}
          for relative, path in package_files(compiled, root)]


def _zip_bytes(compiled, root):
  inventory = compiled["files"]
  if len(inventory) > 10000 or sum(item["size"] for item in inventory) > 512 * 1024 * 1024:
    raise CompileError("Declared payload exceeds size limit", code="PACKAGE_CONTENT_CONFLICT")
  output = io.BytesIO()
  with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    entries = {
        "mpack/files.lock.json": json.dumps(inventory, sort_keys=True) + "\n",
        "mpack/manifest.json": _canonical(compiled["manifest"]) + "\n",
        "mpack/artifacts.lock.json": json.dumps(compiled["artifacts"], sort_keys=True, indent=2) + "\n",
        "mpack/dependencies.lock.json": json.dumps(compiled["dependencies"], sort_keys=True, indent=2) + "\n",
        "mpack/legacy/stack.json": json.dumps(compiled["legacy"], sort_keys=True, indent=2) + "\n",
        "mpack/provenance.json": json.dumps({key: value for key, value in compiled.items()
                                               if key not in ("manifest", "canonical")},
                                              sort_keys=True, indent=2) + "\n",
    }
    for name, content in sorted(entries.items()):
      info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
      info.compress_type = zipfile.ZIP_DEFLATED
      info.external_attr = 0o100644 << 16
      archive.writestr(info, content.encode("utf-8"))
    for relative, path in package_files(compiled, root):
      info = zipfile.ZipInfo("payload/" + relative, date_time=(1980, 1, 1, 0, 0, 0))
      info.compress_type = zipfile.ZIP_DEFLATED
      info.external_attr = 0o100644 << 16
      with open(path, "rb") as stream:
        data = stream.read()
      locked = next(item for item in inventory if item["path"] == relative)
      if hashlib.sha256(data).hexdigest() != locked["sha256"] or len(data) != locked["size"]:
        raise CompileError("Package input changed during build", code="PACKAGE_CONTENT_CONFLICT")
      archive.writestr(info, data)
  return output.getvalue()


def sign_bytes(content, key):
  if not isinstance(key, bytes) or not key:
    raise ValueError("signing key must be non-empty bytes")
  return {"algorithm": "HMAC-SHA256", "digest": hmac.new(key, content, hashlib.sha256).hexdigest()}


def build_package(manifest_path, output_path, signing_key=None):
  compiled = compile_manifest(manifest_path)
  root = os.path.dirname(os.path.realpath(manifest_path))
  if any(item["kind"] != "file" for item in compiled["artifacts"]):
    raise CompileError("Offline export requires vendored file artifacts",
                       code="PACKAGE_CONTENT_CONFLICT")
  inputs = {os.path.realpath(path) for _, path in package_files(compiled, root)}
  inputs.add(os.path.realpath(manifest_path))
  if any(os.path.realpath(path) in inputs for path in (output_path, output_path + ".sig")):
    raise CompileError("Output must not overwrite a package input", code="PACKAGE_CONTENT_CONFLICT")
  if signing_key is not None:
    for _, input_path in package_files(compiled, root):
      if os.path.getsize(input_path) == len(signing_key):
        with open(input_path, "rb") as stream:
          if hmac.compare_digest(stream.read(), signing_key):
            raise CompileError("Signing key cannot be a declared payload", code="PACKAGE_CONTENT_CONFLICT")
  content = _zip_bytes(compiled, root)
  # Verify the exact bytes against the compiled locks before publication.
  with tempfile.NamedTemporaryFile(dir=os.path.dirname(os.path.abspath(output_path)), delete=False) as stream:
    temporary = stream.name
    stream.write(content)
    stream.flush()
    os.fsync(stream.fileno())
  try:
    verify_package(temporary, hashlib.sha256(content).hexdigest())
    os.replace(temporary, output_path)
  finally:
    if os.path.exists(temporary):
      os.unlink(temporary)
  signature = None
  if signing_key is not None:
    signature = sign_bytes(content, signing_key)
    with open(output_path + ".sig", "w", encoding="utf-8") as stream:
      json.dump(signature, stream, sort_keys=True, indent=2)
      stream.write("\n")
  return {"path": output_path, "sha256": hashlib.sha256(content).hexdigest(),
          "manifestDigest": compiled["manifestDigest"], "signature": signature,
          "compiled": compiled}


def verify_package(path, expected_digest, signing_key=None, signature=None):
  """Verify an offline tooling bundle using bounded temporary extraction, without execution.

  expected_digest must come from a trusted caller, not from this archive.
  This is not an Ambari registration or Agent execution endpoint.
  """
  if os.path.getsize(path) > 512 * 1024 * 1024:
    raise CompileError("Bundle exceeds size limit", code="PACKAGE_CONTENT_CONFLICT")
  with open(path, "rb") as stream:
    content = stream.read()
  if not isinstance(expected_digest, str) or not hmac.compare_digest(
      hashlib.sha256(content).hexdigest(), expected_digest):
    raise CompileError("Bundle digest mismatch", code="PACKAGE_CONTENT_CONFLICT")
  if signing_key is not None:
    expected = sign_bytes(content, signing_key)
    if not isinstance(signature, dict) or signature.get("algorithm") != expected["algorithm"] or not hmac.compare_digest(
        str(signature.get("digest", "")), expected["digest"]):
      raise CompileError("Bundle authentication failed", code="AUTHORIZATION_DENIED")
  with zipfile.ZipFile(io.BytesIO(content)) as archive:
    infos = archive.infolist()
    names = [item.filename for item in infos]
    if len(names) != len(set(names)) or len(names) > 10000 or sum(item.file_size for item in infos) > 512 * 1024 * 1024:
      raise CompileError("Invalid bundle inventory", code="PACKAGE_CONTENT_CONFLICT")
    lock = json.loads(archive.read("mpack/files.lock.json"))
    metadata = {"mpack/manifest.json", "mpack/files.lock.json", "mpack/artifacts.lock.json",
                "mpack/dependencies.lock.json", "mpack/legacy/stack.json", "mpack/provenance.json"}
    if set(names) != metadata | {"payload/" + item["path"] for item in lock}:
      raise CompileError("Bundle inventory mismatch", code="PACKAGE_CONTENT_CONFLICT")
    with tempfile.TemporaryDirectory(prefix="mpack-verify-") as root:
      for item in lock:
        target = _relative(root, item["path"], "inventory")
        data = archive.read("payload/" + item["path"])
        if len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
          raise CompileError("Payload digest mismatch", code="PACKAGE_CONTENT_CONFLICT")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as stream:
          stream.write(data)
      manifest = json.loads(archive.read("mpack/manifest.json"))
      validated = validate_manifest(manifest, root)
      compiled = {"manifest": manifest, "artifacts": validated["artifacts"]}
      if payload_lock(compiled, root) != lock or any(item["kind"] != "file" for item in validated["artifacts"]):
        raise CompileError("Bundle is not a complete offline inventory", code="PACKAGE_CONTENT_CONFLICT")
      for name, value in (("artifacts", validated["artifacts"]), ("dependencies", validated["dependencies"])):
        if json.loads(archive.read("mpack/" + name + ".lock.json")) != value:
          raise CompileError("Lock does not match manifest", code="PACKAGE_CONTENT_CONFLICT")
  return {"manifestDigest": validated["digest"], "sha256": expected_digest}
