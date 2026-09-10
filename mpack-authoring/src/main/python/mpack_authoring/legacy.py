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
from .trust import catalog_name, sign_release


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
    if field.get("x-sensitive"):
      expected = {"type": "object", "properties": {"secretRef": {"type": "string"}},
                  "required": ["secretRef"], "additionalProperties": False}
      if any(field.get(key) != value for key, value in expected.items()) or set(field) - set(expected) - {"x-sensitive", "description", "default", "x-secret-encoding"}:
        raise CompileError("Sensitive configuration requires a closed secretRef object")
      default = config.get("defaults", {}).get(name, field.get("default"))
      if not isinstance(default, dict) or set(default) != {"secretRef"} or not str(default["secretRef"]).startswith("secret://mpack."):
        raise CompileError("Host secret fields require an explicit scoped credential reference")
      if field.get("x-secret-encoding", "json-string") not in ("json-string", "literal"):
        raise CompileError("Unsupported secret rendering encoding")
      prop = _xml(document, "property")
      _xml(prop, "name", name)
      _xml(prop, "value", default["secretRef"])
      _xml(prop, "description", field.get("description", "Scoped credential reference"))
      _xml(prop, "property-type", "SECRET_REFERENCE")
      _xml(_xml(prop, "value-attributes"), "type", "string")
      continue
    if field.get("type") not in ("string", "integer", "number", "boolean"):
      raise CompileError("Host export supports non-secret scalar configuration only",
                         code="CAPABILITY_UNSUPPORTED")
    if set(field) - {"type", "default", "description", "minimum", "maximum", "enum", "minLength", "maxLength"}:
      raise CompileError("Configuration constraint is unsupported by host-service/v1",
                         code="CAPABILITY_UNSUPPORTED")
    prop = _xml(document, "property")
    _xml(prop, "name", name)
    default = config.get("defaults", {}).get(name, field.get("default", ""))
    _xml(prop, "value", str(default).lower() if isinstance(default, bool) else default)
    description = field.get("description", name)
    if "minLength" in field or "maxLength" in field:
      description += " Length: {}..{} Unicode characters.".format(field.get("minLength", 0), field.get("maxLength", 65536))
    _xml(prop, "description", description)
    attributes = _xml(prop, "value-attributes")
    _xml(attributes, "type", {"integer": "int", "number": "float", "boolean": "boolean"}.get(field["type"], "string"))
    empty_valid = field["type"] == "string" and field.get("minLength", 0) == 0 and ("enum" not in field or "" in field["enum"])
    _xml(attributes, "empty-value-valid", str(empty_valid).lower())
    if "minimum" in field:
      _xml(attributes, "minimum", field["minimum"])
    if "maximum" in field:
      _xml(attributes, "maximum", field["maximum"])
    if "enum" in field:
      _xml(attributes, "entries_editable", "false")
      entries = _xml(attributes, "entries")
      for value in field["enum"]:
        entry = _xml(entries, "entry")
        text = str(value).lower() if isinstance(value, bool) else str(value)
        _xml(entry, "value", text)
        _xml(entry, "label", text)
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
    log_id = service.get("observability", {}).get("logs", {}).get(component["name"])
    if log_id:
      log = _xml(_xml(child, "logs"), "log")
      _xml(log, "logId", log_id)
      _xml(log, "primary", "true")
    script = _xml(child, "commandScript")
    _xml(script, "script", "scripts/manifest_service.py")
    _xml(script, "scriptType", "PYTHON")
    _xml(script, "timeout", "600")
    commands = sorted(set(component["profiles"][0]["capabilities"]) & {"uninstall", "reload", "upgrade", "purge", "detach", "adopt"})
    if commands:
      customs = _xml(child, "customCommands")
      for action in commands:
        custom = _xml(customs, "customCommand")
        _xml(custom, "name", action.upper())
        command = _xml(custom, "commandScript")
        _xml(command, "script", "scripts/manifest_service.py")
        _xml(command, "scriptType", "PYTHON")
        _xml(command, "timeout", "600")
    dependencies = _xml(child, "configuration-dependencies")
    for config in service.get("configurations", []):
      _xml(dependencies, "config-type", config["name"])
  script = _xml(node, "commandScript")
  _xml(script, "script", "scripts/manifest_service.py")
  _xml(script, "scriptType", "PYTHON")
  _xml(script, "timeout", "120")
  return ET.tostring(document, encoding="utf-8", xml_declaration=True)


def export_legacy(manifest_path, output_directory, signing_key, signature_algorithm="HMAC-SHA256"):
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
  publisher = manifest["metadata"].get("publisher")
  if signature_algorithm not in ("HMAC-SHA256", "Ed25519"):
    raise CompileError("Unsupported signature algorithm", code="AUTHORIZATION_DENIED")
  if bool(publisher) != (signature_algorithm == "Ed25519"):
    raise CompileError("Publisher identity requires Ed25519 signing", code="AUTHORIZATION_DENIED")
  name = catalog_name(manifest["metadata"]["name"], publisher)
  metadata = {"id": name, "name": name,
    "version": manifest["metadata"]["version"], "definition": "definition.tar.gz", "modules": [],
    "authoringFormat": FORMAT, "manifestDigest": compiled["manifestDigest"], "packageDigest": compiled["packageDigest"]}
  if publisher:
    metadata.update({"publisher": publisher, "packageName": manifest["metadata"]["name"],
      "displayName": manifest["metadata"].get("displayName", publisher + "/" + manifest["metadata"]["name"]),
      "compatibility": manifest["spec"].get("compatibility", {}),
      "softwareVersions": {service["name"] + "/" + component["name"]: component["softwareVersion"]
        for service in manifest["spec"]["services"] for component in service["components"]
        if "softwareVersion" in component}})
  metadata["installationPrerequisites"] = {
    "offlineClosure": "declared-payload-only",
    "hostOsPackages": sorted({name for service in manifest["spec"]["services"]
      for component in service["components"] for profile in component["profiles"]
      for name in profile.get("resources", {}).get("packages", [])}),
    "systemExecutables": sorted({profile.get("resources", {}).get("command", {}).get("program", "")
      for service in manifest["spec"]["services"] for component in service["components"]
      for profile in component["profiles"] if profile["adapter"] == "host.systemd/v1"} - {""}),
    "containerImages": sorted({profile["resources"]["image"] for service in manifest["spec"]["services"]
      for component in service["components"] for profile in component["profiles"]
      if profile["adapter"] in ("oci.container/v1", "kubernetes.workload/v1")}),
    "runtimeProfiles": sorted({profile["adapter"] for service in manifest["spec"]["services"]
      for component in service["components"] for profile in component["profiles"]}),
    "hostRunAsUsers": sorted({profile.get("resources", {}).get("unit", {}).get("user", "")
      for service in manifest["spec"]["services"] for component in service["components"]
      for profile in component["profiles"]} - {""}),
  }
  def secret_references(value):
    if isinstance(value, dict):
      for key, child in value.items():
        if key == "secretRef" and isinstance(child, str):
          yield child
        else:
          yield from secret_references(child)
    elif isinstance(value, list):
      for child in value:
        yield from secret_references(child)
  metadata["secretReferences"] = {}
  metadata["secretConfigurationDefaults"] = {}
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
    references = set(secret_references(service))
    for config in service.get("configurations", []):
      references.update(secret_references(json.loads(payload[config["schema"]])))
    prefix = "secret://mpack." + service["name"] + "."
    if len(references) > 32 or any(not isinstance(reference, str) or not reference.startswith(prefix)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", reference[len(prefix):]) for reference in references):
      raise CompileError("Secret references must belong to the consuming service credential namespace")
    environment_refs = set(secret_references([component["profiles"][0].get("resources", {}).get("command", {}).get("environment", {})
      for component in service["components"]]))
    if environment_refs:
      metadata["secretReferences"][service["name"]] = sorted(environment_refs)
    secret_defaults = {}
    for config in service.get("configurations", []):
      for field_name, field in json.loads(payload[config["schema"]]).get("properties", {}).items():
        if field.get("x-sensitive"):
          default = config.get("defaults", {}).get(field_name, field.get("default"))
          if isinstance(default, dict) and isinstance(default.get("secretRef"), str):
            secret_defaults[config["name"] + "." + field_name] = default["secretRef"]
    if secret_defaults:
      metadata["secretConfigurationDefaults"][service["name"]] = secret_defaults
    for component in service["components"]:
      if len(component["profiles"]) != 1 or component["profiles"][0]["adapter"] not in ("host.systemd/v1", "host.files/v1", "oci.container/v1", "kubernetes.workload/v1"):
        raise CompileError("Host export requires one explicit host profile per component",
                           code="CAPABILITY_UNSUPPORTED")
      profile = component["profiles"][0]
      resources = profile.get("resources", {})
      client = profile["adapter"] == "host.files/v1"
      oci = profile["adapter"] == "oci.container/v1"
      kubernetes = profile["adapter"] == "kubernetes.workload/v1"
      if client != (component.get("category") == "CLIENT"):
        raise CompileError("CLIENT components require host.files/v1; host.systemd/v1 requires a server component",
                           code="CAPABILITY_UNSUPPORTED")
      if client:
        if (set(resources) - {"packages", "users", "directories", "executableArtifacts"}
            or "health" in profile or _has_secret_reference(service)
            or any(field.get("x-sensitive") for config in service.get("configurations", [])
                   for field in json.loads(payload[config["schema"]]).get("properties", {}).values())):
          raise CompileError("File clients cannot declare process resources or live secrets", code="CAPABILITY_UNSUPPORTED")
        if set(resources.get("executableArtifacts", [])) - {artifact["id"] for artifact in compiled["artifacts"]}:
          raise CompileError("Client executable artifact is undeclared", code="PACKAGE_CONTENT_CONFLICT")
      elif "executableArtifacts" in resources:
        raise CompileError("Executable artifact publication belongs to host.files/v1", code="CAPABILITY_UNSUPPORTED")
      if oci:
        allowed = {"engine", "image", "runAsUser", "users", "directories", "ports", "command", "mounts", "limits"}
        if (set(resources) - allowed or resources.get("engine") not in ("docker", "podman")
            or not resources.get("runAsUser")
            or not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}", resources.get("image", ""))
            or _has_secret_reference(service)
            or any(field.get("x-sensitive") for config in service.get("configurations", [])
                   for field in json.loads(payload[config["schema"]]).get("properties", {}).values())):
          raise CompileError("OCI requires a local engine, immutable image, scoped user and no live secrets", code="CAPABILITY_UNSUPPORTED")
        destinations = []
        mounted_directories = set()
        for mount in resources.get("mounts", []):
          destination = mount["containerPath"]
          if (mount["directoryRef"] not in {item["path"] for item in resources.get("directories", [])}
              or mount["directoryRef"] in mounted_directories
              or destination in ("/", "/proc", "/sys", "/dev", "/etc", "/etc/ambari-config")
              or destination.startswith(("/proc/", "/sys/", "/dev/", "/etc/ambari-config/"))
              or any(destination == prior or destination.startswith(prior + "/") or prior.startswith(destination + "/") for prior in destinations)):
            raise CompileError("OCI mounts must map distinct declared data directories", code="TARGET_CONFLICT")
          destinations.append(destination)
          mounted_directories.add(mount["directoryRef"])
        command = resources.get("command", {})
        if command and not command.get("program", "").startswith("/"):
          raise CompileError("OCI entrypoint must be an absolute in-container executable", code="SCHEMA_INVALID")
        for argument in command.get("arguments", []):
          if not isinstance(argument, str) and (not isinstance(argument, dict) or set(argument) not in ({"configurationRef"}, {"directoryRef"})):
            raise CompileError("OCI arguments accept literals or mounted file/directory references", code="CAPABILITY_UNSUPPORTED")
        if any(not isinstance(value, str) for value in command.get("environment", {}).values()):
          raise CompileError("OCI environment changes require another image/package declaration", code="CAPABILITY_UNSUPPORTED")
      elif not kubernetes and set(resources) & {"engine", "runAsUser", "mounts", "limits", "connectionRef", "runAsUserId"}:
        raise CompileError("Container resource fields require oci.container/v1", code="CAPABILITY_UNSUPPORTED")
      if kubernetes:
        if (set(resources) - {"connectionRef", "namespace", "image", "replicas", "runAsUserId", "command", "limits"}
            or not resources.get("connectionRef") or not resources.get("runAsUserId")
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", resources.get("namespace", ""))
            or not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}", resources.get("image", ""))
            or not 1 <= resources.get("replicas", 1) <= 32
            or profile.get("health", {}).get("kind") not in ("http", "tcp")
            or set(resources.get("limits", {})) - {"memoryMiB", "cpus"}
            or _has_secret_reference(service)
            or any(config.get("template") for config in service.get("configurations", []))
            or component["name"] in service.get("observability", {}).get("metrics", {})):
          raise CompileError("Kubernetes requires stateless scoped workloads, scalar environment and readiness; host metrics/templates are unsupported",
                             code="CAPABILITY_UNSUPPORTED")
        command = resources.get("command", {})
        if command.get("program") and not command["program"].startswith("/"):
          raise CompileError("Kubernetes entrypoint must be absolute")
        for expression in command.get("arguments", []) + list(command.get("environment", {}).values()):
          if not isinstance(expression, str) and (not isinstance(expression, dict) or set(expression) != {"configRef"}):
            raise CompileError("Kubernetes command accepts literals or scalar config references", code="CAPABILITY_UNSUPPORTED")
      if "upgrade" in profile["capabilities"]:
        policy = profile.get("upgradePolicy", {})
        if (policy.get("configuration") != "compatible" or policy.get("data") != "unchanged"
            or not policy.get("fromPackageDigests")
            or not any(isinstance(argument, dict) and "artifactRef" in argument
                       for argument in resources.get("command", {}).get("arguments", []))):
          raise CompileError("Upgrade requires a declared compatible artifact transition with unchanged data",
                             code="CAPABILITY_UNSUPPORTED")
      elif "upgradePolicy" in profile:
        raise CompileError("Upgrade policy requires the upgrade capability", code="CAPABILITY_UNSUPPORTED")
      if {"detach", "adopt"} & set(profile["capabilities"]):
        if (not {"detach", "adopt"} <= set(profile["capabilities"])
            or _has_secret_reference(service)
            or any(field.get("x-sensitive") for config in service.get("configurations", [])
                   for field in json.loads(payload[config["schema"]]).get("properties", {}).values())):
          raise CompileError("Ownership handoff requires both detach/adopt and no live secrets", code="CAPABILITY_UNSUPPORTED")
      reloadable = "reload" in profile["capabilities"]
      if reloadable and (resources.get("reloadSignal") not in ("HUP", "USR1", "USR2")
          or profile.get("health", {}).get("kind") != "http"
          or _has_secret_reference(resources.get("command", {}).get("environment", {}))):
        raise CompileError("Reload requires a signal, HTTP generation acknowledgement and no environment secrets",
                           code="CAPABILITY_UNSUPPORTED")
      if any(_has_secret_reference(argument) for argument in resources.get("command", {}).get("arguments", [])):
        raise CompileError("Secret values cannot appear in process arguments", code="CAPABILITY_UNSUPPORTED")
      if not client and not oci and not kubernetes and (not resources.get("command", {}).get("program") or not resources.get("unit", {}).get("user")):
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
        if kubernetes and any(field.get("x-resource") or field.get("x-sensitive") for field in schema.get("properties", {}).values()):
          raise CompileError("Kubernetes scalar environment does not accept host paths or live secrets", code="CAPABILITY_UNSUPPORTED")
        if any(field.get("x-resource") and field["x-resource"] not in directories
               for field in schema.get("properties", {}).values()):
          raise CompileError("Configuration references an undeclared managed directory")
        if oci and any(field.get("x-resource") and field["x-resource"] not in mounted_directories
                       for field in schema.get("properties", {}).values()):
          raise CompileError("OCI configuration directories require a declared container mount")
        if config.get("template"):
          template = payload[config["template"]].decode("utf-8")
          references = re.findall(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}", template)
          remainder = re.sub(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}", "", template)
          if "mpack_config_generation" in schema.get("properties", {}):
            raise CompileError("mpack_config_generation is a reserved renderer field")
          if "{{" in remainder or "{%" in template or "{#" in template or set(references) - set(schema.get("properties", {})) - {"mpack_config_generation"}:
            raise CompileError("Host templates support declared scalar fields only", code="CAPABILITY_UNSUPPORTED")
      effects = {config.get("changeEffect", "restart") for config in service.get("configurations", [])}
      if effects - {"restart", "reload"} or ("reload" in effects and not reloadable):
        raise CompileError("Host configuration requires restart or a declared verified reload capability",
                           code="CAPABILITY_UNSUPPORTED")
    module_entries = {"metainfo.xml": _service_xml(service, metadata["version"])}
    metrics = {}
    for component, definition in service.get("observability", {}).get("metrics", {}).items():
      config_type, _, field = definition["portRef"].partition(".")
      provider = {"type": "org.apache.ambari.server.controller.metrics.RestMetricsPropertyProvider",
        "properties": {"port_config_type": config_type, "port_property_name": field,
          "https_port_property_name": field, "protocol": definition.get("protocol", "http"), "numeric_only": "true"},
        "metrics": {"default": {"metrics/mpack/" + name: {
          "metric": definition["path"].lstrip("/") + "##" + "#".join(path),
          "pointInTime": True, "temporal": False} for name, path in definition["fields"].items()}}}
      metrics[component] = {"HostComponent": [provider]}
    if metrics:
      module_entries["metrics.json"] = json.dumps(metrics, sort_keys=True).encode()
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
  if signature_algorithm == "Ed25519":
    sign_release(metadata, signing_key)
  else:
    metadata["signature"] = hmac.new(signing_key, signed, hashlib.sha256).hexdigest()
    metadata["signatureAlgorithm"] = "HMAC-SHA256"
  output.mkdir(parents=True, exist_ok=True)
  (output / metadata["definition"]).write_bytes(archive)
  (output / "mpack.json").write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
  return {"metadata": str(output / "mpack.json"), "definitionSha256": metadata["definitionSha256"],
          "manifestDigest": metadata["manifestDigest"]}


def export_deployable(manifest_path, output_file, signing_key, signature_algorithm="Ed25519"):
  """One deterministic transport archive, containing the authenticated release export."""
  import tempfile
  output = Path(output_file).resolve()
  root = Path(manifest_path).resolve().parent
  if output == root or root in output.parents or output.exists():
    raise CompileError("Deployable output must be a new file outside the source directory")
  with tempfile.TemporaryDirectory(prefix="mpack-release-") as temporary:
    export = Path(temporary) / "release"
    result = export_legacy(manifest_path, export, signing_key, signature_algorithm)
    metadata = json.loads((export / "mpack.json").read_text())
    data = _archive({"mpack.json": (export / "mpack.json").read_bytes(),
                     metadata["definition"]: (export / metadata["definition"]).read_bytes()})
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
      stream.write(data)
  return {"path": str(output), "sha256": hashlib.sha256(data).hexdigest(),
          "definitionSha256": result["definitionSha256"], "format": "mpack-release/v1"}
