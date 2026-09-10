"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

import hashlib
import json
import os
import re

API_VERSION = "mpack.ambari.apache.org/v2alpha1"
KIND = "Mpack"
IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")


class ManifestError(ValueError):
  """A manifest failed a deterministic authoring validation rule."""


def _required(mapping, path):
  value = mapping.get(path)
  if not isinstance(value, str) or not value.strip():
    raise ManifestError("{} must be a non-empty string".format(path))
  return value


def _identifier(value, path):
  if not IDENTIFIER.fullmatch(value):
    raise ManifestError("{} contains an invalid identifier".format(path))


def _within(root, relative, path):
  if not isinstance(relative, str) or not relative:
    raise ManifestError("{} must be a relative path".format(path))
  if os.path.isabs(relative):
    raise ManifestError("{} must not be absolute".format(path))
  root = os.path.realpath(root)
  candidate = os.path.realpath(os.path.join(root, relative))
  if os.path.commonpath((root, candidate)) != root:
    raise ManifestError("{} escapes the package boundary".format(path))
  return candidate


def validate_manifest(manifest, package_root=None):
  """Validate and return a normalized manifest plus its canonical digest."""
  if not isinstance(manifest, dict):
    raise ManifestError("manifest must be an object")
  if manifest.get("apiVersion") != API_VERSION:
    raise ManifestError("apiVersion must be {}".format(API_VERSION))
  if manifest.get("kind") != KIND:
    raise ManifestError("kind must be {}".format(KIND))
  metadata = manifest.get("metadata")
  spec = manifest.get("spec")
  if not isinstance(metadata, dict) or not isinstance(spec, dict):
    raise ManifestError("metadata and spec must be objects")
  name = _required(metadata, "metadata.name")
  version = _required(metadata, "metadata.version")
  _identifier(name, "metadata.name")
  _identifier(version, "metadata.version")

  artifacts = spec.get("artifacts", [])
  if not isinstance(artifacts, list):
    raise ManifestError("spec.artifacts must be a list")
  artifact_ids = set()
  for index, artifact in enumerate(artifacts):
    path = "spec.artifacts[{}]".format(index)
    if not isinstance(artifact, dict):
      raise ManifestError("{} must be an object".format(path))
    artifact_id = _required(artifact, path + ".id")
    _identifier(artifact_id, path + ".id")
    if artifact_id in artifact_ids:
      raise ManifestError("duplicate artifact id {}".format(artifact_id))
    artifact_ids.add(artifact_id)
    source = artifact.get("source")
    if not isinstance(source, dict):
      raise ManifestError(path + ".source must be an object")
    if source.get("kind") == "file":
      if package_root is None:
        raise ManifestError("package_root is required for file artifacts")
      resolved = _within(package_root, source.get("path"), path + ".source.path")
      if not os.path.isfile(resolved):
        raise ManifestError("{} does not exist".format(path + ".source.path"))
    elif source.get("kind") != "url":
      raise ManifestError("{} has unsupported source kind".format(path + ".source.kind"))

  services = spec.get("services")
  if not isinstance(services, list) or not services:
    raise ManifestError("spec.services must be a non-empty list")
  service_ids = set()
  component_ids = set()
  for service_index, service in enumerate(services):
    service_path = "spec.services[{}]".format(service_index)
    if not isinstance(service, dict):
      raise ManifestError(service_path + " must be an object")
    service_name = _required(service, service_path + ".name")
    _identifier(service_name, service_path + ".name")
    if service_name in service_ids:
      raise ManifestError("duplicate service name {}".format(service_name))
    service_ids.add(service_name)
    components = service.get("components", [])
    if not isinstance(components, list):
      raise ManifestError(service_path + ".components must be a list")
    for component_index, component in enumerate(components):
      component_path = "{}.components[{}]".format(service_path, component_index)
      if not isinstance(component, dict):
        raise ManifestError(component_path + " must be an object")
      component_name = _required(component, component_path + ".name")
      _identifier(component_name, component_path + ".name")
      component_key = service_name + "/" + component_name
      if component_key in component_ids:
        raise ManifestError("duplicate component {}".format(component_key))
      component_ids.add(component_key)

  canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
  digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
  return {"manifest": manifest, "canonical": canonical, "digest": digest}


def load_manifest(path):
  with open(path, "r", encoding="utf-8") as stream:
    manifest = json.load(stream)
  return validate_manifest(manifest, os.path.dirname(os.path.realpath(path)))
