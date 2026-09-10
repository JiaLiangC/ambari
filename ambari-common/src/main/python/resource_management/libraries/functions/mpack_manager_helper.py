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

import os

from instance_manager import (
  create_mpack,
  get_conf_dir,
  get_log_dir,
  get_run_dir,
  list_instances,
  set_mpack_instance,
  walk_mpack_dict,
)


MPACK_PATH_KEY = "mpack_path"
MPACK_VERSION_KEY = "mpack_version"
MODULE_VERSION_KEY = "module_version"


def _component_map(component_type, component_instance_name):
  return {component_type: [component_instance_name]}


def create_component_instance(
  mpack_name,
  mpack_version,
  instance_name,
  module_name,
  component_type,
  subgroup_name="default",
  component_instance_name="default",
):
  """Create an idempotent component instance for an Agent command."""
  create_mpack(
    mpack_name,
    mpack_version,
    instance_name,
    subgroup_name,
    module_name,
    None,
    _component_map(component_type, component_instance_name),
    False,
  )


def set_component_instance_version(
  mpack_name,
  mpack_version,
  instance_name,
  module_name,
  component_type,
  subgroup_name="default",
  component_instance_name="default",
):
  """Switch exactly one component instance to an installed mpack version."""
  set_mpack_instance(
    mpack_name,
    mpack_version,
    instance_name,
    subgroup_name,
    module_name,
    None,
    _component_map(component_type, component_instance_name),
  )


def get_component_conf_path(
  mpack_name,
  instance_name,
  module_name,
  component_type,
  subgroup_name="default",
  component_instance_name="default",
):
  return get_conf_dir(
    mpack_name,
    instance_name,
    subgroup_name,
    module_name,
    _component_map(component_type, component_instance_name),
  )


def get_component_log_path(
  mpack_name,
  instance_name,
  module_name,
  component_type,
  subgroup_name="default",
  component_instance_name="default",
):
  return get_log_dir(
    mpack_name,
    instance_name,
    subgroup_name,
    module_name,
    _component_map(component_type, component_instance_name),
  )


def get_component_run_path(
  mpack_name,
  instance_name,
  module_name,
  component_type,
  subgroup_name="default",
  component_instance_name="default",
):
  return get_run_dir(
    mpack_name,
    instance_name,
    subgroup_name,
    module_name,
    _component_map(component_type, component_instance_name),
  )


def get_component_target_path(
  mpack_name,
  instance_name,
  module_name,
  component_type,
  subgroup_name="default",
  component_instance_name="default",
):
  instances = list_instances(
    mpack_name,
    instance_name,
    subgroup_name,
    module_name,
    _component_map(component_type, component_instance_name),
  )
  paths = set()
  walk_mpack_dict(instances, MPACK_PATH_KEY, paths)
  return _single(paths, "component target")


def get_component_home_path(*args, **kwargs):
  return os.readlink(get_component_target_path(*args, **kwargs))


def get_versions(
  mpack_name,
  instance_name,
  module_name,
  component_type,
  subgroup_name="default",
  component_instance_name="default",
):
  instances = list_instances(
    mpack_name,
    instance_name,
    subgroup_name,
    module_name,
    _component_map(component_type, component_instance_name),
  )
  mpack_versions = set()
  module_versions = set()
  walk_mpack_dict(instances, MPACK_VERSION_KEY, mpack_versions)
  walk_mpack_dict(instances, MODULE_VERSION_KEY, module_versions)
  return (
    _single(mpack_versions, "mpack version"),
    _single(module_versions, "module version"),
  )


def _single(values, label):
  if len(values) != 1:
    raise ValueError(f"Expected one {label}, found {len(values)}")
  return sorted(values)[0]
