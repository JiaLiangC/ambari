#!/usr/bin/env python
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
import socket
import os
from urllib.parse import urlparse

from ambari_commons.constants import AMBARI_SUDO_BINARY
from resource_management import *
from resource_management.libraries.functions.stack_features import check_stack_feature
from resource_management.libraries.functions.constants import StackFeature
from resource_management.libraries.functions import conf_select, stack_select
from resource_management.libraries.functions.version import format_stack_version, get_major_version
from resource_management.libraries.functions.copy_tarball import get_sysprep_skip_copy_tarballs_hdfs
from resource_management.libraries.functions.format import format
from resource_management.libraries.functions.default import default
from resource_management.libraries.functions import get_kinit_path
from resource_management.libraries.functions.get_not_managed_resources import get_not_managed_resources
from resource_management.libraries.resources.hdfs_resource import HdfsResource
from resource_management.libraries.script.script import Script
from ambari_commons.constants import AMBARI_SUDO_BINARY
from resource_management.libraries.functions.copy_tarball import get_current_version
from resource_management.libraries.functions.stack_features import check_stack_feature, get_stack_feature_version
from resource_management.libraries.functions import StackFeature



# config object that holds the configurations declared in the config xml file
config = Script.get_config()
config_properties = config['configurations']['config.properties']

node_properties = config['configurations']['node.properties']
jvm_config = config['configurations']['jvm.config']['jvm.config']
connectors_to_add = config['configurations']['connectors.properties']['connectors.to.add']
connectors_to_delete = config['configurations']['connectors.properties']['connectors.to.delete']
memory_configs = ['query.max-memory-per-node', 'query.max-memory']

stack_root = Script.get_stack_root()
hadoop_conf_dir = conf_select.get_hadoop_conf_dir()

component_directory = "trino"
trino_home = format("{stack_root}/current/{component_directory}")
trino_conf_dir = format("{stack_root}/current/{component_directory}/etc")
trino_user = config['configurations']['trino-env']['trino_user']
trino_group = config['configurations']['trino-env']['trino_group']

trino_java_home =  config['configurations']['trino-env']['java_home']
trino_launcher_content = config['configurations']['trino-env']['content']

trino_launcher_bin_path = f"{trino_home}/bin/launcher"
trino_pid_dir = "/var/run/trino"
trino_log_dir = "/var/log/trino"

plugin_dir = f"{trino_home}/lib/plugin"
catalog_conf_dir = f"{trino_home}/etc/catalog"
trino_pid_file = f"{trino_pid_dir}/launcher.pid"
trino_node_data_dir = f"{trino_home}"

trino_start_cmd =  format("{trino_home}/bin/launcher start")
trino_stop_cmd =  format("{trino_home}/bin/launcher stop")

trino_coordinator_hosts = default("/clusterHostInfo/trino_coordinator_hosts", None)
has_trino_coordinator = bool(trino_coordinator_hosts)

trino_http_port = config_properties["http-server.http.port"]
if has_trino_coordinator:
    discovery_uri = f"http://{trino_coordinator_hosts[0]}:{trino_http_port}"
else:
    has_trino_coordinator=""
smoke_user = config['configurations']['cluster-env']['smokeuser']
