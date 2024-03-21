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
from resource_management.libraries.functions.copy_tarball import get_current_version
from resource_management.libraries.functions.stack_features import check_stack_feature, get_stack_feature_version
from resource_management.libraries.functions import StackFeature


config = Script.get_config()

java_home = config['ambariLevelParams']['java_home']
ambari_java_home = default("/ambariLevelParams/ambari_java_home", None)
# not supporting 32 bit jdk.
java64_home = ambari_java_home if ambari_java_home is not None else java_home
stack_root = Script.get_stack_root()

config = Script.get_config()
tmp_dir = Script.get_tmp_dir()
sudo = AMBARI_SUDO_BINARY
fqdn = socket.getfqdn().lower()

retryAble = default("/commandParams/command_retry_enabled", False)

cluster_name = config['clusterName']
stack_name = default("/clusterLevelParams/stack_name", None)
stack_root = Script.get_stack_root()
#3.2
stack_version_unformatted = config['clusterLevelParams']['stack_version']
#3.2.0.0
stack_version_formatted = format_stack_version(stack_version_unformatted)
#3.2
major_stack_version = get_major_version(stack_version_formatted)

#3.2.1.0-001
effective_version = get_current_version(service="GLUTEN")

sysprep_skip_copy_tarballs_hdfs = get_sysprep_skip_copy_tarballs_hdfs()

# New Cluster Stack Version that is defined during the RESTART of a Stack Upgrade
version = default("/commandParams/version", None)

hadoop_conf_dir = conf_select.get_hadoop_conf_dir()
hadoop_bin_dir = stack_select.get_hadoop_dir("bin")

if stack_version_formatted and check_stack_feature(StackFeature.ROLLING_UPGRADE, stack_version_formatted):
  hadoop_home = stack_select.get_hadoop_dir("home")  

hdfs_user = config['configurations']['hadoop-env']['hdfs_user']
hdfs_principal_name = config['configurations']['hadoop-env']['hdfs_principal_name']
hdfs_user_keytab = config['configurations']['hadoop-env']['hdfs_user_keytab']
user_group = config['configurations']['cluster-env']['user_group']

execute_path = os.environ['PATH'] + os.pathsep + hadoop_bin_dir

component_directory = "celeborn"
celeborn_home = format("{stack_root}/current/{component_directory}")
celeborn_conf_dir = format("{stack_root}/current/{component_directory}/conf")

celeborn_user = config['configurations']['celeborn-env']['celeborn_user']
celeborn_group = config['configurations']['celeborn-env']['celeborn_group']
celeborn_log_dir = config['configurations']['celeborn-env']['celeborn_log_dir']
celeborn_pid_dir = config['configurations']['celeborn-env']['celeborn_pid_dir']

# celeborn masters address
celeborn_masters = config['clusterHostInfo']['celeborn_master_hosts']
celeborn_masters_str = '\n'.join(celeborn_masters)

#current hostname 
hostname = config['agentLevelParams']['hostname']

celeborn_master_ha_enabled = False
celeborn_master_port = config['configurations']['celeborn-defaults']['celeborn.master.port']
celeborn_master_ratis_port = config['configurations']['celeborn-defaults']['celeborn.master.ratis.port']

celeborn_master_endpoints = ""
celeborn_master_endpoints_config = ""
# get comma separated lists of celeborn_master_endpoints hosts from celeborn_masters
if(len(celeborn_masters) > 0) :
  if len(celeborn_masters) == 1:
    host = celeborn_masters[0]
    celeborn_master_endpoints_config = format("celeborn.master.host {host}\nceleborn.master.port {celeborn_master_port}")

  if len(celeborn_masters) > 1:
    index = 0
    for host in celeborn_masters:
      celeborn_master_host = host
      if celeborn_master_port is not None:
        celeborn_master_host = host + ":" + str(celeborn_master_port)

      celeborn_master_endpoints += celeborn_master_host
      index += 1
      if( host == hostname ):
        celeborn_master_endpoints_config += format("celeborn.master.ha.node.id {index}\n")
      celeborn_master_endpoints_config += format("celeborn.master.ha.node.{index}.host {host} \nceleborn.master.ha.node.{index}.port {celeborn_master_port} \nceleborn.master.ha.node.{index}.ratis.port {celeborn_master_ratis_port}")

      if index < len(celeborn_masters):
        celeborn_master_endpoints += ","
        celeborn_master_endpoints_config += "\n"
        celeborn_master_ha_enabled = True

print(f"celeborn_master_endpoints: {celeborn_master_endpoints}")
print(f"celeborn_master_endpoints_config: {celeborn_master_endpoints_config}")

# celeborn.master.ha.ratis.raft.server.storage.dir
celeborn_master_ha_ratis_raft_server_storage_dir = config['configurations']['celeborn-defaults']['celeborn.master.ha.ratis.raft.server.storage.dir']
if celeborn_master_ha_ratis_raft_server_storage_dir is None:
  celeborn_master_ha_ratis_raft_server_storage_dir = "/usr/hdp/current/celeborn/celeborn_ratis"
celeborn_master_ha_ratis_raft_server_storage_dir_formatted =  False
if(os.path.exists(celeborn_master_ha_ratis_raft_server_storage_dir) and os.path.isdir(celeborn_master_ha_ratis_raft_server_storage_dir) and len(os.listdir(celeborn_master_ha_ratis_raft_server_storage_dir)) > 0):
  celeborn_master_ha_ratis_raft_server_storage_dir_formatted = True

# celeborn workers address
celeborn_workers = config['clusterHostInfo']['celeborn_worker_hosts']
celeborn_workers_str = '\n'.join(celeborn_workers)
celeborn_worker_storage_dirs = config['configurations']['celeborn-defaults']['celeborn.worker.storage.dirs']

#hdfs store
celeborn_storage_activeTypes = config['configurations']['celeborn-defaults']['celeborn.storage.activeTypes']

# Find current stack and version to push agent files to
stack_name = default("/hostLevelParams/stack_name", None)
stack_version = config['hostLevelParams']['stack_version']

# hadoop params
namenode_address = None
if 'dfs.namenode.rpc-address' in config['configurations']['hdfs-site']:
  namenode_rpcaddress = config['configurations']['hdfs-site']['dfs.namenode.rpc-address']
  namenode_address = format("hdfs://{namenode_rpcaddress}")
else:
  namenode_address = config['configurations']['core-site']['fs.defaultFS']

# celeborn underfs address
celeborn_storage_hdfs_dir = namenode_address + config['configurations']['celeborn-defaults']['celeborn.storage.hdfs.dir']

host_name = config['agentLevelParams']['hostname']

celeborn_hdfs_user_dir = format("/user/{celeborn_user}")
smoke_user = config['configurations']['cluster-env']['smokeuser']
celeborn_authentication = "SIMPLE"

#security_enabled
security_enabled = default("/configurations/cluster-env/security_enabled", None)
kinit_path_local = get_kinit_path(default('/configurations/kerberos-env/executable_search_paths', None))

if security_enabled:
  celeborn_storage_hdfs_kerberos_principal = config['configurations']['celeborn-defaults']['celeborn.storage.hdfs.kerberos.principal']
  celeborn_storage_hdfs_kerberos_keytab = config['configurations']['celeborn-defaults']['celeborn.storage.hdfs.kerberos.keytab']

#for create_hdfs_directory
default_fs = config['configurations']['core-site']['fs.defaultFS']
hdfs_site = config['configurations']['hdfs-site']
hdfs_resource_ignore_file = "/var/lib/ambari-agent/data/.hdfs_resource_ignore"

dfs_type = default("/clusterLevelParams/dfs_type", "") 

import functools
#create partial functions with common arguments for every HdfsResource call
#to create/delete hdfs directory/file/copyfromlocal we need to call params.HdfsResource in code
HdfsResource = functools.partial(
  HdfsResource,
  user=hdfs_user,
  hdfs_resource_ignore_file = hdfs_resource_ignore_file,
  security_enabled = security_enabled,
  keytab = hdfs_user_keytab,
  kinit_path_local = kinit_path_local,
  hadoop_bin_dir = hadoop_bin_dir,
  hadoop_conf_dir = hadoop_conf_dir,
  principal_name = hdfs_principal_name,
  hdfs_site = hdfs_site,
  default_fs = default_fs,
  immutable_paths = get_not_managed_resources(),
  dfs_type = dfs_type
)

celeborn_env_sh = config['configurations']['celeborn-env']['content']
celeborn_defaults_conf = config['configurations']['celeborn-defaults']['content']
celeborn_log4j_xml = config['configurations']['celeborn-log4j']['content']
celeborn_metrics_properties = config['configurations']['celeborn-metrics-properties']['content']
celeborn_quota_xml = config['configurations']['celeborn-quota']['content']
celeborn_ratis_log4j_properties = config['configurations']['celeborn-ratis-log4j-properties']['content']

celeborn_test_cmd=""


celeborn_quota_enabled = config['configurations']['celeborn-defaults']['celeborn.quota.enabled']