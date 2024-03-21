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

config = Script.get_config()

java_home = config['ambariLevelParams']['java_home']
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
effective_version = get_current_version(service="SPARK")

sysprep_skip_copy_tarballs_hdfs = get_sysprep_skip_copy_tarballs_hdfs()

# New Cluster Stack Version that is defined during the RESTART of a Stack Upgrade
version = default("/commandParams/version", None)

hadoop_conf_dir = conf_select.get_hadoop_conf_dir()
hadoop_bin_dir = stack_select.get_hadoop_dir("bin")

if stack_version_formatted and check_stack_feature(StackFeature.ROLLING_UPGRADE, stack_version_formatted):
  hadoop_home = stack_select.get_hadoop_dir("home")
  

component_directory = "kyuubi-server"
kyuubi_home = format("{stack_root}/current/{component_directory}")
kyuubi_conf_dir = format("{stack_root}/current/{component_directory}/conf")

hdfs_user = config['configurations']['hadoop-env']['hdfs_user']
hdfs_principal_name = config['configurations']['hadoop-env']['hdfs_principal_name']
hdfs_user_keytab = config['configurations']['hadoop-env']['hdfs_user_keytab']
user_group = config['configurations']['cluster-env']['user_group']

kyuubi_user = config['configurations']['kyuubi-env']['kyuubi_user']
kyuubi_group = config['configurations']['kyuubi-env']['kyuubi_group']
kyuubi_pid_dir = config['configurations']['kyuubi-env']['kyuubi_pid_dir']
kyuubi_log_dir = config['configurations']['kyuubi-env']['kyuubi_log_dir']
kyuubi_work_dir = format("{kyuubi_home}/work")
kyuubi_pid_file = format("{kyuubi_pid_dir}/kyuubi-{kyuubi_user}-org.apache.kyuubi.server.KyuubiServer.pid")

kyuubi_metrics_dir= format("{stack_root}/current/{component_directory}/work/metrics")
kyuubi_operation_log_dir= format("{stack_root}/current/{component_directory}/work/server_operation_logs") 

kyuubi_env_sh = config['configurations']['kyuubi-env']['content']
kyuubi_log4j2_properties = config['configurations']['kyuubi-log4j2-properties']['content']

kyuubi_hdfs_user_dir = format("/user/{kyuubi_user}")

kyuubi_start_cmd =  format("{kyuubi_home}/bin/kyuubi start")
kyuubi_stop_cmd =  format("{kyuubi_home}/bin/kyuubi stop")

# zookeeper
zookeeper_hosts = config['clusterHostInfo']['zookeeper_server_hosts']
zookeeper_port = default('/configurations/zoo.cfg/clientPort', None)

# get comma separated lists of zookeeper hosts from clusterHostInfo
index = 0
zookeeper_quorum = ""
for host in zookeeper_hosts:
  zookeeper_host = host
  if zookeeper_port is not None:
    zookeeper_host = host + ":" + str(zookeeper_port)

  zookeeper_quorum += zookeeper_host
  index += 1
  if index < len(zookeeper_hosts):
    zookeeper_quorum += ","

cluster_zookeeper_quorum = zookeeper_quorum




#kyuubi_server_port
kyuubi_server_port = config['configurations']['kyuubi-defaults']['kyuubi.frontend.thrift.binary.bind.port']

#kyuubi_client_home = format("{stack_root}/current/kyuubi-client")
#kyuubi_client_conf_dir = format("{stack_root}/current/kyuubi-client/conf")

smoke_user = config['configurations']['cluster-env']['smokeuser']

kyuubi_server_hosts = default("/clusterHostInfo/kyuubi_server_hosts", [])
has_kyuubi_server = not len(kyuubi_server_hosts) == 0


kyuubi_authentication = "NONE"

kinit_path_local = get_kinit_path(default('/configurations/kerberos-env/executable_search_paths', None))
kyuubi_kerberos_keytab =  config['configurations']['kyuubi-defaults']['kyuubi.kinit.keytab']
kyuubi_kerberos_principal =  config['configurations']['kyuubi-defaults']['kyuubi.kinit.principal']
smoke_user_keytab = config['configurations']['cluster-env']['smokeuser_keytab']
smokeuser_principal =  config['configurations']['cluster-env']['smokeuser_principal_name']
hive_kerberos_keytab = config['configurations']['hive-site']['hive.server2.authentication.kerberos.keytab']
  
security_enabled = default("/configurations/cluster-env/security_enabled", None)
#kinit_path_local = get_kinit_path(default('/configurations/kerberos-env/executable_search_paths', None))

if security_enabled:
  kyuubi_authentication = "KERBEROS"
  hive_kerberos_principal = config['configurations']['hive-site']['hive.server2.authentication.kerberos.principal'].replace('_HOST', socket.getfqdn().lower())

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

