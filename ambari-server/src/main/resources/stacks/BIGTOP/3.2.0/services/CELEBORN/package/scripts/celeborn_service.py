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

# Python Imports
import os
import time

# Ambari Commons & Resource Management Imports
from ambari_commons.constants import UPGRADE_TYPE_ROLLING
from resource_management.core import shell
from resource_management.core import utils
from resource_management.core.exceptions import ComponentIsNotRunning, Fail
from resource_management.core.logger import Logger
from resource_management.core.resources.system import File, Execute
from resource_management.core.shell import as_user, quote_bash_args
from resource_management.libraries.functions import get_user_call_output
from resource_management.libraries.functions import StackFeature
from resource_management.libraries.functions.check_process_status import check_process_status
from resource_management.libraries.functions.decorator import retry
from resource_management.libraries.functions.format import format
from resource_management.libraries.functions.show_logs import show_logs
from resource_management.libraries.functions.stack_features import check_stack_feature


def celeborn_service(name, action='start', upgrade_type=None):

  import params
  import status_params

  if name == 'master':
    pid_file = status_params.celeborn_master_pid_file
    cmd_start = format("{celeborn_home}/sbin/start-master.sh")
    cmd_stop = format("{celeborn_home}/sbin/stop-master.sh")
  elif name == 'worker':
    pid_file = status_params.celeborn_worker_pid_file
    cmd_start = format("{celeborn_home}/sbin/start-worker.sh")
    cmd_stop = format("{celeborn_home}/sbin/stop-worker.sh")


  pid = get_user_call_output.get_user_call_output(format("cat {pid_file}"), user=params.celeborn_user, is_checked_call=False)[1]
  process_id_exists_command = format("ls {pid_file} >/dev/null 2>&1 && ps -p {pid} >/dev/null 2>&1")

  if action == 'start':
 
    daemon_cmd = cmd_start 
    Execute(daemon_cmd, 
      user = params.celeborn_user,
      environment = { 'HADOOP_HOME': params.hadoop_home, 'HADOOP_CONF_DIR': params.hadoop_conf_dir,'JAVA_HOME': params.java64_home},
      path = params.execute_path,
      not_if = process_id_exists_command)

  elif action == 'stop':
  
    daemon_cmd = cmd_stop
    hadoop_home = params.hadoop_home
 
    Execute(daemon_cmd, 
      user = params.celeborn_user,
      environment = { 'HADOOP_HOME': params.hadoop_home, 'HADOOP_CONF_DIR': params.hadoop_conf_dir, 'JAVA_HOME': params.java64_home },
      path = params.execute_path)

    File(pid_file,
         action = "delete"
    )

