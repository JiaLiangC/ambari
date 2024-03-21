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

from resource_management.libraries.script import Script
from resource_management.libraries.functions.format import format
from resource_management.libraries.functions.default import default
from resource_management.libraries.functions.version import format_stack_version
from resource_management.libraries.functions.stack_features import check_stack_feature
from resource_management.libraries.functions import StackFeature

config  = Script.get_config()
tmp_dir = Script.get_tmp_dir()


stack_name = default("/clusterLevelParams/stack_name", None)
stack_version_unformatted = config['clusterLevelParams']['stack_version']
stack_version_formatted = format_stack_version(stack_version_unformatted)
celeborn_pid_dir = config['configurations']['celeborn-env']['celeborn_pid_dir']
celeborn_master_pid_file = format('{celeborn_pid_dir}/celeborn-celeborn-org.apache.celeborn.service.deploy.master.Master-1.pid')
celeborn_worker_pid_file = format('{celeborn_pid_dir}/celeborn-celeborn-org.apache.celeborn.service.deploy.worker.Worker-1.pid')
