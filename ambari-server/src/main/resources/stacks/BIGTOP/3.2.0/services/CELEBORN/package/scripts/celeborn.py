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
import os
import sys
from resource_management.libraries.script.script import Script
from resource_management.libraries.resources.xml_config import XmlConfig
from resource_management.libraries.resources.template_config import TemplateConfig
from resource_management.libraries.functions.format import format
from resource_management.libraries.functions import lzo_utils
from resource_management.libraries.functions.default import default
from resource_management.libraries.functions.generate_logfeeder_input_config import generate_logfeeder_input_config
from resource_management.core.source import Template, InlineTemplate
from resource_management.core.resources import Package
from resource_management.core.resources.service import ServiceConfig
from resource_management.core.resources.system import Directory, Execute, File
from ambari_commons.os_family_impl import OsFamilyFuncImpl, OsFamilyImpl
from ambari_commons import OSConst
from resource_management.libraries.functions.constants import StackFeature
from resource_management.libraries.functions.stack_features import check_stack_feature

# name is 'master' or 'regionserver' or 'queryserver' or 'client'
@OsFamilyFuncImpl(os_family=OsFamilyImpl.DEFAULT)
def celeborn(name=None):
  import params
  import status_params
 
  Directory([ status_params.celeborn_pid_dir, params.celeborn_master_ha_ratis_raft_server_storage_dir],
            owner=params.celeborn_user,
            group=params.celeborn_group,
            mode=0o775,
            create_parents = True
  )

  Directory([params.celeborn_log_dir],
            owner=params.celeborn_user,
            group=params.celeborn_group,
            mode=0o777,
            create_parents = True
  )

  # create celeborn-defaults.conf in celeborn install dir
  File(os.path.join(params.celeborn_conf_dir, 'celeborn-defaults.conf'),
       owner=params.celeborn_user,
       group=params.celeborn_group,
       content=InlineTemplate(params.celeborn_defaults_conf),
       mode=0o644,
  )

  # create celeborn-env.sh in celeborn install dir
  File(os.path.join(params.celeborn_conf_dir, 'celeborn-env.sh'),
       owner=params.celeborn_user,
       group=params.celeborn_group,
       content=InlineTemplate(params.celeborn_env_sh),
       mode=0o775,
  )

  #create log4j.xml celeborn install dir
  File(os.path.join(params.celeborn_conf_dir, 'log4j2.xml'),
       owner=params.celeborn_user,
       group=params.celeborn_group,
       content=InlineTemplate(params.celeborn_log4j_xml),
       mode=0o644,
  ) 
  
  #create metrics.properties celeborn install dir
  File(os.path.join(params.celeborn_conf_dir, 'metrics.properties'),
       owner=params.celeborn_user,
       group=params.celeborn_group,
       content=InlineTemplate(params.celeborn_metrics_properties),
       mode=0o644,
  ) 

  #quota.yaml
  if params.celeborn_quota_enabled:
    File(os.path.join(params.celeborn_conf_dir, 'quota.yaml'),
       owner=params.celeborn_user,
       group=params.celeborn_group,
       content=InlineTemplate(params.celeborn_quota_xml),
       mode=0o644,
    ) 

  #ratis-log4j.properties
  File(os.path.join(params.celeborn_conf_dir, 'ratis-log4j.properties'),
       owner=params.celeborn_user,
       group=params.celeborn_group,
       content=InlineTemplate(params.celeborn_ratis_log4j_properties),
       mode=0o644,
  ) 
  
  # hostss
  File(format("{celeborn_conf_dir}/hosts"),
       owner=params.celeborn_user,
       group=params.celeborn_group,
       mode=0o644,
       content=Template('hosts.j2', conf_dir=params.celeborn_conf_dir)
    ) 
  
  # hdfs dir
  params.HdfsResource(params.celeborn_hdfs_user_dir,
                 type="directory",
                 action="create_on_execute",
                 owner=params.celeborn_user,
                 mode=0o775
            )
  params.HdfsResource(params.celeborn_storage_hdfs_dir,
                 type="directory",
                 action="create_on_execute",
                 owner=params.celeborn_user,
                 mode=0o775
            )
            