# -*- coding: utf-8 -*-
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import uuid
import os.path as path
from resource_management import *
import os
from common import  process_connector_conf

class Worker(Script):
    def install(self, env):
        self.install_packages(env)

    def stop(self, env):
        import params
        Execute(params.trino_stop_cmd, user=params.trino_user)

    def start(self, env):
        import params
        self.configure(env)
        Execute(params.trino_start_cmd, user=params.trino_user)

    def status(self, env):
        import params
        env.set_params(params)
        check_process_status(params.trino_pid_file)

    def configure(self, env, upgrade_type=None, config_dir=None):
        import params
        env.set_params(params)

        mode_identified_for_file = 0o644
        mode_identified_for_dir = 0o755


        Directory([params.trino_node_data_dir, params.catalog_conf_dir, params.plugin_dir, params.trino_pid_dir, params.trino_log_dir],
                  owner=params.trino_user,
                  group=params.trino_group,
                  mode=mode_identified_for_dir,
                  create_parents = True
                  )


        Directory(params.trino_home,
                  owner=params.trino_user,
                  group=params.trino_group,
                  mode=mode_identified_for_dir
                  )

        File(params.trino_launcher_bin_path,
             owner=params.trino_user,
             group=params.trino_group,
             content=InlineTemplate(params.trino_launcher_content),
             mode=0o755,
             )


        node_properties = os.path.join(params.trino_conf_dir,'node.properties')
        PropertiesFile(node_properties,
                       properties = params.node_properties,
                       mode=mode_identified_for_file,
                       owner=params.trino_user,
                       group=params.trino_group
                       )
        ModifyPropertiesFile(node_properties,
                             properties = {'node.id': str(uuid.uuid4())},
                             owner = params.trino_user,
                             )

        jvm_config_file = os.path.join(params.trino_conf_dir,'jvm.config')
        File(jvm_config_file,
             owner=params.trino_user,
             group=params.trino_group,
             content=InlineTemplate(params.jvm_config),
             mode=mode_identified_for_file,
             )

        config_properties_file = os.path.join(params.trino_conf_dir,'config.properties')
        PropertiesFile(config_properties_file,
                       properties = params.config_properties,
                       mode=mode_identified_for_file,
                       owner=params.trino_user,
                       group=params.trino_group
                       )

        ModifyPropertiesFile(config_properties_file,
                             properties = {'coordinator': 'false'},
                             mode=mode_identified_for_file,
                             owner = params.trino_user
                             )

        process_connector_conf(params.catalog_conf_dir,params.trino_user,params.trino_group)


if __name__ == '__main__':
    Worker().execute()
