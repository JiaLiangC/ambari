#!/usr/bin/python
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
from resource_management import *

class KyuubiServer(Script):
    def install(self, env):
        self.install_packages(env)

    def configure(self, env, upgrade_type=None, config_dir=None):
        import params
        env.set_params(params)
        

        Directory([params.kyuubi_log_dir, params.kyuubi_pid_dir, params.kyuubi_work_dir, params.kyuubi_metrics_dir, params.kyuubi_operation_log_dir],
                  owner=params.kyuubi_user,
                  group=params.kyuubi_group,
                  mode=0o775,
                  create_parents = True
                  )

        Directory(params.kyuubi_home,
                  owner=params.kyuubi_user,
                  group=params.kyuubi_group,
                  mode=0o775
                  )

        kyuubi_defaults = dict(params.config['configurations']['kyuubi-defaults'])

        PropertiesFile(format("{kyuubi_conf_dir}/kyuubi-defaults.conf"),
               properties = kyuubi_defaults,
               key_value_delimiter = " ",
               owner=params.kyuubi_user,
               group=params.kyuubi_group,
               mode=0o644
               )

        # create kyuubi-env.sh in kyuubi install dir
        File(os.path.join(params.kyuubi_conf_dir, 'kyuubi-env.sh'),
             owner=params.kyuubi_user,
             group=params.kyuubi_group,
             content=InlineTemplate(params.kyuubi_env_sh),
             mode=0o644,
        )

        #create log4j2.properties kyuubi install dir
        File(os.path.join(params.kyuubi_conf_dir, 'log4j2.properties'),
             owner=params.kyuubi_user,
             group=params.kyuubi_group,
             content=InlineTemplate(params.kyuubi_log4j2_properties),
             mode=0o644,
        )
        # work dir
        Directory(os.path.join(params.kyuubi_pid_dir, 'work'),
            owner=params.kyuubi_user,
            group=params.kyuubi_group,
            mode=0o775,
            create_parents = True
            )

        # hdfs dir
        params.HdfsResource(params.kyuubi_hdfs_user_dir,
                       type="directory",
                       action="create_on_execute",
                       owner=params.kyuubi_user,
                       mode=0o775
                  )
                  
    def start(self, env, upgrade_type=None):
        import params
        env.set_params(params)

        self.configure(env)
        Execute(params.kyuubi_start_cmd,user=params.kyuubi_user,environment={'JAVA_HOME': params.java_home})

    def stop(self, env, upgrade_type=None):
        import params
        env.set_params(params)
        self.configure(env)

        Execute(params.kyuubi_stop_cmd,user=params.kyuubi_user,environment={'JAVA_HOME': params.java_home})

    def status(self, env):
        import params
        env.set_params(params)
        check_process_status(params.kyuubi_pid_file)

    def get_user(self):
        import params
        return params.kyuubi_user

    def get_pid_files(self):
        import params
        return [params.kyuubi_pid_file]

if __name__ == "__main__":
    KyuubiServer().execute()
