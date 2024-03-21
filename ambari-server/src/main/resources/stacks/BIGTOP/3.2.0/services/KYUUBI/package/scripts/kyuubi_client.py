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
import sys
import os
from resource_management import *


class KyuubiClient(Script):
  def install(self, env):
    import params
    self.install_packages(env)
    self.configure(env)

  def status(self, env):
    raise ClientComponentHasNoStatus()

  def configure(self, env):
    import params
    env.set_params(params)
            
    Directory([params.kyuubi_log_dir, params.kyuubi_pid_dir, params.kyuubi_work_dir, params.kyuubi_metrics_dir, params.kyuubi_operation_log_dir],
        #Directory([params.kyuubi_log_dir, params.kyuubi_pid_dir, params.kyuubi_operation_log_dir],
                  owner=params.kyuubi_user,
                  group=params.kyuubi_group,
                  mode=0o775,
                  create_parents = True
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
 

 

if __name__ == "__main__":
  KyuubiClient().execute()
