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

import time
import  os
from resource_management import *
from resource_management.libraries.functions.format import format
from dinky_env import dinky_env


class DinkyService(Script):

    # 安装 dinky
    def install(self, env):
        import params
        env.set_params(params)
        self.install_packages(env)
        #Execute(('chmod', '-R', '777', params.dinky_home))
        #Execute(('chown', '-R', params.dinky_user + ":" + params.dinky_group, params.dinky_home))


    def initialize(self, env):
        import params
        env.set_params(params)
        dinky_setup_marker = os.path.join(params.dinky_conf_dir, "dinky_setup")
        if not os.path.exists(dinky_setup_marker):
            try :
                Execute(params.init_sql, user=params.dinky_user)
                Logger.info(format('dinky init finished, cmd: {params.init_sql}'))

                File(dinky_setup_marker,
                     owner = params.dinky_user,
                     group = params.dinky_group,
                     mode = 0o640)
            except Exception as e:
                Logger.exception("There was an exception when  ALTER SYSTEM ADD FOLLOWER: " + str(e))


    def configure(self, env):
        import params
        params.pika_slave = True
        env.set_params(params)
        self.initialize(env)
        dinky_env()

    def start(self, env):
        import params
        env.set_params(params)
        self.configure(env)

        no_op_test = format("ls {params.dinky_pid_file} >/dev/null 2>&1 ")

        start_cmd = format("sh {params.start_script_path}  start {params.dinky_flink_big_version}")
        Execute(start_cmd, user=params.dinky_user, not_if=no_op_test)

    def stop(self, env):
        import params
        env.set_params(params)
        stop_cmd = format("sh {params.start_script_path} stop ")
        Execute(stop_cmd, user=params.dinky_user)
        time.sleep(5)

    def status(self, env):
        import params
        env.set_params(params)
        check_process_status(params.dinky_pid_file)

    def restart(self, env):
        self.stop(env)
        self.start(env)


if __name__ == "__main__":
    DinkyService().execute()
