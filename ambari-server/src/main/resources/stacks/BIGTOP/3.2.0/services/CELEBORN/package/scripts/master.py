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
from resource_management.core import sudo
from resource_management.libraries.functions import check_process_status
import time
from celeborn import celeborn
from celeborn_service import celeborn_service

class CelebornMaster(Script):
    def install(self, env):
        self.install_packages(env)

    def configure(self, env, upgrade_type=None, config_dir=None):
        import params
        env.set_params(params)   
        celeborn(name='master')  

    def start(self, env, upgrade_type=None):
        import params
        env.set_params(params)
        self.configure(env)
        celeborn_service('master', action='start')

        
    def stop(self, env, upgrade_type=None):
        import params
        env.set_params(params)
        celeborn_service('master', action='stop')


    def status(self, env):
        import status_params
        env.set_params(status_params)
        check_process_status(status_params.celeborn_master_pid_file)

    def get_user(self):
        import params
        return params.celeborn_user

    def get_pid_files(self):
        import status_params
        return [status_params.celeborn_master_pid_file]

if __name__ == "__main__":
    CelebornMaster().execute()