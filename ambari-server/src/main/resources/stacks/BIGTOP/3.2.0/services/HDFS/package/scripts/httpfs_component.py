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

import grp
import pwd

from resource_management import *
from utils import initiate_safe_zkfc_failover, get_hdfs_binary, get_dfsadmin_base_command

class Httpfs_component(Script):
    def configure(self, env):
        import params
        Logger.info("Configure HttpFS service")
        try:
            grp.getgrnam(params.httpfs_group)
        except KeyError:
            Logger.info(format("Creating group '{params.httpfs_group}' for HttpFS"))
            Group( group_name=params.httpfs_group,ignore_failures=params.ignore_groupsusers_create)
        try:
            pwd.getpwnam(params.httpfs_user)
        except KeyError:
            Logger.info(format("Creating user '{params.httpfs_user}' for HttpFS"))
            User(username=params.httpfs_user, 
                 groups=[params.httpfs_group],
                 ignore_failures=params.ignore_groupsusers_create
                 )
        Directory(params.httpfs_pid_dir,
                  owner=params.httpfs_user,
                  group=params.httpfs_group,
                  create_parents=True,
                  mode=0o755,
                  )
        Directory(params.httpfs_temp_dir,
                  owner=params.httpfs_user,
                  group=params.httpfs_group,
                  create_parents=True,
                  mode=0o755,
                  )
        Directory(params.httpfs_log_dir,
                  owner=params.httpfs_user,
                  group=params.httpfs_group,
                  create_parents=True,
                  mode=0o755,
                  )
        Logger.info(format("Creating {params.httpfs_conf_dir}/httpfs-env.sh config file"))
        
        File(format("{params.httpfs_conf_dir}/httpfs-env.sh"),
             content=InlineTemplate(params.httpfs_env_template,
                                    httpfs_server_port=params.httpfs_server_port,
                                    httpfs_log_dir=params.httpfs_log_dir
                                    ),
             owner=params.httpfs_user,
             group=params.httpfs_group,
             mode=0o644
             )
        Logger.info(format("Creating {params.httpfs_conf_dir}/httpfs-env.sh config file - DONE"))
        Logger.info(format("Creating {params.httpfs_conf_dir}/httpfs-site.xml config file"))
        XmlConfig("httpfs-site.xml",
                  mode=0o644,
                  owner=params.httpfs_user,
                  group=params.httpfs_group,
                  conf_dir=params.httpfs_conf_dir,
                  configurations=params.config['configurations']['httpfs-site'],
                  configuration_attributes=params.config['configuration_attributes']['httpfs-site']
                  )
        Logger.info(format("Creating {params.httpfs_conf_dir}/httpfs-site.xml config file - DONE"))
        Logger.info(format("Creating {params.httpfs_conf_dir}/httpfs-log4j.properties config file"))
        File(format("{params.httpfs_conf_dir}/httpfs-log4j.properties"),
             mode=0o644,
             owner=params.httpfs_user,
             group=params.httpfs_group,
             content=params.httpfs_log4j_content
             )
        Logger.info(format("Creating {params.httpfs_conf_dir}/httpfs-log4j.properties config file - Done"))
        #Logger.info("Creating symlinks")
        #Link("/usr/bigtop/current/hadoop-httpfs/libexec", to="/usr/bigtop/current/hadoop-client/libexec")
        #Logger.info("Creating symlinks - DONE")

    def install(self, env):
        import params
        Logger.info("Installing HttpFS packages")
        self.install_packages(env)

    def stop(self, env):
        import params
        Logger.info("Stopping HttpFS service")
        hdfs_binary = get_hdfs_binary("HttpFS")
        command = format("{hdfs_binary} --daemon stop httpfs")
        Execute(
            command,
            user=params.httpfs_user,
            environment={'HTTPFS_TEMP': params.httpfs_temp_dir, 'HTTPFS_CONFIG': params.httpfs_conf_dir },
            logoutput=True)


        File(params.httpfs_pid_file,
             action = "delete",
             owner = params.httpfs_user
             )


    def start(self, env):
        import params
        self.configure(env)
        hdfs_binary = get_hdfs_binary("HttpFS")
        command = format("{hdfs_binary} --daemon start httpfs")
        Execute(
            command,
            user=params.httpfs_user,
            environment={'HTTPFS_TEMP': params.httpfs_temp_dir, 'HTTPFS_CONFIG': params.httpfs_conf_dir },
            logoutput=True)
        Logger.info("Starting HttpFS service")


    def status(self, env):
        import params
        check_process_status(params.httpfs_pid_file)


if __name__ == "__main__":
    Httpfs_component().execute()
