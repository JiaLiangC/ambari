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

from resource_management import *
import  os

def dinky_env():
    import params  # import 导入params.py文件
    # User(params.dinky_user, action="create", groups=params.dinky_group
    #      , ignore_already_exists=True  # 忽略已经存在
    #      )  # 创建用户

    Directory([params.dinky_log_dir, params.dinky_pid_dir],
              owner=params.dinky_user,
              group=params.dinky_group,
              mode=0o775,
              create_parents = True
              )


    ## 重写 启动脚本 auto.sh 文件
    File(os.path.join(params.dinky_bin_dir, params.start_script_name),
         mode=0o755,
         content=Template(params.start_script_template_file),
         owner=params.dinky_user,
         group=params.dinky_group
         )

    #content=Template("hbase.conf.j2")
    # 重写 application.yml 文件
    File(os.path.join(params.dinky_conf_dir, params.dinky_application_main_config_file),
         mode=0o755,
         content=Template(params.dinky_application_main_config_template_file),
         owner=params.dinky_user,
         group=params.dinky_group
         )

    ## 根据 mysql 还是 pgsql 重写 application-xxx.yml 文件
    if params.dinky_database_config['dinky_database_type'] == "mysql":
        ## 重写 application-mysql.yml 文件
        File(os.path.join(params.dinky_conf_dir , params.dinky_application_mysql_config_file),
             mode=0o755,
             content=Template(params.dinky_application_mysql_config_template_file),
             owner=params.dinky_user,
             group=params.dinky_group
             )
    else:
        ## 重写 application-pgsql.yml 文件
        File(os.path.join(params.dinky_conf_dir , params.dinky_application_pgsql_config_file),
             mode=0o755,
             content=Template(params.dinky_application_pgsql_config_template_file),
             owner=params.dinky_user,
             group=params.dinky_group
             )