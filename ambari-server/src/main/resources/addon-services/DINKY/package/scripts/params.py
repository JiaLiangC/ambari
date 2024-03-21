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

import sys
import os
from resource_management import *
from resource_management.core.logger import Logger
from resource_management.libraries.functions.format import format
from resource_management.libraries.script.script import Script



config = Script.get_config()

stack_root = Script.get_stack_root()

component_directory = "dinky-server"
dinky_home = format("{stack_root}/current/{component_directory}")
dinky_conf_dir = format("{dinky_home}/config")


dinky_user = config['configurations']['dinky-env']['dinky_user']
dinky_group = config['configurations']['dinky-env']['dinky_group']
dinky_pid_dir = config['configurations']['dinky-env']['dinky_pid_dir']
dinky_pid_filename = format("dinky-{dinky_user}.pid")
dinky_pid_file = os.path.join(dinky_pid_dir, dinky_pid_filename)

dinky_log_dir = config['configurations']['dinky-env']['dinky_log_dir']



dinky_bin_dir = dinky_home
dinky_lib_dir = os.path.join(dinky_home, "lib")
dinky_lib_jars = format("{dinky_lib_dir}/*")
dinky_extends_flink_dir = os.path.join(dinky_home, "extends")
dinky_extends_flink_jars = format("{dinky_extends_flink_dir}/*")

dinky_init_mysql_sqlfile = os.path.join(dinky_home, "sql/dinky-mysql.sql")
dinky_init_pgsqll_sqlfile = os.path.join(dinky_home, "sql/dinky-pg.sql")
dinky_application_main_config_file = "application.yml"
dinky_application_main_config_template_file = format("{dinky_application_main_config_file}.j2")
dinky_application_mysql_config_file = "application-mysql.yml"
dinky_application_mysql_config_template_file = format("{dinky_application_mysql_config_file}.j2")
dinky_application_pgsql_config_file = "application-pgsql.yml"
dinky_application_pgsql_config_template_file = format("{dinky_application_pgsql_config_file}.j2")

start_script_name = "auto.sh"
start_script_path = os.path.join(dinky_home, start_script_name)
start_script_template_file = format("{start_script_name}.j2")



dinky_env_map = {}

dinky_env_map.update(config['configurations']['dinky-application-server'])
dinky_flink_big_version = dinky_env_map['flink.big.version']

dinky_server_port = dinky_env_map['server.port']

dinky_database_config = {'dinky_database_type': dinky_env_map['spring.profiles.active'],
                         'dinky_database_username': dinky_env_map['spring.datasource.database.username'],
                         'dinky_database_password': dinky_env_map['spring.datasource.database.password']}


dinky_database_password = dinky_env_map['spring.datasource.database.password']
dinky_database_name = dinky_env_map['spring.datasource.database.name']
if 'mysql' == dinky_database_config['dinky_database_type']:

    dinky_database_config['dinky_database_driver'] = 'com.mysql.jdbc.Driver'
    dinky_database_config['dinky_database_url'] = 'jdbc:mysql://' + dinky_env_map['spring.datasource.database.host'] \
                                                  + ':' + dinky_env_map['spring.datasource.database.port'] \
                                                  + '/' + dinky_env_map['spring.datasource.database.name'] \
                                                  + '?useUnicode=true&characterEncoding=UTF-8'
    database_host = dinky_env_map['spring.datasource.database.host']
    database_port = dinky_env_map['spring.datasource.database.port']
    dinky_init_sql_path = dinky_init_mysql_sqlfile
    sql_client = "mysql"
    #mysql -h hostname -P port -u username -p'password' dinky_database_name < /path/to/file.sql

    init_sql = format("{sql_client} -h {database_host} -P {database_port}  -u {dinky_user} -p'{dinky_database_password}'   {dinky_database_name}  < {dinky_init_sql_path}")
else:

    dinky_database_config['dinky_database_driver'] = 'org.postgresql.Driver'
    dinky_database_config['dinky_database_url'] = 'jdbc:postgresql://' + dinky_env_map[
        'spring.datasource.database.host'] \
                                                  + ':' + dinky_env_map['spring.datasource.database.port'] \
                                                  + '/' + dinky_env_map['spring.datasource.database.name'] \
                                                  + '?stringtype=unspecified'
    database_host = dinky_env_map['spring.datasource.database.host']
    database_port = dinky_env_map['spring.datasource.database.port']
    dinky_init_sql_path = dinky_init_pgsqll_sqlfile
    sql_client = "psql"
    init_sql = format("PGPASSWORD={dinky_database_password} {sql_client} -h {database_host} -p {database_port}  -U {dinky_user}  -d {dinky_database_name}  < {dinky_init_sql_path}")
