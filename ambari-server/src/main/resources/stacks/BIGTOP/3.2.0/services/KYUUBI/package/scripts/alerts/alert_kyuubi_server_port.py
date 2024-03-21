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

//TODO: 有待实现
alert_kyuubi_server_port.py的实现逻辑可以参考alert_spark_thrift_port.py,在此不列出具体实现逻辑,原理就是定时执行beeline连接操作判断是否可以连接成功。


"""

import os
import socket
import time
import logging
import traceback
from resource_management.libraries.functions import format
from ambari_commons.os_family_impl import OsFamilyFuncImpl, OsFamilyImpl
from resource_management.libraries.script.script import Script
from resource_management.libraries.functions import get_kinit_path
from resource_management.core.resources import Execute
from resource_management.core import global_lock


stack_root = Script.get_stack_root()

OK_MESSAGE = "TCP OK - {0:.3f}s response on port {1}"
CRITICAL_MESSAGE = "Connection failed on host {0}:{1} ({2})"

KYUUBI_SERVER_THRIFT_PORT_KEY = '{{kyuubi-defaults/kyuubi.frontend.thrift.binary.bind.port}'

SECURITY_ENABLED_KEY = '{{cluster-env/security_enabled}}'

KYUUBI_SERVER_KERBEROS_KEYTAB = '{{kyuubi-defaults/kyuubi.kinit.keytab}}'
KYUUBI_SERVER_PRINCIPAL_KEY = '{{kyuubi-defaults/kyuubi.kinit.principal}}'

# The configured Kerberos executable search paths, if any
KERBEROS_EXECUTABLE_SEARCH_PATHS_KEY = '{{kerberos-env/executable_search_paths}}'

THRIFT_PORT_DEFAULT = 10009
KYUUBI_SERVER_TRANSPORT_MODE_DEFAULT = 'binary'

KYUUBI_USER_KEY = '{{kyuubi-env/kyuubi_user}}'

CHECK_COMMAND_TIMEOUT_KEY = 'check.command.timeout'
CHECK_COMMAND_TIMEOUT_DEFAULT = 60.0

logger = logging.getLogger('ambari_alerts')

@OsFamilyFuncImpl(os_family=OsFamilyImpl.DEFAULT)
def get_tokens():
    """
    Returns a tuple of tokens in the format {{site/property}} that will be used
    to build the dictionary passed into execute
    """
    return (KYUUBI_SERVER_THRIFT_PORT_KEY, KYUUBI_SERVER_TRANSPORT_MODE_DEFAULT, 
                SECURITY_ENABLED_KEY, KERBEROS_EXECUTABLE_SEARCH_PATHS_KEY, KYUUBI_USER_KEY,
                KYUUBI_SERVER_KERBEROS_KEYTAB, KYUUBI_SERVER_PRINCIPAL_KEY )

@OsFamilyFuncImpl(os_family=OsFamilyImpl.DEFAULT)
def execute(configurations={}, parameters={}, host_name=None):
    """
    Returns a tuple containing the result code and a pre-formatted result label

    Keyword arguments:
    configurations (dictionary): a mapping of configuration key to value
    parameters (dictionary): a mapping of script parameter key to value
    host_name (string): the name of this host where the alert is running
    """

    kyuubi_home = os.path.join(stack_root, "current", 'kyuubi-client')

    if configurations is None:
        return ('UNKNOWN', ['There were no configurations supplied to the script.'])

    transport_mode = KYUUBI_SERVER_TRANSPORT_MODE_DEFAULT
    if KYUUBI_SERVER_TRANSPORT_MODE_DEFAULT in configurations:
        transport_mode = configurations[KYUUBI_SERVER_TRANSPORT_MODE_DEFAULT]

 
    port = THRIFT_PORT_DEFAULT
    if transport_mode.lower() == 'binary' and KYUUBI_SERVER_THRIFT_PORT_KEY in configurations:
        port = int(configurations[KYUUBI_SERVER_THRIFT_PORT_KEY])

 
    security_enabled = False
    if SECURITY_ENABLED_KEY in configurations:
        security_enabled = str(configurations[SECURITY_ENABLED_KEY]).upper() == 'TRUE'

    kyuubi_kerberos_keytab = None
    if KYUUBI_SERVER_KERBEROS_KEYTAB in configurations:
        kyuubi_kerberos_keytab = configurations[KYUUBI_SERVER_KERBEROS_KEYTAB]

    if host_name is None:
        host_name = socket.getfqdn()

    kyuubi_principal = None
    if KYUUBI_SERVER_PRINCIPAL_KEY in configurations:
        kyuubi_principal = configurations[KYUUBI_SERVER_PRINCIPAL_KEY]
        kyuubi_principal = kyuubi_principal.replace('_HOST',host_name.lower())

    # Get the configured Kerberos executable search paths, if any
    if KERBEROS_EXECUTABLE_SEARCH_PATHS_KEY in configurations:
        kerberos_executable_search_paths = configurations[KERBEROS_EXECUTABLE_SEARCH_PATHS_KEY]
    else:
        kerberos_executable_search_paths = None

    kinit_path_local = get_kinit_path(kerberos_executable_search_paths)

    kyuubiuser = configurations[KYUUBI_USER_KEY]

    if security_enabled:
        kinitcmd = format("{kinit_path_local} -kt {kyuubi_kerberos_keytab} {kyuubi_principal}; ")
        # prevent concurrent kinit
        kinit_lock = global_lock.get_lock(global_lock.LOCK_TYPE_KERBEROS)
        kinit_lock.acquire()
        try:
            Execute(kinitcmd, user=kyuubiuser)
        finally:
            kinit_lock.release()

    result_code = None
    try:
        if host_name is None:
            host_name = socket.getfqdn()

        beeline_url = ["jdbc:hive2://{host_name}:{port}/default", "transportMode={transport_mode}"]
        if security_enabled:
            beeline_url.append("principal={kyuubi_principal}")

        # append url according to used transport

        beeline_cmd = os.path.join(kyuubi_home, "bin", "beeline")
        cmd = "! %s -u '%s'  -e '' 2>&1| awk '{print}'|grep -i -e 'Connection refused' -e 'Invalid URL' -e 'Error: Could not open'" % \
              (beeline_cmd, format(";".join(beeline_url)))

        start_time = time.time()
        try:
            Execute(cmd, user=kyuubiuser, path=[beeline_cmd], timeout=CHECK_COMMAND_TIMEOUT_DEFAULT)
            total_time = time.time() - start_time
            result_code = 'OK'
            label = OK_MESSAGE.format(total_time, port)
        except:
            result_code = 'CRITICAL'
            label = CRITICAL_MESSAGE.format(host_name, port, traceback.format_exc())
    except:
        label = traceback.format_exc()
        result_code = 'UNKNOWN'

    return (result_code, [label])

