"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agree in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import subprocess
import time
import os

from resource_management.core.exceptions import Fail
from resource_management.libraries.script.script import Script
from resource_management.libraries.functions.format import format
from resource_management.core.resources.system import Execute
from resource_management.core.logger import Logger


CHECK_COMMAND_TIMEOUT_DEFAULT = 300.0

class KyuubiServiceCheck(Script):
  def service_check(self, env):
    import params
    env.set_params(params)

    if params.security_enabled:
      #kyuubi_kinit_cmd = format("{kinit_path_local} -kt {smoke_user_keytab} {smokeuser_principal}; ")
      kyuubi_kinit_cmd = format("{kinit_path_local} -kt {hive_kerberos_keytab} {hive_kerberos_principal}; ")
      Execute(kyuubi_kinit_cmd, user=params.smoke_user)


    if params.has_kyuubi_server:
      healthy_kyuubi_host = ""
      for kyuubi_host in params.kyuubi_server_hosts:
        if params.security_enabled:
          kerberos_principal = params.kyuubi_kerberos_principal.replace('_HOST', kyuubi_host)
          beeline_url = ["jdbc:hive2://{kyuubi_host}:{kyuubi_server_port}/default;principal={kerberos_principal}"]
        else:
          beeline_url = ["jdbc:hive2://{kyuubi_host}:{kyuubi_server_port}/default"]
  
        beeline_cmd = os.path.join(params.kyuubi_home, "bin", "beeline")
        cmd = "! %s -u '%s' -n hive -e '' 2>&1| awk '{print}'|grep -i -e 'Connection refused' -e 'Invalid URL' -e 'Error: Could not open'" % \
              (beeline_cmd, format(";".join(beeline_url)))

        try:
          Execute(cmd, user=params.smoke_user, path=[beeline_cmd], timeout=CHECK_COMMAND_TIMEOUT_DEFAULT)
          healthy_kyuubi_host = kyuubi_host
          break
        except:
          pass

      if len(params.kyuubi_server_hosts) > 0 and healthy_kyuubi_host == "":
        raise Fail("Connection to all Kyuubi servers failed.")

if __name__ == "__main__":
  KyuubiServiceCheck().execute()

