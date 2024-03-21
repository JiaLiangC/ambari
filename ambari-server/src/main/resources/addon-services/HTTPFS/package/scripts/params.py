from resource_management import *
from resource_management.libraries.functions import get_kinit_path

config = Script.get_config()
tmp_dir = Script.get_tmp_dir()

ignore_groupsusers_create = default("/configurations/cluster-env/ignore_groupsusers_create", False)
smoke_user = default("/configurations/cluster-env/smokeuser", "ambari-qa")
smoke_user_principal = default("/configurations/cluster-env/smokeuser_principal_name", "")
smoke_user_keytab = default("/configurations/cluster-env/smokeuser_keytab", "")
kinit_path_local = get_kinit_path(default("/configurations/kerberos-env/executable_search_paths", None))

httpfs_user = config['configurations']['httpfs-env']['httpfs_user']
httpfs_group = config['configurations']['httpfs-env']['httpfs_group']
httpfs_conf_dir = config['configurations']['httpfs-env']['conf_dir']

httpfs_server_host = config['clusterHostInfo']['httpfs_gateway_hosts'][0]
httpfs_server_port = config['configurations']['httpfs-env']['port']
httpfs_log_dir = config['configurations']['httpfs-env']['httpfs_log_dir']

httpfs_env_template = config['configurations']['httpfs-env']['content']
httpfs_log4j_content = config['configurations']['httpfs-log4j']['content']

_authentication = config['configurations']['core-site']['hadoop.security.authentication']
security_enabled = ( not is_empty(_authentication) and _authentication == 'kerberos')

