# -*- coding: utf-8 -*-
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from resource_management.core.resources.system import Execute
import re
from resource_management import *
def recursive_glob(rootdir='.', suffix='', filter_func=None):
    import glob
    import os

    """Recursively glob files with a specific suffix from rootdir, and apply an optional filter."""
    files = [
        os.path.join(looproot, filename)
        for looproot, _, filenames in os.walk(rootdir)
        for filename in filenames if filename.endswith(suffix)
    ]
    # 如果提供了过滤函数，进一步过滤文件列表
    if filter_func is not None:
        files = [file for file in files if filter_func(file)]
    return files


def process_connector_conf(catalog_conf_dir,trino_user,trino_group):
    white_list=["jmx", "tpcds", "tpch"]

    config = Script.get_config()
    connector_lists = {k: v for k, v in config['configurations']['connectors.properties'].items() if k.startswith("connector_")}
    for k, v in connector_lists.items():
        connector_tpl_content = InlineTemplate(config['configurations']['connectors.properties'][k])
        connector_name = k.split("_")[1]
        connector_file = os.path.join(catalog_conf_dir, connector_name + '.properties')
        Logger.info(f"writing connector file to {connector_file}")
        File(connector_file,
             owner=trino_user,
             group=trino_group,
             content=connector_tpl_content)

    # 遍历删除catalog 目录下所有 .properties
    connector_filepaths = recursive_glob(catalog_conf_dir, "*.properties")
    connector_name_lists = {k.split("connector_")[1] for k, v in config['configurations']['connectors.properties'].items() if k.startswith("connector_")}
    for filepath in connector_filepaths:
        connector_file_name = os.path.basename(filepath)
        connector_name = connector_file_name.split(".properties")[0]
        if  (connector_name not in connector_name_lists) and (connector_namenot in white_list):
            Logger.info(f" connector file will be removed {filepath}")
            os.remove(filepath)


def check_jdk_version():
    pass
# Replace 'your_file_path' with the actual file path