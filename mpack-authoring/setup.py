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

from pathlib import Path
import shutil

from setuptools import find_packages, setup
from setuptools.command.build_py import build_py

ROOT = Path(__file__).resolve().parent


class BuildWithSchema(build_py):
  def run(self):
    super().run()
    # Only the build output gets a copy; keep one version-controlled schema.
    shutil.copyfile(ROOT / "schema/manifest-v2alpha1.json",
                    Path(self.build_lib) / "mpack_authoring/manifest-v2alpha1.json")


setup(
  name="ambari-mpack-authoring",
  version="0.1.0a1",
  description="Ambari declarative Mpack authoring and offline validation",
  license="Apache-2.0",
  python_requires=">=3.9",
  package_dir={"": "src/main/python"},
  packages=find_packages("src/main/python"),
  package_data={"mpack_authoring": ["manifest-v2alpha1.json"]},
  install_requires=[line.strip() for line in (ROOT / "requirements.txt").read_text().splitlines()
                    if line.strip() and not line.startswith("#")],
  entry_points={"console_scripts": ["mpack-validate=mpack_authoring.validate_manifest:main", "mpack-review=mpack_authoring.review:main"]},
  cmdclass={"build_py": BuildWithSchema},
)
