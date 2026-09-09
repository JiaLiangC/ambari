# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License

MPACK_INSTANCE_MANAGER_BINARY="/usr/lib/mpack-instance-manager/mpack-instance-manager.py"
MPACK_INSTANCE_MANAGER_BINARY_SYMLINK="/usr/sbin/mpack-instance-manager"

# Set the command symlink without replacing a non-symlink owned by another package.
if [ -L "$MPACK_INSTANCE_MANAGER_BINARY_SYMLINK" ]; then
  ln -sfn "$MPACK_INSTANCE_MANAGER_BINARY" "$MPACK_INSTANCE_MANAGER_BINARY_SYMLINK"
elif [ ! -e "$MPACK_INSTANCE_MANAGER_BINARY_SYMLINK" ]; then
  ln -s "$MPACK_INSTANCE_MANAGER_BINARY" "$MPACK_INSTANCE_MANAGER_BINARY_SYMLINK"
else
  echo "Cannot install $MPACK_INSTANCE_MANAGER_BINARY_SYMLINK: path already exists" >&2
  exit 1
fi

exit 0
