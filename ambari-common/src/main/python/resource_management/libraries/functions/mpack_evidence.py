"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements.  See the NOTICE file distributed with this work for
additional information regarding copyright ownership.  The ASF licenses this
file to you under the Apache License, Version 2.0 (the "License"); you may not
use this file except in compliance with the License.  You may obtain a copy of
the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
License for the specific language governing permissions and limitations under
the License.
"""

"""Common lifecycle evidence emitted by every Mpack runtime adapter."""


def lifecycle_evidence(management_released, runtime, data, ownership):
  allowed = {
    (False, "managed", "managed", "managed"),
    (True, "absent", "retained", "released"),
    (True, "absent", "purged", "released"),
    (False, "external", "external", "external"),
    (True, "external", "external", "external"),
  }
  values = (bool(management_released), runtime, data, ownership)
  if values not in allowed:
    raise ValueError("Invalid Mpack lifecycle evidence disposition")
  return {
    "managementReleased": values[0],
    "runtimeDisposition": runtime,
    "dataDisposition": data,
    "ownershipDisposition": ownership,
  }
