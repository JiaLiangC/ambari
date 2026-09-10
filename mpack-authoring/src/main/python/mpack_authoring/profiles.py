"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

PROFILES = {
  "host.systemd/v1": {"install", "configure", "start", "stop", "observe"},
  "oci.container/v1": {"install", "configure", "start", "stop", "observe"},
  "kubernetes.workload/v1": {"install", "configure", "start", "stop", "observe"},
  "external.database/v1": {"observe"},
}


def profile_capabilities(profile_id):
  try:
    return frozenset(PROFILES[profile_id])
  except KeyError as error:
    raise ValueError("Unsupported runtime profile {}".format(profile_id)) from error
