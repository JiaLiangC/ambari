#!/usr/bin/env python3
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

"""Read the local demonstration server using the published client configuration."""

import argparse
import json
from pathlib import Path
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, request, fp, code, message, headers, new_url):
    return None


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--config", required=True, type=Path)
  args = parser.parse_args()
  config = json.loads(args.config.read_text())
  port = config["port"]
  if type(port) is not int or not 1 <= port <= 65535:
    parser.error("Configuration port must be an integer between 1 and 65535")
  opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
  with opener.open("http://127.0.0.1:{}/".format(port), timeout=5) as response:
    print(response.read(65536).decode("utf-8", errors="replace"))


if __name__ == "__main__":
  main()
