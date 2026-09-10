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

import argparse
import configparser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import re
import signal


def configuration(path):
  parser = configparser.ConfigParser(interpolation=None)
  parser.read_string("[server]\n" + Path(path).read_text())
  values = dict(parser["server"])
  values["port"] = int(values["port"])
  if not 1 <= values["port"] <= 65535 or not re.fullmatch(r"[a-f0-9]{64}", values["generation"]):
    raise ValueError("Invalid configuration")
  return values


class HealthHandler(BaseHTTPRequestHandler):
  def do_GET(self):
    # Acknowledgement follows validation and publication inside the process.
    values = self.server.configuration
    self.send_response(200 if self.path == "/health" else 404)
    self.send_header("X-Ambari-Config-Generation", values["generation"])
    self.end_headers()
    self.wfile.write((values.get("message", "ok") + "\n").encode())

  def log_message(self, format, *args):
    # This development example logs no request-controlled text.
    pass


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("--config", required=True)
  args = parser.parse_args()
  values = configuration(args.config)
  server = HTTPServer(("127.0.0.1", values["port"]), HealthHandler)
  server.configuration = values

  def reload_configuration(*_):
    try:
      pending = configuration(args.config)
      if pending["port"] != server.server_port:
        return  # Listener changes require a restart; never acknowledge them.
      server.configuration = pending
    except (OSError, ValueError, KeyError, configparser.Error):
      return  # Keep serving the previous validated generation.

  signal.signal(signal.SIGHUP, reload_configuration)
  server.serve_forever()
