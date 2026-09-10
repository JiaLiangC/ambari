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
import base64
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class AcceptanceFailure(Exception):
  pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, request, stream, code, message, headers, new_url):
    raise AcceptanceFailure("HTTP_REDIRECT_REJECTED")


class Client:
  def __init__(self, url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or parsed.username or parsed.password or parsed.query or parsed.fragment:
      raise AcceptanceFailure("INVALID_API_URL")
    self.url = url.rstrip("/") + "/api/v1"
    self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    user = os.environ.get("AMBARI_USERNAME")
    password = os.environ.get("AMBARI_PASSWORD")
    if not user or not password:
      raise AcceptanceFailure("MISSING_API_CREDENTIALS")
    self.authorization = "Basic " + base64.b64encode((user + ":" + password).encode()).decode()

  def request(self, method, path, data=None, absent=False):
    headers = {"Authorization": self.authorization, "X-Requested-By": "mpack-acceptance"}
    if isinstance(data, bytes):
      headers["Content-Type"] = "application/octet-stream"
    elif data is not None:
      headers["Content-Type"] = "application/json"
      data = json.dumps(data).encode()
    request = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)
    try:
      with self.opener.open(request, timeout=60) as response:
        body = response.read(2 * 1024 * 1024 + 1)
        if len(body) > 2 * 1024 * 1024:
          raise AcceptanceFailure("RESPONSE_LIMIT")
        return json.loads(body) if body else {}
    except urllib.error.HTTPError as error:
      if absent and error.code == 404:
        return None
      raise AcceptanceFailure("HTTP_" + str(error.code)) from None
    except (OSError, ValueError):
      raise AcceptanceFailure("OUTCOME_UNKNOWN_INSPECT_EXISTING_REQUESTS") from None

  def resources(self, cluster):
    result = []
    cursor = ""
    for _ in range(1000):
      page = self.request("GET", cluster + "/mpack_resources?after=" + cursor)["items"]
      result.extend(page)
      if len(page) < 100:
        return result
      following = page[-1]["targetKey"]
      if not isinstance(following, str) or following <= cursor or len(following) != 64:
        raise AcceptanceFailure("INVALID_RESOURCE_CURSOR")
      cursor = following
    raise AcceptanceFailure("RESOURCE_SCAN_LIMIT")

  def wait(self, cluster, response):
    request_id = response.get("Requests", {}).get("id")
    if request_id is None:
      return
    print(json.dumps({"requestId": request_id, "state": "SUBMITTED"}), flush=True)
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
      request = self.request("GET", cluster + "/requests/" + str(request_id) + "?fields=Requests/request_status")
      state = request.get("Requests", {}).get("request_status")
      if state == "COMPLETED":
        return
      if state in ("FAILED", "ABORTED", "TIMEDOUT"):
        raise AcceptanceFailure("REQUEST_" + state)
      time.sleep(1)
    raise AcceptanceFailure("OUTCOME_UNKNOWN_REQUEST_DEADLINE")


def main(argv=None):
  parser = argparse.ArgumentParser(description="Opt-in disposable Ambari Server-Agent package acceptance")
  parser.add_argument("--api-url", required=True)
  parser.add_argument("--cluster", required=True)
  parser.add_argument("--host", required=True)
  parser.add_argument("--package", required=True, help="Trusted deployable .mpack file")
  parser.add_argument("--service", required=True)
  parser.add_argument("--allow-disposable-cluster-changes", action="store_true")
  args = parser.parse_args(argv)
  if not args.allow_disposable_cluster_changes:
    print("No changes made. This harness requires an explicitly disposable integration cluster.", file=sys.stderr)
    return 2
  try:
    client = Client(args.api_url)
    package = Path(args.package)
    if package.stat().st_size > 64 * 1024 * 1024:
      raise AcceptanceFailure("SMOKE_FIXTURE_LIMIT_64_MIB")
    imported = client.request("POST", "/mpacks/imports", package.read_bytes())
    resource = (imported.get("resources") or [{}])[0].get("MpackInfo", {})
    package_id = resource.get("id")
    if package_id is None:
      raise AcceptanceFailure("IMPORT_RESPONSE_MISSING_ID")
    # The repeated import must reconcile to the same catalog row.
    repeated = client.request("POST", "/mpacks/imports", package.read_bytes())
    if (repeated.get("resources") or [{}])[0].get("MpackInfo", {}).get("id") != package_id:
      raise AcceptanceFailure("IMPORT_IDENTITY_CHANGED")
    metadata = client.request("GET", "/mpacks/" + str(package_id) + "?fields=MpackInfo/*")["MpackInfo"]
    quote = lambda value: urllib.parse.quote(value, safe="")
    cluster = "/clusters/" + quote(args.cluster)
    service = cluster + "/services/" + quote(args.service)
    client.request("GET", cluster + "/hosts/" + quote(args.host))
    definition = client.request("GET", "/stacks/" + quote(metadata["stack_name"]) + "/versions/"
      + quote(metadata["mpack_version"]) + "/services/" + quote(args.service)
      + "?fields=components/StackServiceComponents/*,configurations/StackConfigurations/*")
    existing = client.request("GET", service, absent=True)
    repository = metadata["repository_version_id"]
    if existing and existing["ServiceInfo"]["desired_repository_version_id"] != repository:
      raise AcceptanceFailure("EXISTING_SERVICE_USES_ANOTHER_PACKAGE")
    if existing and existing["ServiceInfo"].get("state") == "STARTED":
      raise AcceptanceFailure("STOP_EXISTING_SERVICE_BEFORE_DISPOSABLE_ACCEPTANCE")
    if existing is None:
      client.request("POST", cluster + "/services", {"ServiceInfo": {
        "service_name": args.service, "desired_repository_version_id": repository}})
    for row in definition["components"]:
      name = row["StackServiceComponents"]["component_name"]
      component = service + "/components/" + quote(name)
      if client.request("GET", component, absent=True) is None:
        client.request("POST", component, {"ServiceComponentInfo": {"component_name": name}})
      host = cluster + "/hosts/" + quote(args.host) + "/host_components/" + quote(name)
      if client.request("GET", host, absent=True) is None:
        client.request("POST", host, {"HostRoles": {"component_name": name}})
    configs = {}
    for row in definition.get("configurations", []):
      value = row["StackConfigurations"]
      configs.setdefault(value["type"].removesuffix(".xml"), {})[value["property_name"]] = str(value.get("property_value", ""))
    desired = client.request("GET", cluster + "?fields=Clusters/desired_configs")["Clusters"].get("desired_configs", {})
    missing = [{"type": name, "tag": "mpack-acceptance-" + str(time.time_ns()), "properties": values}
      for name, values in configs.items() if name not in desired]
    if missing:
      client.request("PUT", cluster, {"Clusters": {"desired_config": missing}})
    for state in ("INSTALLED", "STARTED", "INSTALLED"):
      result = client.request("PUT", service, {"RequestInfo": {"context": "Mpack disposable acceptance"},
        "Body": {"ServiceInfo": {"state": state}}})
      client.wait(cluster, result)
    client.wait(cluster, client.request("POST", cluster + "/requests", {
      "RequestInfo": {"command": "UNINSTALL", "context": "Uninstall and retain acceptance data"},
      "Requests": {"resource_filters": [{"service_name": args.service,
        "component_name": row["StackServiceComponents"]["component_name"]} for row in definition["components"]]}}))
    resources = client.resources(cluster)
    selected = [row for row in resources if row["serviceName"] == args.service and row["packageId"] == package_id]
    if not selected or any(row["state"] != "UNINSTALLED_RETAINED" for row in selected):
      raise AcceptanceFailure("MISSING_VERIFIED_RETENTION_EVIDENCE")
    client.request("DELETE", service)
    retained = client.resources(cluster)
    if not all(any(row["targetKey"] == before["targetKey"] for row in retained) for before in selected):
      raise AcceptanceFailure("RETENTION_EVIDENCE_LOST_AFTER_SERVICE_DELETE")
    print(json.dumps({"result": "PASS", "scope": "provided-server-agent", "packageId": package_id,
      "retainedTargets": len(selected), "limits": ["No fault injection", "No database upgrade acceptance",
        "Retention is verified from Agent evidence; physical data recovery requires separate acceptance"]}))
    return 0
  except (AcceptanceFailure, KeyError, OSError, ValueError) as error:
    code = str(error) if isinstance(error, AcceptanceFailure) else "ACCEPTANCE_INPUT_OR_CONTRACT_FAILURE"
    print(json.dumps({"result": "FAIL", "code": code,
      "recovery": "Inspect existing tasks and target evidence. No automatic rollback or purge was attempted."}))
    return 1


if __name__ == "__main__":
  sys.exit(main())
