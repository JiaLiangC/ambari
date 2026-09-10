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


"""Namespaced stateless Kubernetes workloads using existing Ambari task receipts."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import time
import urllib.error
import urllib.parse
import urllib.request

from resource_management.libraries.functions.mpack_host import HostDeployment, HostError, _json_hash, _LocalProbeRedirectHandler


def _private_file(path, limit=1024 * 1024):
  path = Path(path)
  if any(parent.is_symlink() for parent in (path, *path.parents)):
    raise HostError("AUTHORIZATION_DENIED", "Runtime connection path must not contain symbolic links")
  try:
    for parent in path.parents:
      parent_state = parent.stat()
      if parent_state.st_uid != 0 or (parent_state.st_mode & 0o022 and not parent_state.st_mode & stat.S_ISVTX):
        raise HostError("AUTHORIZATION_DENIED", "Runtime connection directory is not controlled by root")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
      state = os.fstat(stream.fileno())
      if not stat.S_ISREG(state.st_mode) or state.st_uid != 0 or state.st_mode & 0o077:
        raise HostError("AUTHORIZATION_DENIED", "Runtime connection files must be root-owned and private")
      data = stream.read(limit + 1)
    if len(data) > limit:
      raise HostError("SCHEMA_INVALID", "Runtime connection file exceeds its limit")
    return data
  except OSError:
    raise HostError("DEPENDENCY_UNRESOLVED", "Runtime connection file is unavailable") from None


class KubernetesConnection:
  """Operator-provided transport credentials, separate from package content."""
  def __init__(self, cluster_id, reference, namespace, cancel=None, root="/etc/ambari-agent/mpack/kubernetes"):
    directory = Path(root) / str(cluster_id) / reference
    try:
      value = json.loads(_private_file(directory / "connection.json", 8192))
      if set(value) != {"server", "namespace"} or value["namespace"] != namespace:
        raise ValueError()
      url = urllib.parse.urlsplit(value["server"])
      if (url.scheme != "https" or not url.hostname or url.username or url.password
          or url.path not in ("", "/") or url.query or url.fragment or url.port == 0):
        raise ValueError()
      ca = _private_file(directory / "ca.pem")
      _private_file(directory / "client.pem")
      _private_file(directory / "client-key.pem")
      context = ssl.create_default_context(cadata=ca.decode("ascii"))
      context.load_cert_chain(str(directory / "client.pem"), str(directory / "client-key.pem"))
    except (TypeError, ValueError, UnicodeError, ssl.SSLError, OSError):
      raise HostError("DEPENDENCY_UNRESOLVED", "Kubernetes connection is invalid or unavailable") from None
    self.server = value["server"].rstrip("/")
    self.identity = {"server": self.server, "caDigest": hashlib.sha256(ca).hexdigest()}
    self.cancel = cancel
    self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
      _LocalProbeRedirectHandler(), urllib.request.HTTPSHandler(context=context))

  def request(self, method, path, body=None, absent=False):
    if not path.startswith("/") or path.startswith("//") or self.cancel is not None and self.cancel.is_set():
      raise HostError("OUTCOME_UNKNOWN", "Kubernetes request canceled or invalid", "UNKNOWN")
    data = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
    if data is not None and len(data) > 1024 * 1024:
      raise HostError("SCHEMA_INVALID", "Kubernetes request exceeds its bound")
    request = urllib.request.Request(self.server + path, data=data, method=method,
      headers={"Accept": "application/json", "Content-Type": "application/json"})
    try:
      with self.opener.open(request, timeout=10) as response:
        raw = response.read(1024 * 1024 + 1)
      if len(raw) > 1024 * 1024:
        raise ValueError()
      value = json.loads(raw)
      if not isinstance(value, dict):
        raise ValueError()
      return value
    except urllib.error.HTTPError as error:
      status = error.code
      error.close()
      if method == "GET" and absent and status == 404:
        return None
      code = "AUTHORIZATION_DENIED" if status in (401, 403) else "TARGET_CONFLICT" if status == 409 else "OUTCOME_UNKNOWN"
      raise HostError(code, "Kubernetes API request was not confirmed", "UNKNOWN" if code == "OUTCOME_UNKNOWN" else "FAILED") from None
    except (OSError, ValueError, urllib.error.URLError):
      raise HostError("OUTCOME_UNKNOWN", "Kubernetes API outcome is unavailable", "UNKNOWN") from None


class KubernetesDeployment(HostDeployment):
  runtime_profile = "kubernetes.workload/v1"
  operations = frozenset({"install", "configure", "start", "stop", "uninstall", "purge", "observe"})

  def __init__(self, *args, connection=None, **kwargs):
    super().__init__(*args, **kwargs)
    resources = self.resources
    if (set(resources) - {"connectionRef", "namespace", "image", "replicas", "runAsUserId", "command", "limits"}
        or self.component.get("category") == "CLIENT" or set(self.profile["capabilities"]) - self.operations
        or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", resources.get("connectionRef", ""))
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", resources.get("namespace", ""))
        or not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}", resources.get("image", ""))
        or type(resources.get("replicas", 1)) is not int or not 1 <= resources.get("replicas", 1) <= 32
        or type(resources.get("runAsUserId")) is not int or not 1 <= resources["runAsUserId"] <= 2147483647
        or self.profile.get("health", {}).get("kind") not in ("http", "tcp")
        or any(config.get("template") for config in self.service.get("configurations", []))):
      raise HostError("CAPABILITY_UNSUPPORTED", "Kubernetes requires a scoped stateless image, scalar environment and readiness probe")
    self.namespace = resources["namespace"]
    self.connection = connection or KubernetesConnection(self.identity["clusterId"], resources["connectionRef"], self.namespace, self.cancel)
    self.native_name = "mpack-" + _json_hash(self.identity)[:40]
    self.collection = "/apis/apps/v1/namespaces/" + self.namespace + "/deployments"
    self.path = self.collection + "/" + self.native_name

  def _configurations(self):
    for config in self.service.get("configurations", []):
      fields = json.loads(self._source(config["schema"]).read_text()).get("properties", {})
      if any(field.get("x-sensitive") or field.get("x-resource") for field in fields.values()):
        raise HostError("CAPABILITY_UNSUPPORTED", "Kubernetes environment configuration cannot contain live secrets or host paths")
    return super()._configurations()

  def _namespace(self):
    value = self.connection.request("GET", "/api/v1/namespaces/" + self.namespace)
    uid = value.get("metadata", {}).get("uid")
    if not uid or value.get("metadata", {}).get("deletionTimestamp"):
      raise HostError("TARGET_CONFLICT", "Kubernetes namespace is missing or terminating")
    identity = dict(self.connection.identity, namespaceUid=uid)
    if self._receipt().get("kubernetesIdentity") not in (None, identity):
      raise HostError("TARGET_CONFLICT", "Kubernetes endpoint or namespace identity changed")
    return identity

  def discover(self):
    identity = self._namespace()
    api = self.connection.request("GET", "/apis/apps/v1")
    deployment = next((value for value in api.get("resources", []) if value.get("name") == "deployments"), {})
    if not deployment.get("namespaced") or not {"get", "create", "update", "delete"} <= set(deployment.get("verbs", [])):
      raise HostError("CAPABILITY_UNSUPPORTED", "Required Deployment API is unavailable")
    return {"profile": self.runtime_profile, "identity": self.identity, "target": self.namespace + "/" + self.native_name,
      "kubernetesIdentity": identity, "observedAt": time.time(), "validForSeconds": 30,
      "capabilities": sorted(set(self.profile["capabilities"]) & self.operations)}

  def _inspect(self, receipt):
    value = self.connection.request("GET", self.path, absent=True)
    if value is None:
      return None
    metadata = value.get("metadata", {})
    annotations = metadata.get("annotations", {})
    if (not metadata.get("uid") or not metadata.get("resourceVersion")
        or metadata.get("namespace") != self.namespace or metadata.get("name") != self.native_name
        or receipt.get("deploymentUid") not in (None, metadata["uid"])
        or not receipt.get("creationIntent") or annotations.get("ambari.apache.org/intent") != receipt["creationIntent"]
        or annotations.get("ambari.apache.org/package") != self.package_digest
        or metadata.get("labels", {}).get("ambari-mpack-target") != self.native_name):
      raise HostError("TARGET_CONFLICT", "Kubernetes workload UID or creation ownership differs")
    return value

  def _owned(self, receipt):
    if self.root.is_symlink():
      raise HostError("TARGET_CONFLICT", "Kubernetes receipt path is not owned")
    self._namespace()
    self._inspect(receipt)

  def _list(self, path):
    value = self.connection.request("GET", path + "?limit=256&labelSelector=ambari-mpack-target%3D" + self.native_name)
    items = value.get("items")
    if not isinstance(items, list) or len(items) > 256 or value.get("metadata", {}).get("continue"):
      raise HostError("OUTCOME_UNKNOWN", "Kubernetes child observation exceeds its bound", "UNKNOWN")
    return items

  def _children(self, uid):
    replicas = self._list("/apis/apps/v1/namespaces/" + self.namespace + "/replicasets")
    owned = set()
    for item in replicas:
      metadata = item.get("metadata", {})
      owners = metadata.get("ownerReferences", [])
      if not uid or not any(owner.get("uid") == uid and owner.get("kind") == "Deployment" and owner.get("controller") for owner in owners):
        raise HostError("TARGET_CONFLICT", "A ReplicaSet has foreign ownership")
      owned.add(metadata["uid"])
    pods = self._list("/api/v1/namespaces/" + self.namespace + "/pods")
    foreign = any(not any(owner.get("uid") in owned and owner.get("kind") == "ReplicaSet" and owner.get("controller")
                  for owner in pod.get("metadata", {}).get("ownerReferences", [])) for pod in pods)
    return pods, foreign

  def observe(self):
    receipt = self._receipt()
    identity = self._namespace()
    value = self._inspect(receipt)
    metadata = value.get("metadata", {}) if value else {}
    status = value.get("status", {}) if value else {}
    replicas = value.get("spec", {}).get("replicas", 1) if value else 0
    uid = metadata.get("uid", receipt.get("deploymentUid"))
    pods, foreign = self._children(uid)
    generation = metadata.get("generation", 0)
    observed = status.get("observedGeneration", -1) >= generation
    ready = bool(value and replicas > 0 and observed and not foreign and not metadata.get("deletionTimestamp")
      and status.get("updatedReplicas", 0) == replicas and status.get("readyReplicas", 0) == replicas
      and status.get("availableReplicas", 0) == replicas and status.get("replicas", 0) == replicas
      and len(pods) == replicas and all(not pod.get("metadata", {}).get("deletionTimestamp") for pod in pods))
    return {"kind": self.runtime_profile, "identity": self.identity, "target": self.namespace + "/" + self.native_name,
      "kubernetesIdentity": identity, "nativeId": uid, "exists": value is not None, "ready": ready,
      "generation": generation, "observedGeneration": status.get("observedGeneration"), "replicas": replicas,
      "remainingPods": len(pods), "foreignChildren": foreign,
      "state": "active" if replicas else "inactive", "job": "deleting" if metadata.get("deletionTimestamp") else "",
      "invocationId": str(uid) + ":" + str(generation) if ready else "", "observedAt": time.time(),
      "publishedConfigGeneration": receipt.get("publishedConfigGeneration"),
      "runningConfigGeneration": receipt.get("runningConfigGeneration")}

  def _template(self, configs, generation):
    command = self.resources.get("command", {})
    def resolve(value):
      if not isinstance(value, str) and (not isinstance(value, dict) or set(value) != {"configRef"}):
        raise HostError("CAPABILITY_UNSUPPORTED", "Kubernetes arguments accept only literals or scalar configuration references")
      result = self._resolve(value, configs, generation)
      if any(char in result for char in ("\0", "\n", "\r")):
        raise HostError("SCHEMA_INVALID", "Kubernetes environment and arguments must be single-line text")
      return result
    limits = self.resources.get("limits", {})
    for key, low, high, default in (("memoryMiB", 64, 65536, 512), ("cpus", 1, 64, 1)):
      if type(limits.get(key, default)) is not int or not low <= limits.get(key, default) <= high:
        raise HostError("SCHEMA_INVALID", "Kubernetes resource limit is invalid")
    if set(limits) - {"memoryMiB", "cpus"}:
      raise HostError("CAPABILITY_UNSUPPORTED", "Kubernetes PID limits belong to node policy")
    health = self._probe_config(configs)
    probe = {"timeoutSeconds": min(30, health["timeoutSeconds"]), "periodSeconds": 5}
    if health["kind"] == "http":
      if not health["path"].startswith("/") or any(char in health["path"] for char in ("\n", "\r", "\0")):
        raise HostError("SCHEMA_INVALID", "Kubernetes readiness path is invalid")
      probe["httpGet"] = {"port": health["port"], "path": health["path"]}
    else:
      probe["tcpSocket"] = {"port": health["port"]}
    environment = []
    for name, value in command.get("environment", {}).items():
      if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise HostError("SCHEMA_INVALID", "Kubernetes environment name is invalid")
      environment.append({"name": name, "value": resolve(value)})
    container = {"name": "software", "image": self.resources["image"], "imagePullPolicy": "IfNotPresent",
      "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
      "resources": {"limits": {"memory": str(limits.get("memoryMiB", 512)) + "Mi", "cpu": str(limits.get("cpus", 1))}},
      "readinessProbe": probe, "env": environment, "args": [resolve(value) for value in command.get("arguments", [])]}
    if command.get("program"):
      if not command["program"].startswith("/"):
        raise HostError("SCHEMA_INVALID", "Kubernetes entrypoint must be absolute")
      container["command"] = [command["program"]]
    return {"metadata": {"labels": {"ambari-mpack-target": self.native_name},
      "annotations": {"ambari.apache.org/config-generation": generation}},
      "spec": {"automountServiceAccountToken": False, "terminationGracePeriodSeconds": 30,
        "securityContext": {"runAsNonRoot": True, "runAsUser": self.resources["runAsUserId"],
                            "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [container]}}

  def _observation_stamp(self, observation):
    return {field: observation.get(field) for field in
            ("kubernetesIdentity", "nativeId", "exists", "generation", "replicas", "job")}

  def _check_ports(self, configs, observation, receipt):
    # Pod ports do not reserve listeners on the Agent host.
    pass

  def _publish(self, configs, generation, receipt):
    if (self.task_binding or {}).get("secretGenerations"):
      raise HostError("CAPABILITY_UNSUPPORTED", "Kubernetes live-secret delivery is not declared")
    identity = self._namespace()
    template = self._template(configs, generation)
    current = self._inspect(receipt)
    if current is not None:
      current_generation = current["spec"]["template"].get("metadata", {}).get("annotations", {}).get("ambari.apache.org/config-generation")
      if current_generation != generation:
        if current["spec"].get("replicas", 1) != 0:
          raise HostError("CAPABILITY_UNSUPPORTED", "Stop the Kubernetes workload before publishing changed configuration")
        self.verify("stop", configs)
        updated = copy.deepcopy(current)
        updated["spec"]["template"] = template
        updated.pop("status", None)
        self.connection.request("PUT", self.path, updated)
    else:
      if receipt.get("deploymentUid") and not receipt.get("workloadRemoved"):
        raise HostError("TARGET_CONFLICT", "Confirmed Deployment disappeared; uninstall before recreating it")
      intent = receipt["intentDigest"] if receipt.get("workloadRemoved") else receipt.get("creationIntent") or receipt["intentDigest"]
      receipt.update(kubernetesIdentity=identity, creationIntent=intent, deploymentUid=None, workloadRemoved=False)
      self._save(receipt)
      value = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": self.native_name,
        "namespace": self.namespace, "labels": {"ambari-mpack-target": self.native_name},
        "annotations": {"ambari.apache.org/intent": intent, "ambari.apache.org/package": self.package_digest}},
        "spec": {"replicas": 0, "revisionHistoryLimit": 2, "progressDeadlineSeconds": 120,
          "selector": {"matchLabels": {"ambari-mpack-target": self.native_name}}, "template": template}}
      self.connection.request("POST", self.collection, value)
    current = self._inspect(receipt)
    if current is None:
      raise HostError("OUTCOME_UNKNOWN", "Published Deployment cannot be observed", "UNKNOWN")
    if current["spec"]["template"]["metadata"].get("annotations", {}).get("ambari.apache.org/config-generation") != generation:
      raise HostError("OUTCOME_UNKNOWN", "Published pod configuration generation is not confirmed", "UNKNOWN")
    if not self._contains(current["spec"]["template"], template):
      raise HostError("TARGET_CONFLICT", "Deployment pod template differs from the declared configuration")
    receipt.update(deploymentUid=current["metadata"]["uid"], publishedConfigGeneration=generation)
    self._save(receipt)

  @staticmethod
  def _contains(actual, expected):
    # API defaulted fields are allowed; declared fields and list members must agree.
    if isinstance(expected, dict):
      return isinstance(actual, dict) and all(key in actual and KubernetesDeployment._contains(actual[key], value)
                                             for key, value in expected.items())
    if isinstance(expected, list):
      return isinstance(actual, list) and len(actual) == len(expected) and all(
        KubernetesDeployment._contains(left, right) for left, right in zip(actual, expected))
    return actual == expected

  def _native(self, action):
    self._namespace()
    receipt = self._receipt()
    current = self._inspect(receipt)
    if current is None:
      if action == "stop":
        return
      raise HostError("TARGET_CONFLICT", "Bound Deployment is unavailable")
    if action not in ("start", "stop"):
      raise HostError("CAPABILITY_UNSUPPORTED", "Kubernetes action is unsupported")
    replicas = self.resources.get("replicas", 1) if action == "start" else 0
    if current["spec"].get("replicas", 1) != replicas:
      current["spec"]["replicas"] = replicas
      current.pop("status", None)
      self.connection.request("PUT", self.path, current)

  def _uninstall(self, configs, receipt):
    self._namespace()
    current = self._inspect(receipt)
    if current is not None and not current["metadata"].get("deletionTimestamp"):
      metadata = current["metadata"]
      self.connection.request("DELETE", self.path, {"apiVersion": "v1", "kind": "DeleteOptions",
        "propagationPolicy": "Foreground", "preconditions": {"uid": metadata["uid"], "resourceVersion": metadata["resourceVersion"]}})
    self.verify("uninstall", configs)
    receipt["workloadRemoved"] = True
    receipt["retainedResources"] = self._retained_resources()
    self._save(receipt)

  def _healthy(self, configs=None, generation=None):
    return self.observe()["ready"]

  def verify(self, action, configs):
    deadline = time.monotonic() + 120
    while True:
      observation = self.observe()
      if action in ("uninstall", "purge") and not observation["exists"] and not observation["remainingPods"]:
        return observation
      if action == "stop" and observation["replicas"] == 0 and not observation["remainingPods"] and not observation["job"]:
        if not observation["exists"] or (observation["observedGeneration"] or 0) >= observation["generation"]:
          return observation
      if action in ("install", "configure") and observation["exists"] and not observation["job"]:
        return observation
      if action == "start" and observation["ready"]:
        return observation
      if time.monotonic() >= deadline or self.cancel is not None and self.cancel.is_set():
        raise HostError("OUTCOME_UNKNOWN", "Kubernetes postcondition is not established", "UNKNOWN")
      time.sleep(0.5)
