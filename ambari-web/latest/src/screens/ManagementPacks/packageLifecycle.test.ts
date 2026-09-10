/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { managedActions, ManagedResource, PackageLifecycle, packageServices } from "./packageLifecycle";
import MpackApi from "../../api/mpacksApi";

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn(), request: vi.fn() }));
vi.mock("../../api/config/axiosConfig", () => ({ ambariApi: api }));
const service = { name: "HTTP_ECHO", components: [{ name: "HTTP_ECHO_SERVER", category: "SLAVE", cardinality: "1" }],
  defaults: { http: { port: "18080" } } };

describe("package lifecycle integration contracts", () => {
  beforeEach(() => { vi.resetAllMocks(); api.post.mockResolvedValue({ data: {} }); api.put.mockResolvedValue({ data: { Requests: { id: 11 } } }); });
  it("reads arbitrary service definitions and multiple configuration files", () => {
    expect(packageServices({ items: [{ StackServices: { service_name: "MY_HTTP" },
      components: [{ StackServiceComponents: { component_name: "HTTP_WORKER", component_category: "SLAVE", cardinality: "1+" } }],
      configurations: [{ StackConfigurations: { type: "web.xml", property_name: "port", property_value: 8080 } },
        { StackConfigurations: { type: "auth.xml", property_name: "enabled", property_value: false } }],
    }] })[0]).toMatchObject({ name: "MY_HTTP", components: [{ name: "HTTP_WORKER", category: "SLAVE", cardinality: "1+" }],
      defaults: { web: { port: "8080" }, auth: { enabled: "false" } } });
  });
  it("uses the existing Stack configuration projection for typed and scoped-reference fields", () => {
    const definitions = packageServices({items: [{StackServices: {service_name: "HTTP_ECHO"}, configurations: [
      {StackConfigurations: {type: "http.xml", property_name: "port", property_value: 18080,
        property_value_attributes: {type: "int", minimum: "1", maximum: "65535", empty_value_valid: false}}},
      {StackConfigurations: {type: "http.xml", property_name: "mode", property_value: "safe",
        property_value_attributes: {type: "string", entries: [{value: "safe", label: "Safe"}]}}},
      {StackConfigurations: {type: "http.xml", property_name: "credential", property_value: "secret://mpack.HTTP_ECHO.auth",
        property_type: ["SECRET_REFERENCE"], property_value_attributes: {type: "string"}}},
    ]}]});
    expect(definitions[0].fields?.http).toMatchObject({
      port: {type: "int", minimum: 1, maximum: 65535, emptyValid: false},
      mode: {entries: [{value: "safe", label: "Safe"}]},
      credential: {secretReference: true},
    });
  });
  it("refuses to resume a service selected from another package repository", async () => {
    api.get.mockResolvedValue({ data: { ServiceInfo: { desired_repository_version_id: 42 } } });
    await expect(PackageLifecycle.install("existing cluster", 43, service, {}, service.defaults)).rejects.toThrow("another package");
    expect(api.post).not.toHaveBeenCalled(); expect(api.put).not.toHaveBeenCalled();
  });
  it("resumes existing records without recreating hosts or replacing published configs", async () => {
    api.get.mockImplementation(async (url: string) => ({ data: url.endsWith("/services/HTTP_ECHO")
      ? { ServiceInfo: { desired_repository_version_id: 43 } }
      : url === "/clusters/existing%20cluster" ? { Clusters: { desired_configs: { http: { tag: "existing" } } } } : {} }));
    await PackageLifecycle.install("existing cluster", 43, service, { HTTP_ECHO_SERVER: ["host.example"] }, service.defaults);
    expect(api.post).not.toHaveBeenCalled(); expect(api.put).toHaveBeenCalledTimes(1);
    expect(api.put).toHaveBeenCalledWith("/clusters/existing%20cluster/services/HTTP_ECHO", expect.objectContaining({
      Body: { ServiceInfo: { state: "INSTALLED" } },
    }));
  });
  it("does not interpret authorization or network failure as an absent service", async () => {
    api.get.mockRejectedValue({ response: { status: 403 } });
    await expect(PackageLifecycle.install("cluster", 43, service, {}, service.defaults)).rejects.toBeDefined();
    expect(api.post).not.toHaveBeenCalled();
  });
  it("does not turn a repeated install into stopping an already running service", async () => {
    api.get.mockResolvedValue({ data: { ServiceInfo: { desired_repository_version_id: 43, state: "STARTED" } } });
    await expect(PackageLifecycle.install("cluster", 43, service, {}, service.defaults)).rejects.toThrow("already running");
    expect(api.post).not.toHaveBeenCalled(); expect(api.put).not.toHaveBeenCalled();
  });
  it("uses existing request identity for uninstall and encodes cluster/service paths", async () => {
    api.get.mockImplementation(async (url: string) => ({data: url.endsWith("/components")
      ? {items: [{ServiceComponentInfo: {component_name: "HTTP_ECHO_SERVER"}}]}
      : {ServiceInfo: {state: "INSTALLED"}}}));
    await PackageLifecycle.uninstall("cluster one", "HTTP_ECHO");
    expect(api.post).toHaveBeenCalledWith("/clusters/cluster%20one/requests", expect.objectContaining({
      Requests: { resource_filters: [{ service_name: "HTTP_ECHO", component_name: "HTTP_ECHO_SERVER" }] },
      RequestInfo: expect.objectContaining({ command: "UNINSTALL" }),
    }));
  });
  it("requires the existing stop workflow before uninstalling a running service", async () => {
    api.get.mockResolvedValue({data: {ServiceInfo: {state: "STARTED"}}});
    await expect(PackageLifecycle.uninstall("cluster", "HTTP_ECHO")).rejects.toThrow("Stop the service");
    expect(api.post).not.toHaveBeenCalled();
  });
  it("pins purge to the retained incarnation and the assigned component filters", async () => {
    api.get.mockImplementation(async (url: string) => ({data: url.endsWith("/components")
      ? {items: [{ServiceComponentInfo: {component_name: "HTTP_ECHO_SERVER"}}]}
      : {ServiceInfo: {state: "INSTALLED"}}}));
    const incarnation = "00000000-0000-0000-0000-000000000001";
    await PackageLifecycle.purge("cluster", "HTTP_ECHO", incarnation);
    expect(api.post).toHaveBeenCalledWith("/clusters/cluster/requests", expect.objectContaining({
      Requests: { resource_filters: [{ service_name: "HTTP_ECHO", component_name: "HTTP_ECHO_SERVER" }] },
      RequestInfo: expect.objectContaining({command: "PURGE", parameters: {expected_target_incarnation: incarnation}}),
    }));
  });
  it("does not submit purge without a retained target or against a running service", async () => {
    await expect(PackageLifecycle.purge("cluster", "HTTP_ECHO", "")).rejects.toThrow("incarnation");
    expect(api.get).not.toHaveBeenCalled();
    api.get.mockResolvedValue({data: {ServiceInfo: {state: "STARTED"}}});
    await expect(PackageLifecycle.purge("cluster", "HTTP_ECHO", "00000000-0000-0000-0000-000000000001"))
      .rejects.toThrow("Stop the service");
    expect(api.post).not.toHaveBeenCalled();
  });
  it("selects an imported release before submitting an incarnation and digest pinned upgrade", async () => {
    api.get.mockImplementation(async (url: string) => ({data: url.endsWith("/components")
      ? {items: [{ServiceComponentInfo: {component_name: "HTTP_ECHO_SERVER"}}]}
      : {ServiceInfo: {state: "INSTALLED", desired_repository_version_id: 43}}}));
    const incarnation = "00000000-0000-0000-0000-000000000001";
    await PackageLifecycle.changeRelease("cluster", "HTTP_ECHO", 44, "b".repeat(64), incarnation, false);
    expect(api.put).toHaveBeenCalledWith("/clusters/cluster/services/HTTP_ECHO", {
      RequestInfo: {context: "Select package release for HTTP_ECHO", parameters: {expected_target_incarnation: incarnation}},
      ServiceInfo: {desired_repository_version_id: 44},
    });
    expect(api.post).toHaveBeenCalledWith("/clusters/cluster/requests", expect.objectContaining({
      RequestInfo: expect.objectContaining({command: "UPGRADE", parameters: {
        expected_target_incarnation: incarnation, expected_package_digest: "b".repeat(64),
      }}),
    }));
    expect(api.put.mock.invocationCallOrder[0]).toBeLessThan(api.post.mock.invocationCallOrder[0]);
  });
  it("does not submit native work after a failed or lost selection response", async () => {
    api.get.mockResolvedValue({data: {ServiceInfo: {state: "INSTALLED", desired_repository_version_id: 43}}});
    api.put.mockRejectedValue(new Error("Selection response unavailable"));
    await expect(PackageLifecycle.changeRelease("cluster", "HTTP_ECHO", 44, "b".repeat(64),
      "00000000-0000-0000-0000-000000000001", false)).rejects.toThrow("Selection response");
    expect(api.post).not.toHaveBeenCalled();
  });
  it("restores selection without asserting a data rollback or starting the service", async () => {
    api.get.mockResolvedValue({data: {ServiceInfo: {state: "INSTALLED", desired_repository_version_id: 44}}});
    expect(await PackageLifecycle.changeRelease("cluster", "HTTP_ECHO", 43, "a".repeat(64),
      "00000000-0000-0000-0000-000000000001", true)).toEqual({selectionRestored: true});
    expect(api.put).toHaveBeenCalledTimes(1);
    expect(api.post).not.toHaveBeenCalled();
  });
  it("retries native verification when the candidate is already selected", async () => {
    api.get.mockImplementation(async (url: string) => ({data: url.endsWith("/components")
      ? {items: [{ServiceComponentInfo: {component_name: "HTTP_ECHO_SERVER"}}]}
      : {ServiceInfo: {state: "INSTALLED", desired_repository_version_id: 44}}}));
    await PackageLifecycle.changeRelease("cluster", "HTTP_ECHO", 44, "b".repeat(64),
      "00000000-0000-0000-0000-000000000001", false);
    expect(api.put).not.toHaveBeenCalled();
    expect(api.post).toHaveBeenCalledTimes(1);
  });
  it("rejects invalid selection identity before I/O and running services before mutation", async () => {
    await expect(PackageLifecycle.changeRelease("cluster", "HTTP_ECHO", 44, "b".repeat(64), "invalid", false))
      .rejects.toThrow("verified package");
    expect(api.get).not.toHaveBeenCalled();
    api.get.mockResolvedValue({data: {ServiceInfo: {state: "STARTED"}}});
    await expect(PackageLifecycle.changeRelease("cluster", "HTTP_ECHO", 44, "b".repeat(64),
      "00000000-0000-0000-0000-000000000001", false)).rejects.toThrow("Stop and verify");
    expect(api.put).not.toHaveBeenCalled(); expect(api.post).not.toHaveBeenCalled();
  });
  it("limits pending handoff and client actions using server component metadata", () => {
    const resource = {currentServiceTarget: true, category: "MASTER", state: "PENDING", operation: "DETACH",
      customCommands: ["DETACH", "ADOPT", "UNINSTALL", "PURGE"]} as ManagedResource;
    expect([...managedActions(resource)]).toEqual(["detach"]);
    expect([...managedActions({...resource, state: "DETACHED"})]).toEqual(["remove", "adopt"]);
    expect([...managedActions({...resource, currentServiceTarget: false})]).toEqual([]);
    expect([...managedActions({...resource, category: "CLIENT", state: "MANAGED", operation: "INSTALL", customCommands: ["UNINSTALL"]})])
      .toEqual(["uninstall"]);
  });
  it("submits ownership handoff through the same incarnation-pinned custom request", async () => {
    api.get.mockImplementation(async (url: string) => ({data: url.endsWith("/components")
      ? {items: [{ServiceComponentInfo: {component_name: "HTTP_ECHO_SERVER"}}]}
      : {ServiceInfo: {state: "INSTALLED"}}}));
    const incarnation = "00000000-0000-0000-0000-000000000001";
    await PackageLifecycle.handoff("cluster", "HTTP_ECHO", "DETACH", incarnation);
    expect(api.post).toHaveBeenCalledWith("/clusters/cluster/requests", expect.objectContaining({
      RequestInfo: expect.objectContaining({command: "DETACH", parameters: {expected_target_incarnation: incarnation}}),
    }));
  });
  it("uploads original file bytes without embedding them in a JSON request", async () => {
    api.request.mockResolvedValue({ data: { resources: [] } });
    const file = new File(["deployable fixture"], "release.mpack");
    await MpackApi.uploadPackage(file);
    expect(api.request).toHaveBeenCalledWith(expect.objectContaining({ url: "/mpacks/imports", data: file,
      headers: { "Content-Type": "application/octet-stream" } }));
  });
});
