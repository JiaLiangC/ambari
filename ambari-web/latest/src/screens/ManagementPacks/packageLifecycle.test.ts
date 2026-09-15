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
  it("validates then submits one server-owned installation plan", async () => {
    const planId = "00000000-0000-4000-8000-000000000001";
    const assignments = {HTTP_ECHO_SERVER: ["host.example"]};
    await PackageLifecycle.install("existing cluster", 43, service, assignments, service.defaults, planId);
    const url = `/clusters/existing%20cluster/mpack_install_plans/${planId}`;
    expect(api.post).toHaveBeenNthCalledWith(1, url, {MpackInstallPlan: {
      repositoryVersionId: 43, serviceName: "HTTP_ECHO", assignments,
      configurations: service.defaults, validateOnly: true,
    }});
    expect(api.post).toHaveBeenNthCalledWith(2, url, {MpackInstallPlan: {
      repositoryVersionId: 43, serviceName: "HTTP_ECHO", assignments,
      configurations: service.defaults, validateOnly: false,
    }});
    expect(api.get).not.toHaveBeenCalled();
    expect(api.put).not.toHaveBeenCalled();
  });
  it("does not execute a plan when validation fails and requires a stable UUID", async () => {
    api.post.mockRejectedValueOnce(new Error("conflict"));
    await expect(PackageLifecycle.install("cluster", 43, service, {}, service.defaults,
      "00000000-0000-4000-8000-000000000001")).rejects.toThrow("conflict");
    expect(api.post).toHaveBeenCalledTimes(1);
    await expect(PackageLifecycle.install("cluster", 43, service, {}, service.defaults, "retry-1"))
      .rejects.toThrow("plan ID");
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
  it("exposes only core lifecycle actions and resumes the matching destructive operation", () => {
    const resource = {currentServiceTarget: true, category: "MASTER", state: "MANAGED",
      customCommands: ["START", "STOP", "UNINSTALL", "PURGE"]} as ManagedResource;
    expect([...managedActions(resource)]).toEqual(["start", "stop", "uninstall"]);
    expect([...managedActions({...resource, state: "PENDING", operation: "START"})]).toEqual(["stop"]);
    expect([...managedActions({...resource, state: "PENDING", operation: "UNINSTALL"})]).toEqual(["uninstall"]);
    expect([...managedActions({...resource, state: "UNINSTALLED_RETAINED"})]).toEqual(["remove", "purge"]);
    expect([...managedActions({...resource, state: "PENDING", operation: "PURGE"})]).toEqual(["purge"]);
    expect(managedActions({...resource, category: "CLIENT", state: "UNREGISTERED"}).has("remove")).toBe(true);
    expect([...managedActions({...resource, currentServiceTarget: false})]).toEqual([]);
  });
  it("uploads original file bytes without embedding them in a JSON request", async () => {
    api.request.mockResolvedValue({ data: { resources: [] } });
    const file = new File(["deployable fixture"], "release.mpack");
    await MpackApi.uploadPackage(file);
    expect(api.request).toHaveBeenCalledWith(expect.objectContaining({ url: "/mpacks/imports", data: file,
      headers: { "Content-Type": "application/octet-stream" } }));
  });
});
