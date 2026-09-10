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

import { ambariApi } from "../../api/config/axiosConfig";

export type PackageComponent = { name: string; category: string; cardinality: string };
export type PackageConfigField = {
  type: string; description: string; secretReference: boolean; emptyValid: boolean;
  minimum?: number; maximum?: number; entries: Array<{ value: string; label: string }>;
};
export type PackageService = {
  name: string;
  components: PackageComponent[];
  defaults: Record<string, Record<string, string>>;
  fields?: Record<string, Record<string, PackageConfigField>>;
};
export type ManagedResource = {
  targetKey: string; serviceName: string; hostName: string; componentName: string;
  packageId: number; taskId: number; state: string; evidence?: unknown;
  targetIncarnation: string; currentServiceTarget: boolean; operation: string;
  materializedPackageId?: number | null;
  selectedPackageId?: number | null;
  category?: string;
  customCommands?: string[];
};

type Json = Record<string, unknown>;
const object = (value: unknown): Json => value && typeof value === "object" ? value as Json : {};
const rows = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
const path = (value: string) => encodeURIComponent(value);

export function packageServices(data: unknown): PackageService[] {
  return rows(object(data).items).map((item) => {
    const service = object(item);
    const defaults: PackageService["defaults"] = {};
    const fields: NonNullable<PackageService["fields"]> = {};
    for (const entry of rows(service.configurations)) {
      const property = object(object(entry).StackConfigurations);
      const type = String(property.type || "").replace(/\.xml$/, "");
      const name = String(property.property_name || "");
      if (type && name) {
        (defaults[type] ||= {})[name] = String(property.property_value ?? "");
        const attributes = object(property.property_value_attributes);
        const numeric = (value: unknown) => value !== undefined && value !== null && value !== "" && Number.isFinite(Number(value)) ? Number(value) : undefined;
        (fields[type] ||= {})[name] = {
          type: String(attributes.type || "string"), description: String(property.property_description || ""),
          secretReference: rows(property.property_type).includes("SECRET_REFERENCE"),
          emptyValid: attributes.empty_value_valid !== false && attributes.empty_value_valid !== "false",
          minimum: numeric(attributes.minimum), maximum: numeric(attributes.maximum),
          entries: rows(attributes.entries).map((entry) => ({value: String(object(entry).value ?? ""),
            label: String(object(entry).label ?? object(entry).value ?? "")})),
        };
      }
    }
    return {
      name: String(object(service.StackServices).service_name || ""), defaults, fields,
      components: rows(service.components).map((entry) => {
        const component = object(object(entry).StackServiceComponents);
        return { name: String(component.component_name || ""), category: String(component.component_category || ""),
          cardinality: String(component.cardinality || "1") };
      }).filter((component) => component.name),
    };
  }).filter((service) => service.name);
}

async function existing(url: string): Promise<Json | undefined> {
  try { return object((await ambariApi.get(url)).data); }
  catch (error) {
    if (object(object(error).response).status === 404) return undefined;
    throw error;
  }
}

export function managedActions(resource: ManagedResource): Set<string> {
  const actions = new Set<string>();
  if (!resource.currentServiceTarget) return actions;
  const supports = (command: string) => resource.customCommands?.includes(command);
  if (["UNINSTALLED_RETAINED", "PURGED", "DETACHED"].includes(resource.state)) actions.add("remove");
  if (resource.state === "PURGED") return actions;
  if (resource.state === "PENDING" && ["PURGE", "DETACH", "ADOPT"].includes(resource.operation || "")) {
    if (supports(resource.operation!)) actions.add(resource.operation!.toLowerCase());
    return actions;
  }
  if (resource.state === "DETACHED") {
    if (supports("ADOPT")) actions.add("adopt");
    return actions;
  }
  if (resource.category === "MASTER" || resource.category === "SLAVE") {
    actions.add("start"); actions.add("stop");
    if (resource.state === "MANAGED" || resource.operation === "UPGRADE") actions.add("upgrade");
  }
  if (supports("UNINSTALL")) actions.add("uninstall");
  if (supports("PURGE") && resource.state === "UNINSTALLED_RETAINED") actions.add("purge");
  if (supports("DETACH") && resource.state === "MANAGED") actions.add("detach");
  return actions;
}

export const PackageLifecycle = {
  async definitions(stack: string, version: string) {
    const response = await ambariApi.get(`/stacks/${path(stack)}/versions/${path(version)}/services`, {
      params: { fields: "StackServices/*,components/StackServiceComponents/*,configurations/StackConfigurations/*" },
    });
    return packageServices(response.data);
  },
  async hosts(cluster: string): Promise<string[]> {
    const response = await ambariApi.get(`/clusters/${path(cluster)}/hosts`, { params: { fields: "Hosts/host_name" } });
    return rows(object(response.data).items).map((host) => String(object(object(host).Hosts).host_name || "")).filter(Boolean);
  },
  async installed(cluster: string): Promise<Json[]> {
    const response = await ambariApi.get(`/clusters/${path(cluster)}/services`, {
      params: { fields: "ServiceInfo/*,components/ServiceComponentInfo/*" },
    });
    return rows(object(response.data).items).map(object);
  },
  async resources(cluster: string, after = ""): Promise<ManagedResource[]> {
    const response = await ambariApi.get(`/clusters/${path(cluster)}/mpack_resources`, { params: { after } });
    return rows(object(response.data).items) as ManagedResource[];
  },
  async install(cluster: string, repository: number, service: PackageService,
    assignments: Record<string, string[]>, configurations: PackageService["defaults"]) {
    const root = `/clusters/${path(cluster)}`;
    const serviceUrl = `${root}/services/${path(service.name)}`;
    const current = await existing(serviceUrl);
    if (current && Number(object(current.ServiceInfo).desired_repository_version_id) !== repository) {
      throw new Error("This service already uses another package version. Refresh the selection before continuing.");
    }
    if (current && object(current.ServiceInfo).state === "STARTED") {
      throw new Error("This service is already running. Use its component and configuration pages to make changes.");
    }
    if (!current) await ambariApi.post(`${root}/services`, { ServiceInfo: {
      service_name: service.name, desired_repository_version_id: repository,
    } });
    for (const component of service.components) {
      const componentUrl = `${serviceUrl}/components/${path(component.name)}`;
      if (!await existing(componentUrl)) await ambariApi.post(componentUrl, { ServiceComponentInfo: { component_name: component.name } });
      for (const host of assignments[component.name] || []) {
        const hostUrl = `${root}/hosts/${path(host)}/host_components/${path(component.name)}`;
        if (!await existing(hostUrl)) await ambariApi.post(hostUrl, { HostRoles: { component_name: component.name, host_name: host } });
      }
    }
    // Preserve a resumed deployment's published config; edits use the existing config workflow.
    const clusterResponse = await ambariApi.get(root, { params: { fields: "Clusters/desired_configs" } });
    const desired = object(object(object(clusterResponse.data).Clusters).desired_configs);
    const missing = Object.entries(configurations).filter(([type]) => !desired[type]).map(([type, properties]) => ({
      type, properties, tag: `mpack-${repository}-${Date.now()}`,
    }));
    if (missing.length) await ambariApi.put(root, { Clusters: { desired_config: missing } });
    return this.state(cluster, service.name, "INSTALLED");
  },
  async state(cluster: string, service: string, state: "INSTALLED" | "STARTED") {
    return (await ambariApi.put(`/clusters/${path(cluster)}/services/${path(service)}`, {
      RequestInfo: { context: `${state === "STARTED" ? "Start" : "Install or stop"} ${service}` },
      Body: { ServiceInfo: { state } },
    })).data;
  },
  async uninstall(cluster: string, service: string) {
    return this.retainedAction(cluster, service, "UNINSTALL");
  },
  async purge(cluster: string, service: string, incarnation: string) {
    return this.retainedAction(cluster, service, "PURGE", incarnation);
  },
  async handoff(cluster: string, service: string, command: "DETACH" | "ADOPT", incarnation: string) {
    return this.retainedAction(cluster, service, command, incarnation);
  },
  async changeRelease(cluster: string, service: string, repository: number, digest: string, incarnation: string, restoreSelection: boolean) {
    if (!/^[a-f0-9]{64}$/.test(digest) || !Number.isSafeInteger(repository) || repository <= 0
      || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(incarnation)) {
      throw new Error("A verified package and target are required.");
    }
    const url = `/clusters/${path(cluster)}/services/${path(service)}`;
    const current = await existing(url);
    if (!current || object(current.ServiceInfo).state !== "INSTALLED") throw new Error("Stop and verify the service before selecting a release.");
    if (Number(object(current.ServiceInfo).desired_repository_version_id) !== repository) {
      await ambariApi.put(url, {RequestInfo: {context: `Select package release for ${service}`, parameters: {expected_target_incarnation: incarnation}},
        ServiceInfo: {desired_repository_version_id: repository}});
    }
    if (restoreSelection) return {selectionRestored: true};
    return this.retainedAction(cluster, service, "UPGRADE", incarnation, digest);
  },
  async retainedAction(cluster: string, service: string, command: "UNINSTALL" | "PURGE" | "UPGRADE" | "DETACH" | "ADOPT", incarnation?: string, digest?: string) {
    if (command === "UPGRADE" && !/^[a-f0-9]{64}$/.test(digest || "")) {
      throw new Error("Artifact update requires a verified package digest.");
    }
    if (command !== "UNINSTALL" && !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(incarnation || "")) {
      throw new Error("Resource mutation requires the target incarnation from resource evidence.");
    }
    const current = await existing(`/clusters/${path(cluster)}/services/${path(service)}`);
    if (!current || object(current.ServiceInfo).state === "STARTED") {
      throw new Error("Stop the service and wait for its request to complete before changing resources.");
    }
    const response = await ambariApi.get(`/clusters/${path(cluster)}/services/${path(service)}/components`);
    const filters = rows(object(response.data).items).map((item) => ({ service_name: service,
      component_name: String(object(object(item).ServiceComponentInfo).component_name || "") })).filter((item) => item.component_name);
    if (!filters.length) throw new Error("No assigned components are available for the resource operation.");
    return (await ambariApi.post(`/clusters/${path(cluster)}/requests`, {
      RequestInfo: { command, context: command === "PURGE" ? `Purge retained data for ${service}` : command === "UPGRADE" ? `Update compatible artifacts for ${service}` : command === "DETACH" ? `Hand off ${service}; retain resources` : command === "ADOPT" ? `Reclaim verified ${service} resources` : `Uninstall ${service}; retain data`,
        ...(command !== "UNINSTALL" ? {parameters: {expected_target_incarnation: incarnation,
          ...(command === "UPGRADE" ? {expected_package_digest: digest} : {})}} : {}),
        operation_level: { level: "SERVICE", cluster_name: cluster, service_name: service } },
      Requests: { resource_filters: filters },
    })).data;
  },
  async removeService(cluster: string, service: string) {
    return (await ambariApi.delete(`/clusters/${path(cluster)}/services/${path(service)}`)).data;
  },
};
