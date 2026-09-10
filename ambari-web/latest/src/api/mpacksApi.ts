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

import { ambariApi } from "./config/axiosConfig";

export type MpackSelection = {
  mpack_name: string;
  mpack_version: string;
};

export type RegistryDefinition = {
  name: string;
  type: "JSON";
  uri: string;
};

const MpackApi = {
  getRegistries: async () => {
    const response = await ambariApi.request({
      url: "/registries",
      method: "GET",
      params: {
        fields: [
          "RegistryInfo/*",
          "mpacks/RegistryMpackInfo/*",
          "mpacks/versions/RegistryMpackVersionInfo/*",
          "scenarios/RegistryScenarioInfo/*",
        ].join(","),
      },
    });
    return response.data;
  },

  getRegisteredMpacks: async () => {
    const response = await ambariApi.request({
      url: "/mpacks",
      method: "GET",
      params: { fields: "MpackInfo/*" },
    });
    return response.data;
  },

  createRegistry: async (registry: RegistryDefinition) => {
    const response = await ambariApi.request({
      url: "/registries",
      method: "POST",
      data: {
        RegistryInfo: {
          registry_name: registry.name,
          registry_type: registry.type,
          registry_uri: registry.uri,
        },
      },
    });
    return response.data;
  },

  updateRegistry: async (registryId: number, registry: RegistryDefinition) => {
    const response = await ambariApi.request({
      url: `/registries/${registryId}`,
      method: "PUT",
      data: {
        RegistryInfo: {
          registry_name: registry.name,
          registry_type: registry.type,
          registry_uri: registry.uri,
        },
      },
    });
    return response.data;
  },

  deleteRegistry: async (registryId: number) => {
    const response = await ambariApi.request({
      url: `/registries/${registryId}`,
      method: "DELETE",
    });
    return response.data;
  },

  recommendScenario: async (registryId: number, scenarioName: string) => {
    const response = await ambariApi.request({
      url: `/registries/${registryId}/recommendations`,
      method: "POST",
      data: {
        recommend: "scenario-mpacks",
        selected_scenarios: [{ scenario_name: scenarioName }],
      },
    });
    return response.data;
  },

  validateSelection: async (
    registryId: number,
    selectedMpacks: MpackSelection[],
  ) => {
    const response = await ambariApi.request({
      url: `/registries/${registryId}/validations`,
      method: "POST",
      data: {
        validate: "upgrade-mpacks",
        selected_mpacks: selectedMpacks,
      },
    });
    return response.data;
  },

  registerFromRegistry: async (
    registryId: number,
    mpackName: string,
    mpackVersion: string,
  ) => {
    const response = await ambariApi.request({
      url: "/mpacks",
      method: "POST",
      data: {
        Body: {
          MpackInfo: {
            registry_id: registryId,
            mpack_name: mpackName,
            mpack_version: mpackVersion,
          },
        },
      },
    });
    return response.data;
  },

  registerFromUri: async (uri: string) => {
    const response = await ambariApi.request({
      url: "/mpacks",
      method: "POST",
      data: {
        Body: {
          MpackInfo: { mpack_uri: uri },
        },
      },
    });
    return response.data;
  },

  deleteMpack: async (mpackId: number) => {
    const response = await ambariApi.request({
      url: `/mpacks/${mpackId}`,
      method: "DELETE",
    });
    return response.data;
  },

  getOperatingSystems: async (mpackId: number) => {
    const response = await ambariApi.request({
      url: `/mpacks/${mpackId}/operating_systems`,
      method: "GET",
      params: { fields: "MpackOperatingSystems/*" },
    });
    return response.data;
  },
};

export default MpackApi;
