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

export type RuntimePlanRequest = {
  capability: string;
  desired?: Record<string, unknown>;
  expectedGeneration?: number;
  idempotencyKey?: string;
};

export type RuntimeOperationRequest = RuntimePlanRequest & {
  plan?: unknown;
};

const runtimePath = (mpackId: number, suffix = "") => `/mpacks/${mpackId}/runtime${suffix}`;

const MpackRuntimeApi = {
  getSchema: async (mpackId: number) => {
    const response = await ambariApi.request({
      url: runtimePath(mpackId, "/schema"),
      method: "GET",
    });
    return response.data;
  },

  getCapabilities: async (mpackId: number) => {
    const response = await ambariApi.request({
      url: runtimePath(mpackId, "/capabilities"),
      method: "GET",
    });
    return response.data;
  },

  getObservations: async (mpackId: number) => {
    const response = await ambariApi.request({
      url: runtimePath(mpackId, "/observations"),
      method: "GET",
    });
    return response.data;
  },

  getOperations: async (mpackId: number) => {
    const response = await ambariApi.request({
      url: runtimePath(mpackId, "/operations"),
      method: "GET",
    });
    return response.data;
  },

  plan: async (mpackId: number, request: RuntimePlanRequest) => {
    const response = await ambariApi.request({
      url: runtimePath(mpackId, "/plans"),
      method: "POST",
      data: request,
    });
    return response.data;
  },

  createOperation: async (mpackId: number, request: RuntimeOperationRequest) => {
    const response = await ambariApi.request({
      url: runtimePath(mpackId, "/operations"),
      method: "POST",
      data: request,
    });
    return response.data;
  },

  cancelOperation: async (mpackId: number, operationId: string) => {
    const response = await ambariApi.request({
      url: runtimePath(mpackId, `/operations/${encodeURIComponent(operationId)}/cancel`),
      method: "POST",
    });
    return response.data;
  },

  recoverOperation: async (mpackId: number, operationId: string, action: string) => {
    const response = await ambariApi.request({
      url: runtimePath(mpackId, `/operations/${encodeURIComponent(operationId)}/recover`),
      method: "POST",
      data: { action },
    });
    return response.data;
  },
};

export default MpackRuntimeApi;
