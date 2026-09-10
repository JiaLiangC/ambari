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

type UnknownRecord = Record<string, unknown>;

function record(value: unknown): UnknownRecord {
  return value !== null && typeof value === "object" ? value as UnknownRecord : {};
}

function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function string(value: unknown): string {
  return value == null ? "" : String(value);
}

function number(value: unknown): number | undefined {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

export type RuntimeCapability = {
  name: string;
  supported: boolean;
  adapter?: string;
  reason?: string;
};

export type RuntimeObservation = {
  kind: string;
  name: string;
  state: string;
  value?: string;
  message?: string;
  observedAt?: string;
  stale: boolean;
};

export type RuntimeOperation = {
  id: string;
  capability: string;
  state: string;
  generation?: number;
  startedAt?: string;
  updatedAt?: string;
  message?: string;
  recoveryActions: string[];
};

export type RuntimePlan = {
  id?: string;
  generation?: number;
  steps: Array<{ id: string; action: string; status?: string; effect?: string }>;
  diagnostics: Array<{ code: string; level: string; message: string; path?: string }>;
};

function resources(value: unknown): UnknownRecord[] {
  const source = record(value);
  const values = array(source.items).length ? array(source.items) : array(source.resources);
  return values.map(record);
}

export function normalizeCapabilities(value: unknown): RuntimeCapability[] {
  const source = record(value);
  const values = array(source.capabilities).length
    ? array(source.capabilities)
    : array(source.effectiveCapabilities).length
      ? array(source.effectiveCapabilities)
      : resources(value);
  return values.map((item) => {
    const capability = record(record(item).Capability || item);
    const supported = capability.supported !== false
      && string(capability.state || capability.status).toUpperCase() !== "UNSUPPORTED";
    return {
      name: string(capability.name || capability.capability || capability.id),
      supported,
      adapter: string(capability.adapter || capability.profile) || undefined,
      reason: string(capability.reason || capability.message) || undefined,
    };
  }).filter((item) => item.name);
}

export function normalizeObservations(value: unknown): RuntimeObservation[] {
  const source = record(value);
  const values = array(source.observations).length
    ? array(source.observations)
    : ["health", "metrics", "logs", "alerts"].flatMap((kind) => (
      array(source[kind]).map((item) => ({ ...record(item), kind }))
    )).concat(resources(value));
  return values.map((item) => {
    const observation = record(record(item).Observation || item);
    const state = string(observation.state || observation.status || "UNKNOWN").toUpperCase();
    return {
      kind: string(observation.kind || observation.type || "health").toLowerCase(),
      name: string(observation.name || observation.metric || observation.id || "observation"),
      state,
      value: observation.value == null ? undefined : string(observation.value),
      message: string(observation.message || observation.detail) || undefined,
      observedAt: string(observation.observedAt || observation.observed_at || observation.timestamp) || undefined,
      stale: Boolean(observation.stale) || state === "STALE" || state === "UNKNOWN",
    };
  });
}

export function normalizeOperations(value: unknown): RuntimeOperation[] {
  const source = record(value);
  const values = array(source.operations).length ? array(source.operations) : resources(value);
  return values.map((item) => {
    const operation = record(record(item).Operation || item);
    const actionValues = array(operation.recoveryActions || operation.recovery_actions);
    return {
      id: string(operation.id || operation.operationId || operation.operation_id),
      capability: string(operation.capability || operation.action),
      state: string(operation.state || operation.status || "UNKNOWN").toUpperCase(),
      generation: number(operation.generation || operation.expectedGeneration),
      startedAt: string(operation.startedAt || operation.started_at) || undefined,
      updatedAt: string(operation.updatedAt || operation.updated_at) || undefined,
      message: string(operation.message || operation.error) || undefined,
      recoveryActions: actionValues.map(string).filter(Boolean),
    };
  }).filter((item) => item.id);
}

export function normalizePlan(value: unknown): RuntimePlan {
  const source = record(value);
  const plan = record(source.plan || record(array(source.resources)[0]).Plan || source);
  const steps = array(plan.steps).map((item, index) => {
    const step = record(item);
    return {
      id: string(step.id || step.stepId || `step-${index + 1}`),
      action: string(step.action || step.capability || step.name),
      status: string(step.status) || undefined,
      effect: string(step.effect || step.effects) || undefined,
    };
  }).filter((step) => step.action);
  const diagnostics = array(plan.diagnostics || source.diagnostics).map((item) => {
    const diagnostic = record(item);
    return {
      code: string(diagnostic.code || diagnostic.type || "UNKNOWN"),
      level: string(diagnostic.level || diagnostic.severity || "ERROR").toUpperCase(),
      message: string(diagnostic.message || diagnostic.detail),
      path: string(diagnostic.path || diagnostic.field) || undefined,
    };
  }).filter((diagnostic) => diagnostic.message);
  return {
    id: string(plan.id || plan.planId) || undefined,
    generation: number(plan.generation || plan.expectedGeneration),
    steps,
    diagnostics,
  };
}

export function operationStateVariant(state: string): "success" | "danger" | "warning" | "secondary" {
  if (["SUCCEEDED", "COMPLETED", "READY"].includes(state)) return "success";
  if (["FAILED", "CANCELLED", "UNSUPPORTED"].includes(state)) return "danger";
  if (["RUNNING", "PENDING", "RETRYING", "UNKNOWN", "STALE"].includes(state)) return "warning";
  return "secondary";
}
