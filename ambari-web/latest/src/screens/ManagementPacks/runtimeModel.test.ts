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

import { describe, expect, it } from "vitest";
import {
  normalizeCapabilities,
  normalizeObservations,
  normalizeOperations,
  normalizePlan,
  operationStateVariant,
} from "./runtimeModel";

describe("management pack runtime normalization", () => {
  it("normalizes capability availability without treating unsupported as healthy", () => {
    expect(normalizeCapabilities({ capabilities: [
      { name: "start", adapter: "host.systemd/v1", supported: true },
      { name: "delete", state: "UNSUPPORTED", reason: "policy" },
    ] })).toEqual([
      { name: "start", adapter: "host.systemd/v1", supported: true, reason: undefined },
      { name: "delete", adapter: undefined, supported: false, reason: "policy" },
    ]);
  });

  it("marks stale and unknown observations explicitly", () => {
    expect(normalizeObservations({ observations: [
      { kind: "health", name: "ready", state: "HEALTHY", value: "true", timestamp: "2026-09-10T00:00:00Z" },
      { type: "metric", metric: "requests", status: "UNKNOWN" },
    ] })).toEqual([
      expect.objectContaining({ kind: "health", name: "ready", stale: false }),
      expect.objectContaining({ kind: "metric", name: "requests", state: "UNKNOWN", stale: true }),
    ]);
    expect(normalizeObservations({ health: [{ name: "ready", state: "HEALTHY" }], metrics: [{ name: "requests", value: 2 }] }))
      .toEqual([
        expect.objectContaining({ kind: "health", name: "ready" }),
        expect.objectContaining({ kind: "metrics", name: "requests", value: "2" }),
      ]);
  });

  it("normalizes operation recovery actions and plans", () => {
    expect(normalizeOperations({ resources: [{ Operation: {
      operation_id: "op-1",
      capability: "restart",
      status: "UNKNOWN",
      recovery_actions: ["retry", "compensate"],
    } }] })).toEqual([expect.objectContaining({
      id: "op-1",
      state: "UNKNOWN",
      recoveryActions: ["retry", "compensate"],
    })]);
    expect(normalizePlan({ plan: {
      plan_id: "plan-1",
      steps: [{ step_id: "s1", action: "stop", effects: "service stopped" }],
      diagnostics: [{ code: "PLAN_STALE", message: "generation changed" }],
    } })).toEqual({
      id: "plan-1",
      generation: undefined,
      steps: [{ id: "s1", action: "stop", status: undefined, effect: "service stopped" }],
      diagnostics: [{ code: "PLAN_STALE", level: "ERROR", message: "generation changed", path: undefined }],
    });
  });

  it("maps lifecycle states to conservative visual variants", () => {
    expect(operationStateVariant("SUCCEEDED")).toBe("success");
    expect(operationStateVariant("UNKNOWN")).toBe("warning");
    expect(operationStateVariant("FAILED")).toBe("danger");
  });
});
