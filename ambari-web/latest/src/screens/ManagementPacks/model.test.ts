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
  normalizeRecommendedBundle,
  normalizeRegistries,
  normalizeRegisteredMpacks,
  normalizeValidationResults,
  redactUri,
} from "./model";

describe("management pack response normalization", () => {
  it("normalizes nested registry catalog resources", () => {
    const registries = normalizeRegistries({
      items: [{
        RegistryInfo: { registry_id: 4, registry_name: "catalog", registry_type: "JSON" },
        mpacks: [{
          RegistryMpackInfo: { mpack_name: "analytics", mpack_display_name: "Analytics" },
          versions: [{
            RegistryMpackVersionInfo: {
              mpack_name: "analytics",
              mpack_version: "2.0",
              mpack_dependencies: [{ name: "base", min_version: "1.0" }],
            },
          }],
        }],
      }],
    });

    expect(registries[0].versions[0]).toMatchObject({
      registryId: 4,
      name: "analytics",
      version: "2.0",
      dependencies: [{ name: "base", minVersion: "1.0" }],
    });
  });

  it("drops malformed registered mpack rows and preserves optional registry ids", () => {
    expect(normalizeRegisteredMpacks({
      items: [
        { MpackInfo: { id: 7, mpack_name: "analytics", mpack_version: "2.0" } },
        { MpackInfo: {} },
      ],
    })).toEqual([expect.objectContaining({ id: 7, registryId: undefined })]);
  });

  it("keeps publisher identity, package version and repository selection distinct", () => {
    expect(normalizeRegisteredMpacks({ items: [{ MpackInfo: { id: 7, publisher: "team",
      package_name: "http", mpack_name: "publisher-4-team-http", mpack_version: "2",
      repository_version_id: 51, stack_name: "MPACK_hash", signature_algorithm: "Ed25519",
      software_versions: { "HTTP/SERVER": "1.0" } } }] })[0]).toMatchObject({
      publisher: "team", packageName: "http", version: "2", repositoryVersionId: 51,
      stackName: "MPACK_hash", signatureAlgorithm: "Ed25519", softwareVersions: { "HTTP/SERVER": "1.0" },
    });
  });

  it("reads validation and recommendation resource properties", () => {
    expect(normalizeValidationResults({
      resources: [{ results: [{ level: "FATAL", message: "incompatible" }] }],
    })).toEqual([{ type: "", level: "FATAL", message: "incompatible" }]);
    expect(normalizeRecommendedBundle({
      resources: [{ recommendations: { mpack_bundles: [{
        mpacks: [{ mpack_name: "analytics", mpack_version: "2.0" }],
      }] } }],
    })).toEqual({ alternatives: 1, mpacks: [{ name: "analytics", version: "2.0" }] });
  });

  it("redacts credentials and query material from displayed registry URIs", () => {
    expect(redactUri("https://user:secret@example.test/catalog.json?token=hidden#fragment"))
      .toBe("https://example.test/catalog.json");
  });
});

