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

export type RegistryScenario = {
  name: string;
  description: string;
  mpacks: string[];
};

export type MpackDependency = {
  name: string;
  minVersion?: string;
  maxVersion?: string;
};

export type MpackModule = {
  name: string;
  displayName: string;
  version: string;
  category: string;
};

export type CatalogMpackVersion = {
  registryId: number;
  registryName: string;
  mpackId: string;
  name: string;
  displayName: string;
  description: string;
  version: string;
  dependencies: MpackDependency[];
  modules: MpackModule[];
};

export type RegistryCatalog = {
  id: number;
  name: string;
  type: string;
  versions: CatalogMpackVersion[];
  scenarios: RegistryScenario[];
};

export type RegisteredMpack = {
  prerequisites?: Record<string, unknown>;
  stackName?: string;
  publisher?: string;
  packageName?: string;
  digest?: string;
  signatureAlgorithm?: string;
  signatureKeyId?: string;
  repositoryVersionId?: number;
  compatibility?: Record<string, unknown>;
  softwareVersions?: Record<string, unknown>;
  id: number;
  registryId?: number;
  mpackId: string;
  name: string;
  displayName: string;
  description: string;
  version: string;
  modules: MpackModule[];
};

export type ValidationResult = {
  type: string;
  level: string;
  message: string;
};

export type OperatingSystemMetadata = {
  osType: string;
  repositories: Array<{
    id: string;
    name: string;
    baseUrl: string;
  }>;
};

type UnknownRecord = Record<string, unknown>;

function record(value: unknown): UnknownRecord {
  return value !== null && typeof value === "object"
    ? value as UnknownRecord
    : {};
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

function modules(value: unknown): MpackModule[] {
  return array(value).map((item) => {
    const module = record(item);
    return {
      name: string(module.name),
      displayName: string(module.displayName || module.display_name || module.name),
      version: string(module.version),
      category: string(module.category),
    };
  }).filter((module) => module.name);
}

export function normalizeRegistries(response: unknown): RegistryCatalog[] {
  const registries: Array<RegistryCatalog | null> = array(record(response).items).map((registryValue) => {
    const registry = record(registryValue);
    const info = record(registry.RegistryInfo);
    const id = number(info.registry_id);
    const name = string(info.registry_name);
    if (id === undefined || !name) return null;

    const versions = array(registry.mpacks).flatMap((mpackValue) => {
      const mpack = record(mpackValue);
      const mpackInfo = record(mpack.RegistryMpackInfo);
      return array(mpack.versions).map((versionValue) => {
        const versionInfo = record(record(versionValue).RegistryMpackVersionInfo);
        const dependencies: MpackDependency[] = array(versionInfo.mpack_dependencies).map((dependencyValue) => {
          const dependency = record(dependencyValue);
          return {
            name: string(dependency.name),
            minVersion: string(dependency.minVersion || dependency.min_version) || undefined,
            maxVersion: string(dependency.maxVersion || dependency.max_version) || undefined,
          };
        }).filter((dependency) => dependency.name);
        return {
          registryId: id,
          registryName: name,
          mpackId: string(versionInfo.mpack_id || mpackInfo.mpack_id),
          name: string(versionInfo.mpack_name || mpackInfo.mpack_name),
          displayName: string(mpackInfo.mpack_display_name
            || versionInfo.mpack_name
            || mpackInfo.mpack_name),
          description: string(versionInfo.mpack_description
            || mpackInfo.mpack_description),
          version: string(versionInfo.mpack_version),
          dependencies,
          modules: modules(versionInfo.modules),
        };
      }).filter((version) => version.name && version.version);
    });

    const scenarios = array(registry.scenarios).map((scenarioValue) => {
      const scenarioInfo = record(record(scenarioValue).RegistryScenarioInfo);
      return {
        name: string(scenarioInfo.scenario_name),
        description: string(scenarioInfo.scenario_description),
        mpacks: array(scenarioInfo.scenario_mpacks)
          .map((mpack) => string(record(mpack).name))
          .filter(Boolean),
      };
    }).filter((scenario) => scenario.name);

    return {
      id,
      name,
      type: string(info.registry_type),
      versions,
      scenarios,
    };
  });
  return registries.filter((registry): registry is RegistryCatalog => registry !== null)
    .sort((left, right) => left.name.localeCompare(right.name));
}

export function normalizeRegisteredMpacks(response: unknown): RegisteredMpack[] {
  const mpacks: Array<RegisteredMpack | null> = array(record(response).items).map((itemValue) => {
    const info = record(record(itemValue).MpackInfo);
    const id = number(info.id);
    if (id === undefined) return null;
    return {
      id,
      registryId: number(info.registry_id),
      prerequisites: record(info.prerequisites),
      stackName: string(info.stack_name) || undefined,
      publisher: string(info.publisher) || undefined,
      packageName: string(info.package_name) || undefined,
      digest: string(info.content_digest) || undefined,
      signatureAlgorithm: string(info.signature_algorithm) || undefined,
      signatureKeyId: string(info.signature_key_id) || undefined,
      repositoryVersionId: info.repository_version_id == null ? undefined : number(info.repository_version_id),
      compatibility: record(info.compatibility),
      softwareVersions: record(info.software_versions),
      mpackId: string(info.mpack_id),
      name: string(info.mpack_name),
      displayName: string(info.mpack_display_name || info.mpack_name),
      description: string(info.mpack_description),
      version: string(info.mpack_version),
      modules: modules(info.modules),
    };
  });
  return mpacks.filter((mpack): mpack is RegisteredMpack => mpack !== null)
    .sort((left, right) => left.name.localeCompare(right.name)
      || left.version.localeCompare(right.version));
}

export function normalizeValidationResults(response: unknown): ValidationResult[] {
  const resource = record(array(record(response).resources)[0]);
  const nested = record(resource.RegistryValidation);
  return array(resource.results || nested.results).map((value) => {
    const result = record(value);
    return {
      type: string(result.type),
      level: string(result.level),
      message: string(result.message),
    };
  }).filter((result) => result.message);
}

export function normalizeRecommendedBundle(response: unknown): {
  alternatives: number;
  mpacks: Array<{ name: string; version: string }>;
} {
  const resource = record(array(record(response).resources)[0]);
  const nested = record(resource.RegistryRecommendation);
  const recommendations = record(resource.recommendations || nested.recommendations);
  const bundles = array(recommendations.mpack_bundles);
  const first = record(bundles[0]);
  return {
    alternatives: bundles.length,
    mpacks: array(first.mpacks).map((value) => {
      const mpack = record(value);
      return {
        name: string(mpack.mpack_name),
        version: string(mpack.mpack_version),
      };
    }).filter((mpack) => mpack.name && mpack.version),
  };
}

export function normalizeOperatingSystems(response: unknown): OperatingSystemMetadata[] {
  return array(record(response).items).map((itemValue) => {
    const info = record(record(itemValue).MpackOperatingSystems);
    return {
      osType: string(info.os_type),
      repositories: array(info.repositories).map((repositoryValue) => {
        const repository = record(repositoryValue);
        return {
          id: string(repository.repoId || repository.repo_id || repository.id),
          name: string(repository.repoName || repository.repo_name || repository.name),
          baseUrl: string(repository.baseUrl || repository.base_url),
        };
      }),
    };
  }).filter((operatingSystem) => operatingSystem.osType);
}

export function catalogKey(version: CatalogMpackVersion): string {
  return `${version.registryId}\u0000${version.name}\u0000${version.version}`;
}

export function selectionSignature(versions: CatalogMpackVersion[]): string {
  return versions.map(catalogKey).sort().join("\u0001");
}

export function redactUri(value: string): string {
  try {
    const uri = new URL(value);
    uri.username = "";
    uri.password = "";
    uri.search = "";
    uri.hash = "";
    return uri.toString();
  } catch {
    return value ? "Configured" : "";
  }
}
