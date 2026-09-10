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
package org.apache.ambari.server.topology;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

/**
 * Exact registered mpack selection carried by a Blueprint. This is package
 * metadata; it does not introduce a second runtime service identity.
 */
public final class MpackReference {

  public static final String SETTING_NAME = "mpack_instances";
  private static final String FIELD_INSTANCE_NAME = "name";
  private static final String FIELD_MPACK_ID = "mpack_id";
  private static final String FIELD_MPACK_NAME = "mpack_name";
  private static final String FIELD_MPACK_TYPE = "type";
  private static final String FIELD_VERSION = "version";
  private static final String FIELD_REGISTRY_ID = "registry_id";
  private static final String FIELD_SERVICES = "services";
  private static final String FIELD_SERVICE_INSTANCES = "service_instances";
  private static final String FIELD_OWNER = "owner";
  private static final String FIELD_STATE = "lifecycle_state";
  private static final String FIELD_GENERATION = "generation";
  private static final String FIELD_RETENTION_UNTIL = "retention_until";
  private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]*");

  private final String instanceName;
  private final Long mpackId;
  private final String mpackName;
  private final String version;
  private final Long registryId;
  private final Map<String, String> services;
  private final String owner;
  private final String lifecycleState;
  private final long generation;
  private final Long retentionUntil;

  public MpackReference(String instanceName, Long mpackId, String mpackName, String version,
      Long registryId, Map<String, String> services) {
    this(instanceName, mpackId, mpackName, version, registryId, services,
        null, MpackLifecycleState.REGISTERED.name(), 0L, null);
  }

  public MpackReference(String instanceName, Long mpackId, String mpackName, String version,
      Long registryId, Map<String, String> services, String owner, String lifecycleState,
      long generation, Long retentionUntil) {
    this.instanceName = requireIdentifier(instanceName, "mpack instance name");
    this.mpackId = mpackId;
    this.mpackName = requireIdentifier(mpackName, "mpack name");
    if (StringUtils.isBlank(version)) {
      throw new IllegalArgumentException("Mpack version is required");
    }
    this.version = version;
    this.registryId = registryId;
    if (StringUtils.isNotBlank(owner)) {
      this.owner = requireIdentifier(owner, "mpack owner");
    } else {
      this.owner = null;
    }
    this.lifecycleState = MpackLifecycleState.parse(lifecycleState).name();
    if (generation < 0) {
      throw new IllegalArgumentException("Mpack lifecycle generation cannot be negative");
    }
    this.generation = generation;
    this.retentionUntil = retentionUntil;

    Map<String, String> serviceCopy = new LinkedHashMap<>();
    services.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> {
      String name = requireIdentifier(entry.getKey(), "service instance name");
      String type = requireIdentifier(entry.getValue(), "service type");
      if (!name.equals(type)) {
        throw new IllegalArgumentException(String.format(
            "Service instance %s cannot alias type %s because runtime service identity is service_name",
            name, type));
      }
      serviceCopy.put(name, type);
    });
    this.services = Collections.unmodifiableMap(serviceCopy);
  }

  public String getInstanceName() {
    return instanceName;
  }

  public Long getMpackId() {
    return mpackId;
  }

  public String getMpackName() {
    return mpackName;
  }

  public String getVersion() {
    return version;
  }

  public Long getRegistryId() {
    return registryId;
  }

  public Map<String, String> getServices() {
    return services;
  }

  public String getOwner() {
    return owner;
  }

  public String getLifecycleState() {
    return lifecycleState;
  }

  public long getGeneration() {
    return generation;
  }

  public Long getRetentionUntil() {
    return retentionUntil;
  }

  public MpackReference resolved(long resolvedMpackId, Long resolvedRegistryId) {
    return new MpackReference(instanceName, resolvedMpackId, mpackName, version,
        resolvedRegistryId, services, owner, lifecycleState, generation, retentionUntil);
  }

  public Map<String, String> toSettingMap() {
    Map<String, String> values = new LinkedHashMap<>();
    values.put(FIELD_INSTANCE_NAME, instanceName);
    values.put(FIELD_MPACK_ID, String.valueOf(mpackId));
    values.put(FIELD_MPACK_NAME, mpackName);
    values.put(FIELD_VERSION, version);
    if (registryId != null) {
      values.put(FIELD_REGISTRY_ID, String.valueOf(registryId));
    }
    values.put(FIELD_SERVICES, encodeServices(services));
    if (owner != null) {
      values.put(FIELD_OWNER, owner);
    }
    if (!isDefaultLifecycle()) {
      values.put(FIELD_STATE, lifecycleState);
      values.put(FIELD_GENERATION, String.valueOf(generation));
      if (retentionUntil != null) {
        values.put(FIELD_RETENTION_UNTIL, String.valueOf(retentionUntil));
      }
    }
    return values;
  }

  public Map<String, Object> toApiMap() {
    Map<String, Object> values = new LinkedHashMap<>();
    values.put(FIELD_INSTANCE_NAME, instanceName);
    values.put(FIELD_MPACK_ID, mpackId);
    values.put(FIELD_MPACK_TYPE, mpackName);
    values.put(FIELD_VERSION, version);
    if (registryId != null) {
      values.put(FIELD_REGISTRY_ID, registryId);
    }
    List<Map<String, String>> serviceInstances = new ArrayList<>();
    services.forEach((name, type) -> serviceInstances.add(
        Map.of("name", name, "type", type)));
    values.put(FIELD_SERVICE_INSTANCES, serviceInstances);
    if (owner != null) {
      values.put(FIELD_OWNER, owner);
    }
    if (!isDefaultLifecycle()) {
      values.put(FIELD_STATE, lifecycleState);
      values.put(FIELD_GENERATION, generation);
      if (retentionUntil != null) {
        values.put(FIELD_RETENTION_UNTIL, retentionUntil);
      }
    }
    return values;
  }

  @SuppressWarnings("unchecked")
  public static MpackReference fromApiMap(Map<String, Object> values) {
    String instanceName = value(values.get(FIELD_INSTANCE_NAME));
    String mpackName = value(values.get(FIELD_MPACK_NAME));
    if (StringUtils.isBlank(mpackName)) {
      mpackName = value(values.get(FIELD_MPACK_TYPE));
    }
    if (StringUtils.isBlank(mpackName)) {
      mpackName = instanceName;
    }
    Map<String, String> services = new LinkedHashMap<>();
    Object rawServices = values.get(FIELD_SERVICE_INSTANCES);
    if (rawServices instanceof Collection) {
      for (Object rawService : (Collection<?>) rawServices) {
        if (!(rawService instanceof Map)) {
          throw new IllegalArgumentException("Mpack service_instances entries must be objects");
        }
        Map<String, Object> service = (Map<String, Object>) rawService;
        String serviceName = value(service.get("name"));
        if (StringUtils.isBlank(serviceName)) {
          throw new IllegalArgumentException("Mpack service instance name is required");
        }
        String serviceType = value(service.get("type"));
        if (StringUtils.isBlank(serviceType)) {
          serviceType = serviceName;
        }
        if (services.putIfAbsent(serviceName, serviceType) != null) {
          throw new IllegalArgumentException("Duplicate service instance " + serviceName);
        }
      }
    }
    return new MpackReference(instanceName, number(values.get(FIELD_MPACK_ID)), mpackName,
        value(values.get(FIELD_VERSION)), number(values.get(FIELD_REGISTRY_ID)), services,
        value(values.get(FIELD_OWNER)), value(values.get(FIELD_STATE)),
        longValue(values.get(FIELD_GENERATION), 0L), number(values.get(FIELD_RETENTION_UNTIL)));
  }

  public static MpackReference fromSettingMap(Map<String, String> values) {
    return new MpackReference(values.get(FIELD_INSTANCE_NAME),
        number(values.get(FIELD_MPACK_ID)), values.get(FIELD_MPACK_NAME),
        values.get(FIELD_VERSION), number(values.get(FIELD_REGISTRY_ID)),
        decodeServices(values.get(FIELD_SERVICES)), values.get(FIELD_OWNER),
        values.get(FIELD_STATE), longValue(values.get(FIELD_GENERATION), 0L),
        number(values.get(FIELD_RETENTION_UNTIL)));
  }

  public static List<MpackReference> fromSetting(Setting setting) {
    if (setting == null) {
      return Collections.emptyList();
    }
    List<MpackReference> result = new ArrayList<>();
    for (Map<String, String> values : setting.getSettingValue(SETTING_NAME)) {
      result.add(fromSettingMap(values));
    }
    result.sort(Comparator.comparing(MpackReference::getInstanceName));
    return Collections.unmodifiableList(result);
  }

  private static String encodeServices(Map<String, String> services) {
    return services.entrySet().stream()
        .map(entry -> entry.getKey() + "=" + entry.getValue())
        .reduce((left, right) -> left + "," + right)
        .orElse("");
  }

  private static Map<String, String> decodeServices(String encoded) {
    Map<String, String> services = new LinkedHashMap<>();
    if (StringUtils.isBlank(encoded)) {
      return services;
    }
    for (String entry : encoded.split(",")) {
      String[] pair = entry.split("=", 2);
      if (pair.length != 2) {
        throw new IllegalArgumentException("Invalid persisted mpack service mapping");
      }
      services.put(pair[0], pair[1]);
    }
    return services;
  }

  private static String value(Object value) {
    return value == null ? null : String.valueOf(value);
  }

  private static Long number(Object value) {
    String text = value(value);
    return StringUtils.isBlank(text) ? null : Long.valueOf(text);
  }

  private static long longValue(Object value, long defaultValue) {
    String text = value(value);
    return StringUtils.isBlank(text) ? defaultValue : Long.parseLong(text);
  }

  private boolean isDefaultLifecycle() {
    return owner == null && MpackLifecycleState.REGISTERED.name().equals(lifecycleState)
        && generation == 0L && retentionUntil == null;
  }

  public MpackReference adopt(String newOwner) {
    return transition(MpackLifecycleState.ADOPTED, newOwner, null);
  }

  public MpackReference detach() {
    return transition(MpackLifecycleState.DETACHED, null, retentionUntil);
  }

  public MpackReference requestDelete(long retainUntil) {
    if (retainUntil < 0) {
      throw new IllegalArgumentException("Retention timestamp cannot be negative");
    }
    return transition(MpackLifecycleState.DELETE_PENDING, owner, retainUntil);
  }

  public MpackReference beginUpgrade(String targetVersion) {
    if (StringUtils.isBlank(targetVersion)) {
      throw new IllegalArgumentException("Upgrade target version is required");
    }
    MpackReference next = transition(MpackLifecycleState.UPGRADE_PENDING, owner, retentionUntil);
    return new MpackReference(instanceName, mpackId, mpackName, targetVersion, registryId,
        services, next.owner, next.lifecycleState, next.generation, next.retentionUntil);
  }

  private MpackReference transition(MpackLifecycleState next, String nextOwner,
      Long nextRetentionUntil) {
    MpackLifecycleState current = MpackLifecycleState.parse(lifecycleState);
    if (!current.canTransitionTo(next)) {
      throw new IllegalStateException("Invalid mpack lifecycle transition " + current + " -> " + next);
    }
    return new MpackReference(instanceName, mpackId, mpackName, version, registryId, services,
        nextOwner, next.name(), generation + 1, nextRetentionUntil);
  }

  private static String requireIdentifier(String value, String label) {
    if (StringUtils.isBlank(value) || !IDENTIFIER.matcher(value).matches()) {
      throw new IllegalArgumentException("Invalid " + label + ": " + value);
    }
    return value;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof MpackReference)) {
      return false;
    }
    MpackReference that = (MpackReference) other;
    return Objects.equals(instanceName, that.instanceName)
        && Objects.equals(mpackId, that.mpackId)
        && Objects.equals(mpackName, that.mpackName)
        && Objects.equals(version, that.version)
        && Objects.equals(registryId, that.registryId)
        && Objects.equals(services, that.services)
        && Objects.equals(owner, that.owner)
        && Objects.equals(lifecycleState, that.lifecycleState)
        && generation == that.generation
        && Objects.equals(retentionUntil, that.retentionUntil);
  }

  @Override
  public int hashCode() {
    return Objects.hash(instanceName, mpackId, mpackName, version, registryId, services, owner,
        lifecycleState, generation, retentionUntil);
  }
}
