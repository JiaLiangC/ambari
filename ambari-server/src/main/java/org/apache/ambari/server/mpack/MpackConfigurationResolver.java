/*
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

package org.apache.ambari.server.mpack;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.ambari.server.utils.SecretReference;

/**
 * Server-side resolver for a package configuration schema.
 *
 * <p>Values are retained with their source and generation so that a runtime
 * adapter can decide whether a change requires reload, restart or migration.
 * Secret values stay references and are never copied into the resolved map.</p>
 */
public final class MpackConfigurationResolver {
  public enum ValueType { STRING, BOOLEAN, INTEGER, NUMBER, OBJECT, ARRAY }

  public enum Effect { NONE, RELOAD, RESTART, MIGRATION }

  public static final class Field {
    private final String name;
    private final ValueType type;
    private final Object defaultValue;
    private final Effect effect;
    private final boolean sensitive;

    public Field(String name, ValueType type, Object defaultValue, Effect effect,
        boolean sensitive) {
      if (name == null || name.trim().isEmpty() || type == null || effect == null) {
        throw new IllegalArgumentException("Configuration field name, type and effect are required");
      }
      this.name = name;
      this.type = type;
      this.defaultValue = defaultValue;
      this.effect = effect;
      this.sensitive = sensitive;
      validateValue(defaultValue);
    }

    public String getName() { return name; }
    public ValueType getType() { return type; }
    public Object getDefaultValue() { return defaultValue; }
    public Effect getEffect() { return effect; }
    public boolean isSensitive() { return sensitive; }

    public void validateValue(Object value) {
      if (value == null) {
        return;
      }
      boolean valid;
      switch (type) {
        case STRING:
          valid = value instanceof String;
          break;
        case BOOLEAN:
          valid = value instanceof Boolean;
          break;
        case INTEGER:
          valid = value instanceof Integer || value instanceof Long;
          break;
        case NUMBER:
          valid = value instanceof Number;
          break;
        case OBJECT:
          valid = value instanceof Map;
          break;
        case ARRAY:
          valid = value instanceof Iterable;
          break;
        default:
          valid = false;
      }
      if (!valid) {
        throw new IllegalArgumentException("Invalid type for configuration field " + name
            + ": expected " + type);
      }
    }
  }

  public static final class ResolvedValue {
    private final String name;
    private final Object value;
    private final Object redactedValue;
    private final String source;
    private final long generation;
    private final Effect effect;
    private final boolean secretReference;

    private ResolvedValue(Field field, Object value, String source, long generation) {
      field.validateValue(value);
      this.name = field.getName();
      this.value = value;
      this.redactedValue = field.isSensitive() || isSecret(value) ? "<secret-ref>" : value;
      this.source = source == null ? "default" : source;
      this.generation = generation;
      this.effect = field.getEffect();
      this.secretReference = isSecret(value);
    }

    public String getName() { return name; }
    public Object getValue() { return value; }
    public Object getRedactedValue() { return redactedValue; }
    public String getSource() { return source; }
    public long getGeneration() { return generation; }
    public Effect getEffect() { return effect; }
    public boolean isSecretReference() { return secretReference; }
  }

  private MpackConfigurationResolver() {
  }

  public static Map<String, ResolvedValue> resolve(Map<String, Field> schema,
      Map<String, Object> values, Map<String, String> sources, long generation) {
    if (schema == null || schema.isEmpty() || generation < 0) {
      throw new IllegalArgumentException("A non-empty schema and non-negative generation are required");
    }
    Map<String, Object> supplied = values == null ? Collections.emptyMap() : values;
    for (String name : supplied.keySet()) {
      if (!schema.containsKey(name)) {
        throw new IllegalArgumentException("Unknown configuration field " + name);
      }
    }
    Map<String, ResolvedValue> result = new LinkedHashMap<>();
    for (Map.Entry<String, Field> entry : schema.entrySet()) {
      String name = entry.getKey();
      Field field = entry.getValue();
      Object value = supplied.containsKey(name) ? supplied.get(name) : field.getDefaultValue();
      String source = sources == null ? null : sources.get(name);
      result.put(name, new ResolvedValue(field, value, source, generation));
    }
    return Collections.unmodifiableMap(result);
  }

  public static boolean isSecret(Object value) {
    return value instanceof String && SecretReference.isSecret((String) value);
  }
}
