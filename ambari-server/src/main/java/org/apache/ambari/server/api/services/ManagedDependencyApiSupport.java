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
package org.apache.ambari.server.api.services;

import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

import jakarta.persistence.PersistenceException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.apache.ambari.server.controller.dependencies.ManagedDependencyIntegrationException;
import org.apache.ambari.server.controller.dependencies.ManagedDependencyType;
import org.apache.ambari.server.controller.dependencies.ManagedServiceDependencyCoordinator.CreateRequest;
import org.apache.ambari.server.controller.dependencies.ManagedServiceDependencyCoordinator.DraftReference;
import org.apache.ambari.server.controller.dependencies.ManagedServiceDependencyCoordinator.LifecycleRequest;
import org.apache.ambari.server.controller.dependencies.ManagedServiceDependencyCoordinator.ProviderReference;
import org.apache.ambari.server.security.authorization.AuthorizationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

final class ManagedDependencyApiSupport {
  private static final Logger LOG = LoggerFactory.getLogger(ManagedDependencyApiSupport.class);
  private static final int MAX_REQUEST_BYTES = 65_536;
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private ManagedDependencyApiSupport() {
  }

  static Response invoke(Supplier<Object> action) {
    try {
      return Response.ok(action.get()).type(MediaType.APPLICATION_JSON_TYPE).build();
    } catch (ManagedDependencyIntegrationException e) {
      return error(e.getStatus(), e.getCode(), e.getMessage());
    } catch (AuthorizationException e) {
      return error(Response.Status.FORBIDDEN.getStatusCode(), "DEPENDENCY_AUTHORIZATION_FAILED",
          "The authenticated user is not authorized for this dependency operation.");
    } catch (IllegalArgumentException e) {
      return error(Response.Status.BAD_REQUEST.getStatusCode(), "INVALID_DEPENDENCY_REQUEST",
          safeMessage(e, "The dependency request is invalid."));
    } catch (PersistenceException e) {
      LOG.error("Managed dependency persistence failed: {}", e.getClass().getName());
      return error(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "DEPENDENCY_STORAGE_FAILED",
          "The dependency operation could not be persisted.");
    } catch (RuntimeException e) {
      LOG.error("Managed dependency request failed: {}", e.getClass().getName());
      return error(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "DEPENDENCY_SERVER_ERROR",
          "The dependency operation could not be completed.");
    }
  }

  static Response accepted(Supplier<Object> action) {
    try {
      return Response.accepted(action.get()).type(MediaType.APPLICATION_JSON_TYPE).build();
    } catch (ManagedDependencyIntegrationException e) {
      return error(e.getStatus(), e.getCode(), e.getMessage());
    } catch (AuthorizationException e) {
      return error(Response.Status.FORBIDDEN.getStatusCode(), "DEPENDENCY_AUTHORIZATION_FAILED",
          "The authenticated user is not authorized for this dependency operation.");
    } catch (IllegalArgumentException e) {
      return error(Response.Status.BAD_REQUEST.getStatusCode(), "INVALID_DEPENDENCY_REQUEST",
          safeMessage(e, "The dependency request is invalid."));
    } catch (PersistenceException e) {
      LOG.error("Managed dependency persistence failed: {}", e.getClass().getName());
      return error(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "DEPENDENCY_STORAGE_FAILED",
          "The dependency operation could not be persisted.");
    } catch (RuntimeException e) {
      LOG.error("Managed dependency request failed: {}", e.getClass().getName());
      return error(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "DEPENDENCY_SERVER_ERROR",
          "The dependency operation could not be completed.");
    }
  }

  static JsonNode body(String raw, Set<String> allowedFields) {
    if (raw == null || raw.getBytes(StandardCharsets.UTF_8).length > MAX_REQUEST_BYTES) {
      throw new IllegalArgumentException("Dependency request body is missing or too large");
    }
    try {
      JsonNode node = MAPPER.readTree(raw);
      if (node == null || !node.isObject()) {
        throw new IllegalArgumentException("Dependency request body must be a JSON object");
      }
      requireOnly(node, allowedFields);
      return node;
    } catch (JsonProcessingException e) {
      throw new IllegalArgumentException("Dependency request body is not valid JSON", e);
    }
  }

  static CreateRequest createRequest(String raw) {
    JsonNode root = body(raw, Set.of("binding_id", "dependency_type", "provider",
        "expected_provider_fingerprint", "expected_consumer_descriptor_fingerprint",
        "expected_snapshot_fingerprint", "preview_schema_version", "operation_id", "draft"));
    JsonNode provider = requiredObject(root, "provider", Set.of("cluster_id", "service_name"));
    DraftReference draft = null;
    if (root.hasNonNull("draft")) {
      JsonNode draftNode = requiredObject(root, "draft", Set.of("id", "revision"));
      draft = new DraftReference(uuid(text(draftNode, "id")), positiveLong(draftNode, "revision"));
    }
    return new CreateRequest(uuid(text(root, "binding_id")), type(text(root, "dependency_type")),
        provider(provider), fingerprint(root, "expected_provider_fingerprint"),
        fingerprint(root, "expected_consumer_descriptor_fingerprint"),
        fingerprint(root, "expected_snapshot_fingerprint"),
        positiveInt(root, "preview_schema_version"), uuid(text(root, "operation_id")), draft);
  }

  static LifecycleRequest lifecycleRequest(String raw) {
    JsonNode root = body(raw, Set.of("operation_id", "expected_row_version"));
    return new LifecycleRequest(uuid(text(root, "operation_id")),
        nonNegativeLong(root, "expected_row_version"));
  }

  static ProviderReference provider(JsonNode node) {
    return new ProviderReference(positiveLong(node, "cluster_id"), text(node, "service_name"));
  }

  static ManagedDependencyType type(String value) {
    try {
      return ManagedDependencyType.valueOf(value);
    } catch (RuntimeException e) {
      throw new IllegalArgumentException("dependency type must be HDFS or ZOOKEEPER", e);
    }
  }

  static UUID uuid(String value) {
    try {
      UUID uuid = UUID.fromString(value);
      if (!uuid.toString().equals(value)) {
        throw new IllegalArgumentException("UUIDs must use canonical lower-case form");
      }
      return uuid;
    } catch (RuntimeException e) {
      throw new IllegalArgumentException("A canonical UUID is required", e);
    }
  }

  static UUID optionalUuid(JsonNode node, String field) {
    if (!node.has(field) || node.get(field).isNull()) {
      return null;
    }
    return uuid(text(node, field));
  }

  static long positiveLong(String value, String field) {
    try {
      long result = Long.parseLong(value);
      if (result <= 0) {
        throw new NumberFormatException();
      }
      return result;
    } catch (RuntimeException e) {
      throw new IllegalArgumentException(field + " must be a positive integer", e);
    }
  }

  static JsonNode requiredObject(JsonNode parent, String field, Set<String> fields) {
    JsonNode value = parent.get(field);
    if (value == null || !value.isObject()) {
      throw new IllegalArgumentException(field + " must be an object");
    }
    requireOnly(value, fields);
    return value;
  }

  static String text(JsonNode node, String field) {
    JsonNode value = node.get(field);
    if (value == null || !value.isTextual() || value.textValue().isBlank()) {
      throw new IllegalArgumentException(field + " must be a non-empty string");
    }
    return value.textValue().trim();
  }

  static String fingerprint(JsonNode node, String field) {
    String value = text(node, field);
    if (!value.matches("sha256:[0-9a-f]{64}")) {
      throw new IllegalArgumentException(field + " must be a SHA-256 fingerprint");
    }
    return value;
  }

  static long positiveLong(JsonNode node, String field) {
    JsonNode value = node.get(field);
    if (value == null || !value.isIntegralNumber() || !value.canConvertToLong()
        || value.longValue() <= 0) {
      throw new IllegalArgumentException(field + " must be a positive integer");
    }
    return value.longValue();
  }

  static int positiveInt(JsonNode node, String field) {
    JsonNode value = node.get(field);
    if (value == null || !value.isIntegralNumber() || !value.canConvertToInt()
        || value.intValue() <= 0) {
      throw new IllegalArgumentException(field + " must be a positive integer");
    }
    return value.intValue();
  }

  static long nonNegativeLong(JsonNode node, String field) {
    JsonNode value = node.get(field);
    if (value == null || !value.isIntegralNumber() || !value.canConvertToLong()
        || value.longValue() < 0) {
      throw new IllegalArgumentException(field + " must be a non-negative integer");
    }
    return value.longValue();
  }

  static void requireOnly(JsonNode object, Set<String> allowed) {
    Iterator<String> names = object.fieldNames();
    while (names.hasNext()) {
      String name = names.next();
      if (!allowed.contains(name)) {
        throw new IllegalArgumentException("Unknown dependency request field: " + name);
      }
    }
  }

  private static Response error(int status, String code, String message) {
    Map<String, Object> response = new LinkedHashMap<>();
    response.put("code", code);
    response.put("message", message);
    return Response.status(status).type(MediaType.APPLICATION_JSON_TYPE).entity(response).build();
  }

  private static String safeMessage(IllegalArgumentException exception, String fallback) {
    String message = exception.getMessage();
    return message == null || message.length() > 256 ? fallback : message;
  }
}
