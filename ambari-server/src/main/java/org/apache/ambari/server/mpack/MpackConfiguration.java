/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ambari.server.mpack;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.commons.codec.digest.DigestUtils;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

/** Validates the exported host scalar contract before existing config/task persistence. */
public final class MpackConfiguration {
  private MpackConfiguration() {
  }

  public static void validate(Path module, String digest, String service, String type,
      Map<String, String> properties) throws IOException {
    JsonObject descriptor = read(module.resolve("manifest-service.json"));
    if (!digest.equals(descriptor.getAsJsonObject("package").get("digest").getAsString())
        || !service.equals(descriptor.getAsJsonObject("service").get("name").getAsString())) {
      throw new IOException("Package configuration identity differs from catalog authority");
    }
    for (JsonElement element : descriptor.getAsJsonObject("service").getAsJsonArray("configurations")) {
      JsonObject config = element.getAsJsonObject();
      if (!type.equals(config.get("name").getAsString())) {
        continue;
      }
      String relative = config.get("schema").getAsString();
      Path payload = module.resolve("payload").toAbsolutePath().normalize();
      Path path = payload.resolve(relative).normalize();
      if (!path.startsWith(payload) || !path.toRealPath().equals(path)) {
        throw new IOException("Configuration schema path is outside authenticated payload");
      }
      JsonObject schema = read(path);
      boolean locked = false;
      for (JsonElement entry : descriptor.getAsJsonArray("files")) {
        JsonObject file = entry.getAsJsonObject();
        if (relative.equals(file.get("path").getAsString())) {
          locked = file.get("sha256").getAsString().equals(DigestUtils.sha256Hex(Files.readAllBytes(path)));
        }
      }
      if (!locked) {
        throw new IOException("Configuration schema differs from its package lock");
      }
      validateValues(schema, config.has("defaults") ? config.getAsJsonObject("defaults") : new JsonObject(),
          properties, service);
      return;
    }
    throw new IOException("Package configuration type is not declared");
  }

  static JsonObject read(Path path) throws IOException {
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) > 1048576) {
      throw new IOException("Package configuration metadata is missing or oversized");
    }
    return JsonParser.parseString(Files.readString(path)).getAsJsonObject();
  }

  static void validateValues(JsonObject schema, JsonObject defaults, Map<String, String> supplied, String service) {
    JsonObject fields = schema.getAsJsonObject("properties");
    if (fields == null || supplied.size() > fields.size() || !fields.keySet().containsAll(supplied.keySet())) {
      throw invalid();
    }
    for (Map.Entry<String, JsonElement> entry : fields.entrySet()) {
      String name = entry.getKey();
      JsonObject field = entry.getValue().getAsJsonObject();
      if (field.has("x-resource")) {
        if (supplied.containsKey(name)) {
          throw invalid(); // Native paths are injected by the assigned Agent only.
        }
        continue;
      }
      JsonElement value = supplied.containsKey(name) ? new JsonPrimitive(supplied.get(name))
          : defaults.has(name) ? defaults.get(name) : field.get("default");
      if (value == null || value.isJsonNull()) {
        if (field.has("x-sensitive") || schema.has("required") && schema.getAsJsonArray("required").contains(new JsonPrimitive(name))) {
          throw invalid();
        }
        continue;
      }
      if (field.has("x-sensitive")) {
        String reference = value.isJsonObject() ? value.getAsJsonObject().get("secretRef").getAsString() : value.getAsString();
        if (!reference.matches("secret://mpack\\." + Pattern.quote(service) + "\\.[A-Za-z0-9_.-]{1,128}")) {
          throw invalid();
        }
        continue;
      }
      String text = value.getAsString();
      if (text.length() > 65536 || text.indexOf('\n') >= 0 || text.indexOf('\r') >= 0 || text.indexOf(0) >= 0) {
        throw invalid();
      }
      switch (field.get("type").getAsString()) {
        case "integer":
        case "number":
          if (field.get("type").getAsString().equals("integer") && !text.matches("-?[0-9]+")) {
            throw invalid();
          }
          BigDecimal number;
          try {
            number = new BigDecimal(text);
          } catch (NumberFormatException invalidNumber) {
            throw invalid();
          }
          if (!Double.isFinite(number.doubleValue())
              || field.has("minimum") && number.compareTo(field.get("minimum").getAsBigDecimal()) < 0
              || field.has("maximum") && number.compareTo(field.get("maximum").getAsBigDecimal()) > 0) {
            throw invalid();
          }
          value = new JsonPrimitive(number);
          break;
        case "boolean":
          if (!text.equalsIgnoreCase("true") && !text.equalsIgnoreCase("false")) {
            throw invalid();
          }
          value = new JsonPrimitive(Boolean.parseBoolean(text));
          break;
        case "string":
          int length = text.codePointCount(0, text.length());
          if (field.has("minLength") && length < field.get("minLength").getAsInt()
              || field.has("maxLength") && length > field.get("maxLength").getAsInt()) {
            throw invalid();
          }
          value = new JsonPrimitive(text);
          break;
        default:
          throw invalid();
      }
      if (field.has("enum") && !field.getAsJsonArray("enum").contains(value)) {
        throw invalid();
      }
    }
  }

  private static IllegalArgumentException invalid() {
    return new IllegalArgumentException("SCHEMA_INVALID: package configuration violates its declared scalar contract");
  }
}
