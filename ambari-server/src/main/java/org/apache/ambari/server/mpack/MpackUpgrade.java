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
import java.util.Map;
import java.util.TreeMap;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

/** Pure admission for the stopped, data-unchanged host artifact update contract. */
public final class MpackUpgrade {
  private MpackUpgrade() {
  }

  public static void validate(JsonObject previous, JsonObject candidate) throws IOException {
    try {
      JsonObject from = previous.getAsJsonObject("package");
      JsonObject to = candidate.getAsJsonObject("package");
      JsonObject oldService = previous.getAsJsonObject("service");
      JsonObject newService = candidate.getAsJsonObject("service");
      JsonPrimitive format = new JsonPrimitive("mpack.ambari.apache.org/host-service/v1");
      if (!format.equals(previous.get("format")) || !format.equals(candidate.get("format"))
          || !from.get("name").equals(to.get("name")) || !oldService.get("name").equals(newService.get("name"))
          || from.get("digest").equals(to.get("digest"))
          || !names(oldService, "configurations").keySet().equals(names(newService, "configurations").keySet())) {
        throw incompatible();
      }
      Map<String, JsonObject> oldComponents = names(oldService, "components");
      Map<String, JsonObject> newComponents = names(newService, "components");
      if (oldComponents.isEmpty() || !oldComponents.keySet().equals(newComponents.keySet())) {
        throw incompatible();
      }
      for (Map.Entry<String, JsonObject> entry : oldComponents.entrySet()) {
        JsonObject oldComponent = entry.getValue();
        JsonObject newComponent = newComponents.get(entry.getKey());
        for (String property : new String[]{"category", "role", "cardinality"}) {
          if (!java.util.Objects.equals(oldComponent.get(property), newComponent.get(property))) {
            throw incompatible();
          }
        }
        if (oldComponent.getAsJsonArray("profiles").size() != 1 || newComponent.getAsJsonArray("profiles").size() != 1) {
          throw incompatible();
        }
        JsonObject oldProfile = oldComponent.getAsJsonArray("profiles").get(0).getAsJsonObject();
        JsonObject newProfile = newComponent.getAsJsonArray("profiles").get(0).getAsJsonObject();
        JsonObject policy = newProfile.getAsJsonObject("upgradePolicy");
        boolean artifact = false;
        for (JsonElement argument : newProfile.getAsJsonObject("resources").getAsJsonObject("command").getAsJsonArray("arguments")) {
          artifact |= argument.isJsonObject() && argument.getAsJsonObject().has("artifactRef");
        }
        if (!artifact || !new JsonPrimitive("host.systemd/v1").equals(oldProfile.get("adapter"))
            || !oldProfile.get("adapter").equals(newProfile.get("adapter"))
            || !newProfile.getAsJsonArray("capabilities").contains(new JsonPrimitive("upgrade"))
            || !policy.getAsJsonArray("fromPackageDigests").contains(from.get("digest"))
            || !new JsonPrimitive("compatible").equals(policy.get("configuration"))
            || !new JsonPrimitive("unchanged").equals(policy.get("data"))
            || !layout(oldProfile).equals(layout(newProfile))) {
          throw incompatible();
        }
      }
    } catch (RuntimeException malformed) {
      throw incompatible();
    }
  }

  private static Map<String, JsonObject> names(JsonObject object, String field) {
    Map<String, JsonObject> result = new TreeMap<>();
    if (object.has(field)) {
      for (JsonElement value : object.getAsJsonArray(field)) {
        JsonObject item = value.getAsJsonObject();
        if (result.put(item.get("name").getAsString(), item) != null) {
          throw new IllegalArgumentException("Duplicate declaration");
        }
      }
    }
    return result;
  }

  private static JsonObject layout(JsonObject profile) {
    JsonObject result = profile.getAsJsonObject("resources").deepCopy();
    result.remove("command");
    result.remove("reloadSignal");
    return result;
  }

  private static IOException incompatible() {
    return new IOException("CAPABILITY_UNSUPPORTED: package update requires compatible artifacts and unchanged data/resources");
  }
}
