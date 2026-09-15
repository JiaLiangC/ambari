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

import java.util.Set;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/** Validates the profile-independent evidence required to release a target. */
public final class MpackRemovalEvidence {
  private static final Set<String> RUNTIMES = Set.of("absent", "external");
  private static final Set<String> DATA = Set.of("retained", "purged", "external");
  private static final Set<String> OWNERSHIP = Set.of("released", "external");

  private final String data;
  private final String ownership;

  private MpackRemovalEvidence(String data, String ownership) {
    this.data = data;
    this.ownership = ownership;
  }

  public static MpackRemovalEvidence released(JsonObject observation) {
    if (observation == null || !booleanValue(observation, "managementReleased")) {
      throw new IllegalArgumentException("Management release evidence is missing");
    }
    String runtime = stringValue(observation, "runtimeDisposition");
    String data = stringValue(observation, "dataDisposition");
    String ownership = stringValue(observation, "ownershipDisposition");
    if (!RUNTIMES.contains(runtime) || !DATA.contains(data) || !OWNERSHIP.contains(ownership)
        || "external".equals(runtime) != "external".equals(data)
        || "external".equals(runtime) != "external".equals(ownership)
        || "absent".equals(runtime) && "external".equals(data)) {
      throw new IllegalArgumentException("Management release dispositions are inconsistent");
    }
    return new MpackRemovalEvidence(data, ownership);
  }

  public boolean isPurged() {
    return "purged".equals(data);
  }

  public String resourceState() {
    return "external".equals(ownership) ? "UNREGISTERED"
        : isPurged() ? "PURGED" : "UNINSTALLED_RETAINED";
  }

  private static boolean booleanValue(JsonObject value, String name) {
    JsonElement field = value.get(name);
    return field != null && field.isJsonPrimitive()
        && field.getAsJsonPrimitive().isBoolean() && field.getAsBoolean();
  }

  private static String stringValue(JsonObject value, String name) {
    JsonElement field = value.get(name);
    if (field == null || !field.isJsonPrimitive() || !field.getAsJsonPrimitive().isString()) {
      throw new IllegalArgumentException("Management release disposition is missing: " + name);
    }
    return field.getAsString();
  }
}
