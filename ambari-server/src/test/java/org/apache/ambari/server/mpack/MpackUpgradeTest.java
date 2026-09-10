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

import static org.junit.Assert.assertThrows;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class MpackUpgradeTest {
  private JsonObject release(String digest) {
    Map<String, Object> resources = Map.of(
        "unit", Map.of("user", "http"),
        "directories", List.of(Map.of("path", "data", "owner", "http")),
        "command", Map.of("program", "/usr/bin/python3", "arguments", List.of(Map.of("artifactRef", "server"))));
    Map<String, Object> profile = Map.of(
        "adapter", "host.systemd/v1", "capabilities", List.of("upgrade"),
        "upgradePolicy", Map.of("fromPackageDigests", List.of("a".repeat(64)),
            "configuration", "compatible", "data", "unchanged"),
        "resources", resources);
    Map<String, Object> service = Map.of(
        "name", "HTTP_ECHO", "configurations", List.of(Map.of("name", "http")),
        "components", List.of(Map.of("name", "SERVER", "category", "MASTER", "profiles", List.of(profile))));
    return new Gson().toJsonTree(Map.of(
        "format", "mpack.ambari.apache.org/host-service/v1",
        "package", Map.of("name", "publisher-4-team-http", "digest", digest),
        "service", service)).getAsJsonObject();
  }

  private JsonObject profile(JsonObject value) {
    return value.getAsJsonObject("service").getAsJsonArray("components").get(0).getAsJsonObject()
        .getAsJsonArray("profiles").get(0).getAsJsonObject();
  }

  @Test
  public void testCompatibleArtifactChangeUsesSameIdentityAndResourceLayout() throws Exception {
    JsonObject previous = release("a".repeat(64));
    JsonObject candidate = release("b".repeat(64));
    profile(candidate).getAsJsonObject("resources").getAsJsonObject("command").addProperty("program", "/usr/local/bin/python3");
    MpackUpgrade.validate(previous, candidate);
    profile(candidate).getAsJsonObject("resources").getAsJsonObject("unit").addProperty("user", "other");
    assertThrows(IOException.class, () -> MpackUpgrade.validate(previous, candidate));
  }

  @Test
  public void testUndeclaredDataMigrationAndForeignPackageCannotChangeSelection() {
    JsonObject previous = release("a".repeat(64));
    JsonObject candidate = release("b".repeat(64));
    candidate.getAsJsonObject("package").addProperty("name", "another-publisher");
    assertThrows(IOException.class, () -> MpackUpgrade.validate(previous, candidate));
    candidate.getAsJsonObject("package").addProperty("name", "publisher-4-team-http");
    profile(candidate).getAsJsonObject("upgradePolicy").addProperty("data", "migration");
    assertThrows(IOException.class, () -> MpackUpgrade.validate(previous, candidate));
    profile(candidate).getAsJsonObject("upgradePolicy").addProperty("data", "unchanged");
    profile(candidate).getAsJsonObject("upgradePolicy").add("fromPackageDigests", new JsonArray());
    assertThrows(IOException.class, () -> MpackUpgrade.validate(previous, candidate));
  }
}
