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

import java.util.Map;

import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class MpackConfigurationTest {
  private final JsonObject schema = JsonParser.parseString("{\"properties\":{"
      + "\"port\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":65535,\"default\":18080},"
      + "\"mode\":{\"type\":\"string\",\"enum\":[\"safe\",\"strict\"],\"default\":\"safe\"},"
      + "\"path\":{\"type\":\"string\",\"x-resource\":\"data\"},"
      + "\"message\":{\"type\":\"string\",\"maxLength\":2}},\"required\":[\"port\"]}").getAsJsonObject();

  @Test
  public void validatesDefaultsTypedValuesAndUnicodeLength() {
    MpackConfiguration.validateValues(schema, new JsonObject(), Map.of("port", "1234", "message", "😀😀"), "WEB");
    for (Map<String, String> invalid : java.util.List.of(Map.of("port", "0"), Map.of("port", "1.5"),
        Map.of("mode", "unsafe"), Map.of("path", "/etc"), Map.of("unknown", "value"),
        Map.of("message", "abc"), Map.of("message", "a\nb"))) {
      assertThrows(IllegalArgumentException.class,
          () -> MpackConfiguration.validateValues(schema, new JsonObject(), invalid, "WEB"));
    }
  }

  @Test
  public void sensitiveFieldsRequireScopedReferencesBeforePersistence() {
    JsonObject secret = JsonParser.parseString("{\"properties\":{\"credential\":{\"type\":\"object\",\"x-sensitive\":true}}}").getAsJsonObject();
    MpackConfiguration.validateValues(secret, new JsonObject(), Map.of("credential", "secret://mpack.WEB.password"), "WEB");
    assertThrows(IllegalArgumentException.class, () -> MpackConfiguration.validateValues(secret, new JsonObject(),
        Map.of("credential", "secret://mpack.OTHER.password"), "WEB"));
    assertThrows(IllegalArgumentException.class, () -> MpackConfiguration.validateValues(secret, new JsonObject(),
        Map.of("credential", "unresolved literal"), "WEB"));
    assertThrows(IllegalArgumentException.class, () -> MpackConfiguration.validateValues(secret, new JsonObject(), Map.of(), "WEB"));
  }
}
