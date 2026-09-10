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
package org.apache.ambari.server.topology;

import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

public class MpackReferenceTest {
  @Test
  public void testSelectionRoundTripRetainsPackageAndServiceIdentity() {
    MpackReference reference = new MpackReference("package", 1L, "TEST", "1", null,
        Map.of("REDIS", "REDIS"));
    Assert.assertEquals(reference, MpackReference.fromApiMap(reference.toApiMap()));
    Assert.assertEquals(reference, MpackReference.fromSettingMap(reference.toSettingMap()));
  }

  @Test
  public void testBlueprintCannotAssertLiveOwnershipOrLifecycle() {
    MpackReference reference = new MpackReference("package", 1L, "TEST", "1", null,
        Map.of("REDIS", "REDIS"));
    for (String field : new String[]{"owner", "lifecycle_state", "generation", "retention_until"}) {
      Map<String, Object> values = new HashMap<>(reference.toApiMap());
      values.put(field, "untrusted");
      Assert.assertThrows(IllegalArgumentException.class, () -> MpackReference.fromApiMap(values));
    }
    Assert.assertThrows(IllegalArgumentException.class, () -> new MpackReference(
        "package", 1L, "TEST", "1", null, Map.of("REDIS_SECOND", "REDIS")));
  }
}
