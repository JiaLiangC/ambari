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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.google.gson.JsonObject;

public class MpackRemovalEvidenceTest {
  @Test
  public void testMapsRetainedPurgedAndExternalEvidence() {
    MpackRemovalEvidence retained = MpackRemovalEvidence.released(
        evidence(true, "absent", "retained", "released"));
    assertEquals("UNINSTALLED_RETAINED", retained.resourceState());
    assertFalse(retained.isPurged());

    MpackRemovalEvidence purged = MpackRemovalEvidence.released(
        evidence(true, "absent", "purged", "released"));
    assertEquals("PURGED", purged.resourceState());
    assertTrue(purged.isPurged());

    assertEquals("UNREGISTERED", MpackRemovalEvidence.released(
        evidence(true, "external", "external", "external")).resourceState());
  }

  @Test
  public void testRejectsMissingTypedOrMixedEvidence() {
    assertThrows(IllegalArgumentException.class, () -> MpackRemovalEvidence.released(
        evidence(false, "absent", "retained", "released")));
    assertThrows(IllegalArgumentException.class, () -> MpackRemovalEvidence.released(
        evidence(true, "external", "retained", "external")));
    JsonObject wrongType = evidence(true, "absent", "retained", "released");
    wrongType.addProperty("managementReleased", "true");
    assertThrows(IllegalArgumentException.class, () -> MpackRemovalEvidence.released(wrongType));
  }

  private JsonObject evidence(boolean released, String runtime, String data, String ownership) {
    JsonObject result = new JsonObject();
    result.addProperty("managementReleased", released);
    result.addProperty("runtimeDisposition", runtime);
    result.addProperty("dataDisposition", data);
    result.addProperty("ownershipDisposition", ownership);
    return result;
  }
}
