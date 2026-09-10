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
package org.apache.ambari.server.controller.metrics;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import com.google.gson.JsonParser;

public class RestMetricProjectionTest {
  @Test
  public void testNestedNumericMetricsCannotExposeStringsOrDocuments() {
    var document = JsonParser.parseString("{\"worker\":{\"count\":4,\"label\":\"private-value\",\"children\":[1]},\"count\":99}");
    assertEquals(Double.valueOf(4), RestMetricsPropertyProvider.numericValue(document, new String[]{"worker", "count"}));
    assertNull(RestMetricsPropertyProvider.numericValue(document, new String[]{"worker", "label"}));
    assertNull(RestMetricsPropertyProvider.numericValue(document, new String[]{"worker"}));
    assertNull(RestMetricsPropertyProvider.numericValue(document, new String[]{"worker", "children"}));
    assertNull(RestMetricsPropertyProvider.numericValue(document, new String[]{"worker", "missing"}));
    assertNull(RestMetricsPropertyProvider.numericValue(JsonParser.parseString("{\"count\":1e999}"), new String[]{"count"}));
  }
}
