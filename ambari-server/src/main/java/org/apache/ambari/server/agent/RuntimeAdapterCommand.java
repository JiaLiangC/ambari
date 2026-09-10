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

package org.apache.ambari.server.agent;

import java.util.HashMap;
import java.util.Map;

/**
 * Retired alpha command constants retained for compatibility guards.
 *
 * <p>No server producer may activate this protocol. Authorization and task
 * execution remain with the established Ambari service workflow.</p>
 */
public final class RuntimeAdapterCommand {
  public static final String PROFILE = "runtime_profile";
  public static final String OPERATION = "runtime_operation";
  public static final String CONTEXT = "runtime_context";
  public static final String PLAN = "runtime_plan";
  public static final String OPERATION_ID = "runtime_operation_id";
  public static final String IDEMPOTENCY_KEY = "runtime_idempotency_key";

  private RuntimeAdapterCommand() {
  }

  /**
   * The parameter-driven alpha protocol is retired. Keep the source signature
   * so callers fail before scheduling instead of silently executing a legacy task.
   */
  public static void add(Map<String, String> commandParams, String profile,
      String operation, String context) {
    throw new UnsupportedOperationException("Parameter-driven runtime execution is unsupported");
  }

  public static Map<String, String> create(String profile, String operation,
      String context) {
    Map<String, String> result = new HashMap<>();
    add(result, profile, operation, context);
    return result;
  }
}
