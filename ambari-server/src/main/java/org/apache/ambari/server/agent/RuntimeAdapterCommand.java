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
 * Shared server-side command contract for V2 runtime adapters.
 *
 * <p>The command remains an ordinary Ambari execution command.  This helper
 * only adds namespaced parameters; dispatch, scheduling, authorization and
 * cluster/service ownership remain the existing Ambari responsibilities.</p>
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
   * Add a runtime operation to an existing command parameter map.
   *
   * @param commandParams mutable command parameters
   * @param profile versioned runtime profile, for example host.systemd/v1
   * @param operation adapter operation
   * @param context serialized JSON context containing the authoritative
   *                clusterId/serviceName/componentName references
   */
  public static void add(Map<String, String> commandParams, String profile,
      String operation, String context) {
    if (commandParams == null) {
      throw new IllegalArgumentException("commandParams must not be null");
    }
    requireText(profile, "profile");
    requireText(operation, "operation");
    requireText(context, "context");
    commandParams.put(PROFILE, profile);
    commandParams.put(OPERATION, operation);
    commandParams.put(CONTEXT, context);
  }

  /**
   * Create an isolated parameter map for callers building a new command.
   */
  public static Map<String, String> create(String profile, String operation,
      String context) {
    Map<String, String> result = new HashMap<>();
    add(result, profile, operation, context);
    return result;
  }

  private static void requireText(String value, String name) {
    if (value == null || value.trim().isEmpty()) {
      throw new IllegalArgumentException(name + " must not be empty");
    }
  }
}
