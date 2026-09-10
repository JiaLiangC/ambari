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

package org.apache.ambari.server.topology;

/** Durable lifecycle states carried with a Blueprint mpack reference. */
public enum MpackLifecycleState {
  REGISTERED,
  ADOPTED,
  DETACHED,
  DELETE_PENDING,
  UPGRADE_PENDING;

  public boolean canTransitionTo(MpackLifecycleState next) {
    if (next == null || next == this) {
      return false;
    }
    switch (this) {
      case REGISTERED:
        return next == ADOPTED || next == DETACHED || next == UPGRADE_PENDING;
      case ADOPTED:
        return next == DETACHED || next == DELETE_PENDING || next == UPGRADE_PENDING;
      case DETACHED:
        return next == ADOPTED || next == DELETE_PENDING || next == UPGRADE_PENDING;
      case UPGRADE_PENDING:
        return next == ADOPTED || next == DETACHED || next == DELETE_PENDING;
      case DELETE_PENDING:
      default:
        return false;
    }
  }

  public static MpackLifecycleState parse(String value) {
    if (value == null || value.trim().isEmpty()) {
      return REGISTERED;
    }
    try {
      return valueOf(value.trim().toUpperCase());
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Unknown mpack lifecycle state: " + value, e);
    }
  }
}
