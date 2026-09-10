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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Applies lifecycle transitions to the durable mpack reference carried by a
 * Blueprint setting. Callers persist the returned reference using the same
 * Blueprint setting DAO used for mpack_instances.
 */
public final class MpackLifecycleManager {
  private MpackLifecycleManager() {
  }

  public static MpackReference adopt(MpackReference reference, String owner) {
    requireReference(reference);
    return reference.adopt(owner);
  }

  public static MpackReference detach(MpackReference reference) {
    requireReference(reference);
    return reference.detach();
  }

  public static MpackReference requestDelete(MpackReference reference, long retentionUntil) {
    requireReference(reference);
    return reference.requestDelete(retentionUntil);
  }

  public static MpackReference beginUpgrade(MpackReference reference, String targetVersion) {
    requireReference(reference);
    return reference.beginUpgrade(targetVersion);
  }

  /**
   * Delete only detached references whose retention window has elapsed.
   * Active or malformed references remain in the result, fail-closed.
   */
  public static List<MpackReference> purgeExpired(List<MpackReference> references,
      long now) {
    if (references == null) {
      return Collections.emptyList();
    }
    List<MpackReference> result = new ArrayList<>();
    for (MpackReference reference : references) {
      requireReference(reference);
      boolean expired = reference.getRetentionUntil() != null
          && reference.getRetentionUntil() <= now
          && MpackLifecycleState.DELETE_PENDING.name().equals(reference.getLifecycleState());
      if (!expired) {
        result.add(reference);
      }
    }
    return Collections.unmodifiableList(result);
  }

  public static void requireDeletable(MpackReference reference, long now) {
    requireReference(reference);
    if (!MpackLifecycleState.DELETE_PENDING.name().equals(reference.getLifecycleState())) {
      throw new IllegalStateException("Mpack must be DELETE_PENDING before deletion");
    }
    if (reference.getRetentionUntil() == null || reference.getRetentionUntil() > now) {
      throw new IllegalStateException("Mpack retention window has not elapsed");
    }
  }

  private static void requireReference(MpackReference reference) {
    Objects.requireNonNull(reference, "mpack reference");
  }
}
