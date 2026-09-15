/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ambari.server.orm.dao;

import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;

import org.apache.ambari.server.mpack.MpackRemovalEvidence;
import org.apache.ambari.server.orm.RequiresSession;
import org.apache.ambari.server.orm.entities.MpackEntity;
import org.apache.ambari.server.orm.entities.MpackTargetResourceEntity;
import org.apache.commons.codec.digest.DigestUtils;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import com.google.inject.persist.Transactional;

/** Projects existing task intent and verified Agent evidence; never schedules work. */
@Singleton
public class MpackTargetResourceDAO {
  private static final Set<String> MUTATIONS = Set.of(
      "INSTALL", "CONFIGURE", "START", "STOP", "RESTART", "UNINSTALL", "PURGE");
  @Inject
  private Provider<EntityManager> managers;

  @Transactional
  public void recordIntent(String serialized, Long taskId) {
    if (serialized == null) {
      return;
    }
    JsonObject binding = JsonParser.parseString(serialized).getAsJsonObject();
    if (!MUTATIONS.contains(binding.get("operation").getAsString())) {
      return;
    }
    EntityManager manager = managers.get();
    Long packageId = binding.get("packageId").getAsLong();
    // Catalog deletion takes the same lock; the FK remains the final guard.
    if (manager.find(MpackEntity.class, packageId, LockModeType.PESSIMISTIC_WRITE) == null) {
      throw new IllegalStateException("Package disappeared before task persistence");
    }
    String key = DigestUtils.sha256Hex(binding.get("targetIncarnation").getAsString() + "\n"
        + binding.get("hostName").getAsString() + "\n" + binding.get("role").getAsString());
    MpackTargetResourceEntity resource = manager.find(MpackTargetResourceEntity.class, key, LockModeType.PESSIMISTIC_WRITE);
    boolean created = resource == null;
    boolean purge = "PURGE".equals(binding.get("operation").getAsString());
    boolean purgeStarted = !created && "PURGE".equals(JsonParser.parseString(
        resource.getTaskBinding()).getAsJsonObject().get("operation").getAsString());
    if (purge && (created || !(Set.of("UNINSTALLED_RETAINED", "PURGED").contains(resource.getResourceState())
        || purgeStarted))) {
      throw new IllegalStateException("Purge requires verified retained-resource ownership");
    }
    if (!purge && !created && (purgeStarted || "PURGED".equals(resource.getResourceState()))) {
      throw new IllegalStateException("Purge has begun; finish purge and use a new service incarnation");
    }
    if (resource == null) {
      resource = new MpackTargetResourceEntity();
      resource.setTargetKey(key);
      resource.setClusterId(binding.get("clusterId").getAsLong());
      resource.setServiceName(binding.get("serviceName").getAsString());
      resource.setTargetIncarnation(binding.get("targetIncarnation").getAsString());
      resource.setHostName(binding.get("hostName").getAsString());
      resource.setComponentName(binding.get("role").getAsString());
    } else if (resource.getTaskId() >= taskId) {
      throw new IllegalStateException("Task intent was superseded");
    }
    resource.setMpackId(packageId);
    resource.setTaskId(taskId);
    resource.setTaskBinding(serialized);
    resource.setResourceState("PENDING");
    if (created) {
      manager.persist(resource);
    }
  }

  @Transactional
  public void recordReport(Long taskId, String serialized) {
    if (serialized == null || serialized.length() > 131072) {
      return;
    }
    List<MpackTargetResourceEntity> resources = managers.get().createQuery(
        "SELECT r FROM MpackTargetResourceEntity r WHERE r.taskId = :id", MpackTargetResourceEntity.class)
        .setParameter("id", taskId).setLockMode(LockModeType.PESSIMISTIC_WRITE).getResultList();
    if (resources.isEmpty()) {
      return;
    }
    try {
      JsonObject report = JsonParser.parseString(serialized).getAsJsonObject().getAsJsonObject("mpackOperation");
      if (report == null || !"SUCCEEDED".equals(report.get("state").getAsString())) {
        return;
      }
      for (MpackTargetResourceEntity resource : resources) {
        managers.get().refresh(resource, LockModeType.PESSIMISTIC_WRITE);
        if (!taskId.equals(resource.getTaskId())) {
          continue;
        }
        JsonObject binding = JsonParser.parseString(resource.getTaskBinding()).getAsJsonObject();
        JsonObject observation = report.getAsJsonObject("observation");
        JsonObject identity = observation.getAsJsonObject("identity");
        if (!binding.get("packageDigest").equals(report.get("packageDigest"))
            || !taskId.toString().equals(report.get("taskId").getAsString())
            || !binding.get("clusterId").equals(identity.get("clusterId"))
            || !binding.get("serviceName").equals(identity.get("serviceName"))
            || !binding.get("role").equals(identity.get("componentName"))
            || !binding.get("hostName").equals(identity.get("hostName"))
            || !binding.get("targetIncarnation").equals(identity.get("targetIncarnation"))) {
          return;
        }
        boolean uninstalled = "UNINSTALL".equals(binding.get("operation").getAsString());
        boolean purged = "PURGE".equals(binding.get("operation").getAsString());
        MpackRemovalEvidence removal = null;
        if (uninstalled || purged) {
          removal = MpackRemovalEvidence.released(observation);
        }
        if ((uninstalled || purged) && (!report.has("retainedResources")
            || !report.get("retainedResources").isJsonArray()
            || report.getAsJsonArray("retainedResources").size() == 0)) {
          return;
        }
        if (purged && (!report.has("purged") || !report.get("purged").getAsBoolean()
            || !report.has("purgedResources") || !report.get("purgedResources").isJsonArray()
            || !removal.isPurged() || !validPurgeEvidence(report))) {
          return;
        }
        if (report.has("materializedPackageDigest") && !report.get("materializedPackageDigest").isJsonNull()) {
          String materialized = report.get("materializedPackageDigest").getAsString();
          if (materialized.equals(binding.get("packageDigest").getAsString())) {
            resource.setMaterializedMpackId(binding.get("packageId").getAsLong());
          } else {
            MpackEntity previous = resource.getMaterializedMpackId() == null ? null
                : managers.get().find(MpackEntity.class, resource.getMaterializedMpackId());
            if (previous == null || !materialized.equals(previous.getContentDigest())) {
              return;
            }
          }
        }
        if (purged) {
          resource.setMaterializedMpackId(null);
        }
        resource.setResourceEvidence(serialized);
        resource.setResourceState(uninstalled || purged ? removal.resourceState() : "MANAGED");
      }
    } catch (RuntimeException malformedReport) {
      // A malformed observation cannot authorize deleting service or data.
      // Keep the intent and any earlier evidence for an explicit recovery task.
    }
  }

  private boolean validPurgeEvidence(JsonObject report) {
    Map<String, JsonObject> retained = new java.util.HashMap<>();
    for (com.google.gson.JsonElement value : report.getAsJsonArray("retainedResources")) {
      JsonObject resource = value.getAsJsonObject();
      String path = resource.get("path").getAsString();
      if (retained.put(path, resource) != null) {
        return false;
      }
    }
    boolean receiptRetained = false;
    for (com.google.gson.JsonElement value : report.getAsJsonArray("purgedResources")) {
      JsonObject resource = value.getAsJsonObject();
      JsonObject before = retained.remove(resource.get("path").getAsString());
      if (before == null || !before.get("device").equals(resource.get("device"))
          || !before.get("inode").equals(resource.get("inode"))) {
        return false;
      }
      String disposition = resource.get("disposition").getAsString();
      if ("receipt-only".equals(disposition)) {
        if (receiptRetained) {
          return false;
        }
        receiptRetained = true;
      } else if (!"purged".equals(disposition)) {
        return false;
      }
    }
    return receiptRetained && retained.isEmpty();
  }

  @RequiresSession
  public List<MpackTargetResourceEntity> findPage(Long clusterId, String after, int limit) {
    return managers.get().createQuery("SELECT r FROM MpackTargetResourceEntity r WHERE r.clusterId = :id "
        + "AND r.targetKey > :after ORDER BY r.targetKey", MpackTargetResourceEntity.class)
        .setParameter("id", clusterId).setParameter("after", after).setMaxResults(limit).getResultList();
  }

  @RequiresSession
  public List<MpackTargetResourceEntity> findByCluster(Long clusterId) {
    return managers.get().createQuery("SELECT r FROM MpackTargetResourceEntity r WHERE r.clusterId = :id",
        MpackTargetResourceEntity.class).setParameter("id", clusterId).getResultList();
  }

  @RequiresSession
  public void requireHostRemovable(Long clusterId, String service, String incarnation,
      String host, String component, boolean neverInstalled) {
    List<MpackTargetResourceEntity> resources = managers.get().createQuery(
        "SELECT r FROM MpackTargetResourceEntity r WHERE r.clusterId = :cluster "
        + "AND r.serviceName = :service AND r.targetIncarnation = :incarnation "
        + "AND r.hostName = :host AND r.componentName = :component", MpackTargetResourceEntity.class)
        .setParameter("cluster", clusterId).setParameter("service", service).setParameter("incarnation", incarnation)
        .setParameter("host", host).setParameter("component", component).getResultList();
    if (resources.isEmpty() && !neverInstalled || resources.stream().anyMatch(
        resource -> !Set.of("UNINSTALLED_RETAINED", "PURGED", "UNREGISTERED").contains(resource.getResourceState()))) {
      throw new IllegalStateException("Verified management release is required before removing this host component");
    }
  }

  @RequiresSession
  public void requireRemovable(Long clusterId, String serviceName) {
    Long count = managers.get().createQuery("SELECT COUNT(r) FROM MpackTargetResourceEntity r "
        + "WHERE r.clusterId = :cluster AND r.serviceName = :service AND r.resourceState NOT IN :states", Long.class)
        .setParameter("cluster", clusterId).setParameter("service", serviceName)
        .setParameter("states", Set.of("UNINSTALLED_RETAINED", "PURGED", "UNREGISTERED")).getSingleResult();
    if (count != 0) {
      throw new IllegalStateException("Verify management release for every target before deleting the service");
    }
  }

}
