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
  private static final Set<String> MUTATIONS = Set.of("INSTALL", "CONFIGURE", "START", "STOP", "RESTART", "RELOAD", "UPGRADE", "DETACH", "ADOPT", "UNINSTALL", "PURGE");
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
    String operation = binding.get("operation").getAsString();
    String previousOperation = created ? null : JsonParser.parseString(resource.getTaskBinding()).getAsJsonObject().get("operation").getAsString();
    if (!created && "PENDING".equals(resource.getResourceState()) && Set.of("DETACH", "ADOPT").contains(previousOperation)
        && !operation.equals(previousOperation)) {
      throw new IllegalStateException("Reconcile the pending ownership handoff before another operation");
    }
    if (!created && "DETACHED".equals(resource.getResourceState()) && !Set.of("DETACH", "ADOPT").contains(operation)) {
      throw new IllegalStateException("Adopt the detached target before modifying its resources");
    }
    if ("ADOPT".equals(operation) && (created || !("DETACHED".equals(resource.getResourceState()) || "ADOPT".equals(previousOperation)))) {
      throw new IllegalStateException("Adoption requires verified prior handoff of this same target");
    }
    if ("DETACH".equals(operation) && (created || !(Set.of("MANAGED", "DETACHED").contains(resource.getResourceState()) || "DETACH".equals(previousOperation)))) {
      throw new IllegalStateException("Detachment requires a verified managed target");
    }
    if (Set.of("DETACH", "ADOPT").contains(operation)) {
      if (!packageId.equals(resource.getMaterializedMpackId()) || resource.getResourceEvidence() == null) {
        throw new IllegalStateException("Ownership handoff requires the confirmed installed package");
      }
      JsonObject evidence = JsonParser.parseString(resource.getResourceEvidence()).getAsJsonObject()
          .getAsJsonObject("mpackOperation").getAsJsonObject("observation");
      if (!evidence.has("loadState") || !"loaded".equals(evidence.get("loadState").getAsString())
          || !"inactive".equals(evidence.get("state").getAsString()) || !"0".equals(evidence.get("pid").getAsString())) {
        throw new IllegalStateException("Stop and verify the native target before ownership handoff");
      }
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
        // A late result for a superseded task never replaces the latest intent.
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
        if ((uninstalled || purged) && (!removed(observation)
            || !report.has("retainedResources") || !report.get("retainedResources").isJsonArray()
            || report.getAsJsonArray("retainedResources").size() == 0)) {
          return;
        }
        if (purged && (!report.has("purged") || !report.get("purged").getAsBoolean()
            || !report.has("purgedResources") || !report.get("purgedResources").isJsonArray()
            || !validPurgeEvidence(report))) {
          return;
        }
        boolean detached = "DETACH".equals(binding.get("operation").getAsString());
        boolean adopted = "ADOPT".equals(binding.get("operation").getAsString());
        if ((detached || adopted) && (!report.has("detached") || report.get("detached").getAsBoolean() != detached
            || !"loaded".equals(observation.get("loadState").getAsString())
            || !"inactive".equals(observation.get("state").getAsString()) || !"0".equals(observation.get("pid").getAsString())
            || !binding.get("packageDigest").equals(report.get("materializedPackageDigest")))) {
          return;
        }
        if (detached && (!report.has("retainedResources") || !report.get("retainedResources").isJsonArray()
            || report.getAsJsonArray("retainedResources").size() == 0)) {
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
        resource.setResourceState(purged ? "PURGED" : detached ? "DETACHED" : uninstalled ? "UNINSTALLED_RETAINED" : "MANAGED");
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

  private boolean removed(JsonObject observation) {
    if (observation.has("kind") && "kubernetes.workload/v1".equals(observation.get("kind").getAsString())) {
      return !observation.get("exists").getAsBoolean() && observation.get("remainingPods").getAsInt() == 0;
    }
    if (observation.has("kind") && "oci.container/v1".equals(observation.get("kind").getAsString())) {
      return !observation.get("exists").getAsBoolean()
          && "inactive".equals(observation.get("state").getAsString())
          && "0".equals(observation.get("pid").getAsString());
    }
    if (observation.has("kind") && "host.files/v1".equals(observation.get("kind").getAsString())) {
      return "absent".equals(observation.get("state").getAsString())
          && observation.get("publicationAbsent").getAsBoolean();
    }
    return "not-found".equals(observation.get("loadState").getAsString())
        && "inactive".equals(observation.get("state").getAsString())
        && "0".equals(observation.get("pid").getAsString());
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
        resource -> !Set.of("UNINSTALLED_RETAINED", "PURGED", "DETACHED").contains(resource.getResourceState()))) {
      throw new IllegalStateException("Verified UNINSTALL or DETACH evidence is required before removing this host component");
    }
  }

  @RequiresSession
  public void requireRemovable(Long clusterId, String serviceName) {
    Long count = managers.get().createQuery("SELECT COUNT(r) FROM MpackTargetResourceEntity r "
        + "WHERE r.clusterId = :cluster AND r.serviceName = :service AND r.resourceState NOT IN :states", Long.class)
        .setParameter("cluster", clusterId).setParameter("service", serviceName)
        .setParameter("states", Set.of("UNINSTALLED_RETAINED", "PURGED", "DETACHED")).getSingleResult();
    if (count != 0) {
      throw new IllegalStateException("Run and verify UNINSTALL or DETACH for every managed target before deleting the service");
    }
  }

  /** A stopped native observation determines the source release, not desired selection. */
  @RequiresSession
  public Long requireStoppedRelease(Long clusterId, String service, String incarnation) {
    List<MpackTargetResourceEntity> resources = managers.get().createQuery(
        "SELECT r FROM MpackTargetResourceEntity r WHERE r.clusterId = :cluster AND r.serviceName = :service "
            + "AND r.targetIncarnation = :incarnation", MpackTargetResourceEntity.class)
        .setParameter("cluster", clusterId).setParameter("service", service).setParameter("incarnation", incarnation)
        .getResultList();
    Long release = null;
    for (MpackTargetResourceEntity resource : resources) {
      if (!"MANAGED".equals(resource.getResourceState()) || resource.getMaterializedMpackId() == null
          || resource.getResourceEvidence() == null) {
        throw new IllegalStateException("Stop and verify every target before changing the selected package");
      }
      JsonObject result = JsonParser.parseString(resource.getResourceEvidence()).getAsJsonObject().getAsJsonObject("mpackOperation");
      JsonObject observation = result.getAsJsonObject("observation");
      if (!observation.has("loadState") || !observation.has("pid")
          || !"inactive".equals(observation.get("state").getAsString()) || !"0".equals(observation.get("pid").getAsString())
          || !"loaded".equals(observation.get("loadState").getAsString())
          || release != null && !release.equals(resource.getMaterializedMpackId())) {
        throw new IllegalStateException("Package selection requires stopped targets on one verified release");
      }
      release = resource.getMaterializedMpackId();
    }
    if (release == null) {
      throw new IllegalStateException("No verified installed target is available for an artifact update");
    }
    return release;
  }
}
