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
package org.apache.ambari.server.orm.dao;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;

import org.apache.ambari.server.controller.dependencies.ManagedDependencyIntegrationException;
import org.apache.ambari.server.controller.dependencies.ManagedDependencyServiceKey;
import org.apache.ambari.server.controller.dependencies.ManagedDependencySnapshot;
import org.apache.ambari.server.orm.RequiresSession;
import org.apache.ambari.server.orm.entities.ClusterServiceEntity;
import org.apache.ambari.server.orm.entities.ClusterServiceEntityPK;
import org.apache.ambari.server.orm.entities.HostComponentStateEntity;
import org.apache.ambari.server.orm.entities.RepositoryVersionEntity;
import org.apache.ambari.server.orm.entities.ScopedWorkflowStateEntity;
import org.apache.ambari.server.orm.entities.ServiceComponentDesiredStateEntity;
import org.apache.ambari.server.orm.entities.ServiceDesiredStateEntity;
import org.apache.ambari.server.orm.entities.ServiceDesiredStateEntityPK;
import org.apache.ambari.server.orm.entities.ServiceDependencyBindingEntity;
import org.apache.ambari.server.orm.entities.ServiceDependencyFenceEntity;
import org.apache.ambari.server.orm.entities.ServiceDependencyHostResultEntity;
import org.apache.ambari.server.orm.entities.ServiceDependencyHostResultEntityPK;
import org.apache.ambari.server.orm.entities.ServiceDependencyOperationEntity;
import org.apache.ambari.server.orm.entities.ServiceDependencySnapshotEntity;
import org.apache.ambari.server.orm.entities.ServiceDependencySnapshotEntityPK;
import org.apache.ambari.server.utils.StageUtils;

import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import com.google.inject.persist.Transactional;

@Singleton
public class ServiceDependencyDAO {
  private static final Comparator<ManagedDependencyServiceKey> SERVICE_KEY_ORDER =
      Comparator.comparingLong(ManagedDependencyServiceKey::clusterId)
          .thenComparing(ManagedDependencyServiceKey::serviceName);

  @Inject
  private Provider<EntityManager> entityManagerProvider;

  @RequiresSession
  public ServiceDependencyBindingEntity findBinding(String bindingId) {
    return entityManagerProvider.get().find(ServiceDependencyBindingEntity.class, bindingId);
  }

  @RequiresSession
  public ServiceDependencySnapshotEntity findSnapshot(String bindingId, long snapshotVersion) {
    return entityManagerProvider.get().find(ServiceDependencySnapshotEntity.class,
        new ServiceDependencySnapshotEntityPK(bindingId, snapshotVersion));
  }

  @RequiresSession
  public ServiceDependencyOperationEntity findOperation(String operationId) {
    return entityManagerProvider.get().find(ServiceDependencyOperationEntity.class, operationId);
  }

  @RequiresSession
  public ServiceDependencyHostResultEntity findHostResult(String bindingId, long snapshotVersion,
      long operationEpoch, long hostId, String dependencyType, String checkKind) {
    return entityManagerProvider.get().find(ServiceDependencyHostResultEntity.class,
        new ServiceDependencyHostResultEntityPK(
            bindingId, snapshotVersion, operationEpoch, hostId, dependencyType, checkKind));
  }

  @RequiresSession
  public List<ServiceDependencyHostResultEntity> findOutstandingCommands() {
    return entityManagerProvider.get().createNamedQuery(
        "ServiceDependencyHostResultEntity.findOutstanding",
        ServiceDependencyHostResultEntity.class).getResultList();
  }

  @RequiresSession
  public List<ServiceDependencyHostResultEntity> findHostResults(
      String bindingId, long snapshotVersion) {
    return entityManagerProvider.get().createQuery(
        "SELECT result FROM ServiceDependencyHostResultEntity result "
            + "WHERE result.bindingId=:bindingId AND result.snapshotVersion=:snapshotVersion "
            + "ORDER BY result.hostId, result.dependencyType, result.checkKind",
        ServiceDependencyHostResultEntity.class)
        .setParameter("bindingId", bindingId)
        .setParameter("snapshotVersion", snapshotVersion)
        .getResultList();
  }

  @RequiresSession
  public List<ServiceDependencyHostResultEntity> findHostResults(
      String bindingId, long snapshotVersion, long operationEpoch) {
    return entityManagerProvider.get().createQuery(
        "SELECT result FROM ServiceDependencyHostResultEntity result "
            + "WHERE result.bindingId=:bindingId AND result.snapshotVersion=:snapshotVersion "
            + "AND result.operationEpoch=:operationEpoch "
            + "ORDER BY result.hostId, result.dependencyType, result.checkKind",
        ServiceDependencyHostResultEntity.class)
        .setParameter("bindingId", bindingId)
        .setParameter("snapshotVersion", snapshotVersion)
        .setParameter("operationEpoch", operationEpoch)
        .getResultList();
  }

  @RequiresSession
  public List<ServiceDependencyHostResultEntity> findHostResultsByTask(long taskId) {
    return entityManagerProvider.get().createNamedQuery(
        "ServiceDependencyHostResultEntity.findByTask", ServiceDependencyHostResultEntity.class)
        .setParameter("taskId", taskId)
        .getResultList();
  }

  @RequiresSession
  public ServiceDependencyFenceEntity findFence(String bindingId) {
    return entityManagerProvider.get().find(ServiceDependencyFenceEntity.class, bindingId);
  }

  @RequiresSession
  public List<ServiceDependencyBindingEntity> findAllBindings() {
    return entityManagerProvider.get().createQuery(
        "SELECT binding FROM ServiceDependencyBindingEntity binding ORDER BY binding.bindingId",
        ServiceDependencyBindingEntity.class).getResultList();
  }

  @RequiresSession
  public List<ServiceDependencyOperationEntity> findOperations(String bindingId) {
    return entityManagerProvider.get().createNamedQuery(
        "ServiceDependencyOperationEntity.findByBinding", ServiceDependencyOperationEntity.class)
        .setParameter("bindingId", bindingId)
        .getResultList();
  }

  @RequiresSession
  public List<ServiceDependencyBindingEntity> findByConsumer(long clusterId, String serviceName) {
    return entityManagerProvider.get().createNamedQuery(
        "ServiceDependencyBindingEntity.findByConsumer", ServiceDependencyBindingEntity.class)
        .setParameter("clusterId", clusterId)
        .setParameter("serviceName", serviceName)
        .getResultList();
  }

  @RequiresSession
  public List<ServiceDependencyBindingEntity> findByProvider(long clusterId, String serviceName) {
    return entityManagerProvider.get().createNamedQuery(
        "ServiceDependencyBindingEntity.findByProvider", ServiceDependencyBindingEntity.class)
        .setParameter("clusterId", clusterId)
        .setParameter("serviceName", serviceName)
        .getResultList();
  }

  @RequiresSession
  public ServiceDependencyBindingEntity findByConsumerAndType(
      long clusterId, String serviceName, String dependencyType) {
    List<ServiceDependencyBindingEntity> rows = entityManagerProvider.get().createNamedQuery(
        "ServiceDependencyBindingEntity.findByConsumerAndType", ServiceDependencyBindingEntity.class)
        .setParameter("clusterId", clusterId)
        .setParameter("serviceName", serviceName)
        .setParameter("dependencyType", dependencyType)
        .setMaxResults(1)
        .getResultList();
    return rows.isEmpty() ? null : rows.get(0);
  }

  /**
   * Reads the complete approved HBase dependency plan under its service-row
   * publication lock. The returned snapshots are detached immutable values.
   */
  @Transactional
  public Optional<List<ManagedDependencySnapshot>> findApprovedLivePlanSnapshots(
      long consumerClusterId) {
    EntityManager entityManager = entityManagerProvider.get();
    ClusterServiceEntityPK serviceId = new ClusterServiceEntityPK();
    serviceId.setClusterId(consumerClusterId);
    serviceId.setServiceName("HBASE");
    ClusterServiceEntity service = entityManager.find(
        ClusterServiceEntity.class, serviceId, LockModeType.PESSIMISTIC_READ);
    if (service == null) {
      return Optional.empty();
    }
    List<ServiceDependencyBindingEntity> bindings = entityManager.createNamedQuery(
        "ServiceDependencyBindingEntity.findByConsumer", ServiceDependencyBindingEntity.class)
        .setParameter("clusterId", consumerClusterId)
        .setParameter("serviceName", "HBASE")
        .setLockMode(LockModeType.PESSIMISTIC_READ)
        .getResultList();
    if (bindings.isEmpty()) {
      return Optional.empty();
    }
    List<ManagedDependencySnapshot> snapshots = new java.util.ArrayList<>();
    Set<String> types = new java.util.HashSet<>();
    for (ServiceDependencyBindingEntity binding : bindings) {
      boolean reconcilingZooKeeper = "ZOOKEEPER".equals(binding.getDependencyType())
          && "FENCING_UNCERTAIN".equals(binding.getState())
          && "ZOOKEEPER_HANDOFF_RECONCILING".equals(binding.getProvisioningPhase())
          && "DEPENDENCY_ZOOKEEPER_HANDOFF_RECONCILIATION_REQUIRED"
              .equals(binding.getFailureCode());
      if (!types.add(binding.getDependencyType())
          || !"APPROVED".equals(binding.getSnapshotApproval())
          || !Set.of("PROVISIONING", "READY", "FAILED").contains(binding.getState())
              && !reconcilingZooKeeper) {
        throw invalidLivePlan("The active managed HBase dependency state is inconsistent.");
      }
      ServiceDependencySnapshotEntity entity = entityManager.find(
          ServiceDependencySnapshotEntity.class,
          new ServiceDependencySnapshotEntityPK(
              binding.getBindingId(), binding.getDesiredSnapshotVersion()),
          LockModeType.PESSIMISTIC_READ);
      if (entity == null) {
        throw invalidLivePlan("The approved managed HBase dependency snapshot is missing.");
      }
      try {
        ManagedDependencySnapshot snapshot = StageUtils.getGson().fromJson(
            entity.getSnapshotJson(), ManagedDependencySnapshot.class);
        if (snapshot == null
            || !Objects.equals(entity.getSchemaVersion(), snapshot.schemaVersion())
            || !Objects.equals(entity.getSnapshotVersion(), snapshot.snapshotVersion())
            || !binding.getBindingId().equals(snapshot.bindingId().toString())
            || !binding.getDependencyType().equals(snapshot.type().name())
            || !binding.getProviderClusterId().equals(snapshot.providerService().clusterId())
            || !binding.getProviderServiceName().equals(snapshot.providerService().serviceName())
            || !entity.getConsumerFingerprint().equals(snapshot.consumerFingerprint())
            || !entity.getProviderFingerprint().equals(snapshot.providerFingerprint())
            || !binding.getProviderFingerprint().equals(snapshot.providerFingerprint())
            || !entity.getSnapshotFingerprint().equals(snapshot.snapshotFingerprint())) {
          throw invalidLivePlan(
              "The approved managed HBase dependency snapshot requires review.");
        }
        snapshots.add(snapshot);
      } catch (ManagedDependencyIntegrationException e) {
        throw e;
      } catch (RuntimeException e) {
        throw new ManagedDependencyIntegrationException(409,
            "DEPENDENCY_SECURITY_PROOF_UPDATE_REQUIRED",
            "The approved managed HBase dependency snapshot cannot be verified.", e);
      }
    }
    return Optional.of(List.copyOf(snapshots));
  }

  private ManagedDependencyIntegrationException invalidLivePlan(String message) {
    return new ManagedDependencyIntegrationException(409,
        "DEPENDENCY_SECURITY_PROOF_UPDATE_REQUIRED", message);
  }

  /**
   * Locks both service rows in canonical order before publishing the immutable
   * snapshot, initial operation and active binding in one transaction.
   */
  @Transactional
  public void create(ServiceDependencyBindingEntity binding,
      ServiceDependencySnapshotEntity snapshot, ServiceDependencyOperationEntity operation,
      CreationGuard guard) {
    create(binding, snapshot, operation, null, guard);
  }

  @Transactional
  public void create(ServiceDependencyBindingEntity binding,
      ServiceDependencySnapshotEntity snapshot, ServiceDependencyOperationEntity operation,
      ServiceDependencyHostResultEntity initialCommand, CreationGuard guard) {
    Objects.requireNonNull(guard, "guard");
    EntityManager entityManager = entityManagerProvider.get();
    ManagedDependencyServiceKey consumer = new ManagedDependencyServiceKey(
        binding.getConsumerClusterId(), binding.getConsumerServiceName());
    ManagedDependencyServiceKey provider = new ManagedDependencyServiceKey(
        binding.getProviderClusterId(), binding.getProviderServiceName());
    if (SERVICE_KEY_ORDER.compare(consumer, provider) <= 0) {
      lockService(entityManager, consumer);
      lockService(entityManager, provider);
    } else {
      lockService(entityManager, provider);
      lockService(entityManager, consumer);
    }

    lockAndValidateDraft(entityManager, guard.draft());
    lockAndValidateRepositories(entityManager, guard.repositories());
    lockAndValidateServiceVersions(entityManager, guard.services());

    if (entityManager.find(ServiceDependencyFenceEntity.class, binding.getBindingId(),
        LockModeType.PESSIMISTIC_WRITE) != null) {
      throw new IllegalStateException("A detached binding UUID cannot be reused");
    }
    entityManager.persist(binding);
    entityManager.persist(snapshot);
    entityManager.persist(operation);
    if (initialCommand != null) {
      requireCurrentCommandOwner(binding, operation, initialCommand);
      if (!isProviderCommand(initialCommand.getCheckKind())) {
        throw new IllegalArgumentException("The initial dependency command must target its provider");
      }
      binding.setActionHostId(initialCommand.getHostId());
      entityManager.persist(initialCommand);
    }
    entityManager.flush();
  }

  /** Starts a new consumer retry epoch while retaining all prior command evidence. */
  @Transactional
  public LifecycleTransition startRetry(String bindingId, long expectedRowVersion,
      ServiceDependencyOperationEntity requested, int userId) {
    EntityManager entityManager = entityManagerProvider.get();
    ServiceDependencyBindingEntity binding = entityManager.find(
        ServiceDependencyBindingEntity.class, bindingId, LockModeType.PESSIMISTIC_WRITE);
    if (binding == null) {
      throw new StaleApprovalException("The managed dependency binding no longer exists");
    }
    ServiceDependencyOperationEntity existing = entityManager.find(
        ServiceDependencyOperationEntity.class, requested.getOperationId(),
        LockModeType.PESSIMISTIC_WRITE);
    if (existing != null) {
      requireExactLifecycleRetry(binding, existing, requested);
      return new LifecycleTransition(binding, existing, null, false);
    }
    if (!Objects.equals(binding.getRowVersion(), expectedRowVersion)) {
      throw new StaleApprovalException("The managed dependency changed after it was read");
    }
    if (!"FAILED".equals(binding.getState()) || !Boolean.TRUE.equals(binding.getFailureRetryable())) {
      throw new StaleApprovalException("The managed dependency is not in a retryable failed state");
    }
    if (binding.getProviderPreparationHash() == null) {
      throw new StaleApprovalException(
          "Provider preparation cannot be retried under a new identity without fencing review");
    }
    requireNextLifecycleOperation(binding, requested, "RETRY", binding.getDesiredSnapshotVersion());
    entityManager.persist(requested);
    binding.setOperationEpoch(requested.getOperationEpoch());
    binding.setActiveOperationId(requested.getOperationId());
    binding.setActiveRequestId(null);
    binding.setState("PROVISIONING");
    binding.setProvisioningPhase("PROVIDER_PREPARED");
    binding.setFailureCode(null);
    binding.setFailurePhase(null);
    binding.setFailureMessage(null);
    binding.setFailureRetryable(false);
    binding.setUpdatedByUserId(userId);
    binding.setUpdateTimestamp(System.currentTimeMillis());
    entityManager.flush();
    return new LifecycleTransition(binding, requested, null, true);
  }

  /** Starts provider-journal invalidation only after every prior command is terminal. */
  @Transactional
  public LifecycleTransition startDetach(String bindingId, long expectedRowVersion,
      ServiceDependencyOperationEntity requested, ServiceDependencyHostResultEntity invalidation,
      int userId) {
    EntityManager entityManager = entityManagerProvider.get();
    ServiceDependencyBindingEntity binding = entityManager.find(
        ServiceDependencyBindingEntity.class, bindingId, LockModeType.PESSIMISTIC_WRITE);
    if (binding == null) {
      throw new StaleApprovalException("The managed dependency binding no longer exists");
    }
    ServiceDependencyOperationEntity existing = entityManager.find(
        ServiceDependencyOperationEntity.class, requested.getOperationId(),
        LockModeType.PESSIMISTIC_WRITE);
    if (existing != null) {
      requireExactLifecycleRetry(binding, existing, requested);
      ServiceDependencyHostResultEntity command = entityManager.find(
          ServiceDependencyHostResultEntity.class, commandId(invalidation));
      return new LifecycleTransition(binding, existing, command, false);
    }
    if (!Objects.equals(binding.getRowVersion(), expectedRowVersion)) {
      throw new StaleApprovalException("The managed dependency changed after it was read");
    }
    if (binding.getActionHostId() == null) {
      throw new StaleApprovalException("The provider action host has not been durably pinned");
    }
    long activeCommands = entityManager.createQuery(
        "SELECT COUNT(result) FROM ServiceDependencyHostResultEntity result "
            + "WHERE result.bindingId=:bindingId AND result.operationEpoch=:operationEpoch "
            + "AND result.state IN ('INTENT', 'SCHEDULING', 'DISPATCHED')", Long.class)
        .setParameter("bindingId", bindingId)
        .setParameter("operationEpoch", binding.getOperationEpoch())
        .getSingleResult();
    if (activeCommands != 0) {
      throw new StaleApprovalException(
          "A managed dependency command is still running; retry detach after it is terminal");
    }
    requireNextLifecycleOperation(binding, requested, "DETACH", binding.getDesiredSnapshotVersion());
    requireCurrentCommandOwnerForTransition(binding, requested, invalidation);
    if (!"INVALIDATE_BINDING_EPOCH".equals(invalidation.getCheckKind())
        || !Objects.equals(binding.getActionHostId(), invalidation.getHostId())
        || !Objects.equals(binding.getDependencyType(), invalidation.getDependencyType())) {
      throw new StaleApprovalException("The detach command does not match the active provider fence");
    }
    entityManager.persist(requested);
    entityManager.persist(invalidation);
    binding.setOperationEpoch(requested.getOperationEpoch());
    binding.setActiveOperationId(requested.getOperationId());
    binding.setActiveRequestId(null);
    binding.setState("DETACHING");
    binding.setProvisioningPhase("DETACHING");
    binding.setFailureCode(null);
    binding.setFailurePhase(null);
    binding.setFailureMessage(null);
    binding.setFailureRetryable(false);
    binding.setUpdatedByUserId(userId);
    binding.setUpdateTimestamp(System.currentTimeMillis());
    entityManager.flush();
    return new LifecycleTransition(binding, requested, invalidation, true);
  }

  /** Persists an exact command before its external Ambari request is created. */
  @Transactional
  public ServiceDependencyHostResultEntity planCommand(ServiceDependencyHostResultEntity command) {
    EntityManager entityManager = entityManagerProvider.get();
    ServiceDependencyHostResultEntity result = planCommand(entityManager, command);
    entityManager.flush();
    return result;
  }

  /** Atomically plans a multi-dependency preparation bundle in binding-ID order. */
  @Transactional
  public List<ServiceDependencyHostResultEntity> planCommands(
      List<ServiceDependencyHostResultEntity> commands) {
    EntityManager entityManager = entityManagerProvider.get();
    List<ServiceDependencyHostResultEntity> result = new java.util.ArrayList<>();
    for (ServiceDependencyHostResultEntity command : commands.stream()
        .sorted(Comparator.comparing(ServiceDependencyHostResultEntity::getBindingId))
        .toList()) {
      result.add(planCommand(entityManager, command));
    }
    entityManager.flush();
    return List.copyOf(result);
  }

  private ServiceDependencyHostResultEntity planCommand(EntityManager entityManager,
      ServiceDependencyHostResultEntity command) {
    ServiceDependencyBindingEntity binding = entityManager.find(
        ServiceDependencyBindingEntity.class, command.getBindingId(), LockModeType.PESSIMISTIC_WRITE);
    ServiceDependencyOperationEntity operation = entityManager.find(
        ServiceDependencyOperationEntity.class, command.getOperationId(), LockModeType.PESSIMISTIC_WRITE);
    requireCurrentCommandOwner(binding, operation, command);
    if (isProviderCommand(command.getCheckKind())) {
      if (binding.getActionHostId() == null) {
        binding.setActionHostId(command.getHostId());
      } else if (!binding.getActionHostId().equals(command.getHostId())) {
        throw new StaleApprovalException("A different provider host is already pinned to this binding");
      }
    }
    ServiceDependencyHostResultEntityPK id = commandId(command);
    ServiceDependencyHostResultEntity existing = entityManager.find(
        ServiceDependencyHostResultEntity.class, id, LockModeType.PESSIMISTIC_WRITE);
    if (existing != null) {
      if (!Objects.equals(existing.getOperationId(), command.getOperationId())
          || !Objects.equals(existing.getOperationEpoch(), command.getOperationEpoch())
          || !Objects.equals(existing.getCommandRequestHash(), command.getCommandRequestHash())
          || !Objects.equals(existing.getCommandJson(), command.getCommandJson())
          || !Objects.equals(existing.getComponentName(), command.getComponentName())) {
        throw new StaleApprovalException("A different command already owns this dependency step");
      }
      return existing;
    }
    if ("READY".equals(binding.getState())
        && command.getCheckKind().startsWith("PREPARE_")
        && Set.of("HBASE_MASTER", "HBASE_REGIONSERVER", "HBASE_THRIFT")
            .contains(command.getComponentName())) {
      binding.setState("PROVISIONING");
      binding.setProvisioningPhase("CONSUMER_VERIFYING");
      binding.setFailureCode(null);
      binding.setFailurePhase(null);
      binding.setFailureMessage(null);
      binding.setFailureRetryable(false);
      binding.setUpdateTimestamp(System.currentTimeMillis());
      operation.setState("CONSUMER_VERIFYING");
      operation.setFailureCode(null);
      operation.setFailureMessage(null);
      operation.setUpdateTimestamp(System.currentTimeMillis());
    }
    entityManager.persist(command);
    return command;
  }

  /** Associates a canonical HBase INSTALL task before the action transaction is published. */
  @Transactional
  public boolean associatePreparationTask(ServiceDependencyHostResultEntity expected,
      String actualComponentName, long requestId, long stageId, long taskId) {
    EntityManager entityManager = entityManagerProvider.get();
    ServiceDependencyBindingEntity binding = entityManager.find(
        ServiceDependencyBindingEntity.class, expected.getBindingId(), LockModeType.PESSIMISTIC_WRITE);
    ServiceDependencyOperationEntity operation = entityManager.find(
        ServiceDependencyOperationEntity.class, expected.getOperationId(), LockModeType.PESSIMISTIC_WRITE);
    ServiceDependencyHostResultEntity command = entityManager.find(
        ServiceDependencyHostResultEntity.class, commandId(expected), LockModeType.PESSIMISTIC_WRITE);
    requireCurrentCommandOwner(binding, operation, command);
    if (!Objects.equals(command.getCommandRequestHash(), expected.getCommandRequestHash())
        || !Objects.equals(command.getCommandJson(), expected.getCommandJson())) {
      throw new StaleApprovalException("The HBase task does not match its preparation intent");
    }
    if (!Objects.equals(command.getComponentName(), actualComponentName)) {
      return false;
    }
    if (command.getAmbariTaskId() != null
        && (!command.getAmbariRequestId().equals(requestId)
            || !command.getAmbariStageId().equals(stageId)
            || !command.getAmbariTaskId().equals(taskId))) {
      throw new StaleApprovalException("A different HBase task owns this preparation intent");
    }
    command.setAmbariRequestId(requestId);
    command.setAmbariStageId(stageId);
    command.setAmbariTaskId(taskId);
    command.setState("DISPATCHED");
    command.setCheckTimestamp(System.currentTimeMillis());
    operation.setAmbariRequestId(requestId);
    binding.setActiveRequestId(requestId);
    binding.setUpdateTimestamp(System.currentTimeMillis());
    entityManager.flush();
    return true;
  }

  /** Claims a current command before the dispatcher creates its external Ambari action. */
  @Transactional
  public boolean claimCommandDispatch(ServiceDependencyHostResultEntityPK id) {
    EntityManager entityManager = entityManagerProvider.get();
    ServiceDependencyHostResultEntity reference = entityManager.find(
        ServiceDependencyHostResultEntity.class, id);
    if (reference == null) {
      throw new StaleApprovalException("The persisted dependency command no longer exists");
    }
    ServiceDependencyBindingEntity binding = entityManager.find(
        ServiceDependencyBindingEntity.class, id.getBindingId(), LockModeType.PESSIMISTIC_WRITE);
    ServiceDependencyOperationEntity operation = entityManager.find(
        ServiceDependencyOperationEntity.class, reference.getOperationId(), LockModeType.PESSIMISTIC_WRITE);
    ServiceDependencyHostResultEntity command = entityManager.find(
        ServiceDependencyHostResultEntity.class, id, LockModeType.PESSIMISTIC_WRITE);
    requireCurrentCommandOwner(binding, operation, command);
    if ("SUCCEEDED".equals(command.getState()) || "DISPATCHED".equals(command.getState())) {
      return false;
    }
    if (!"INTENT".equals(command.getState()) && !"SCHEDULING".equals(command.getState())) {
      throw new StaleApprovalException("The dependency command is not dispatchable");
    }
    command.setState("SCHEDULING");
    command.setCheckTimestamp(System.currentTimeMillis());
    entityManager.flush();
    return true;
  }

  /** Records the exact Ambari task created for an already-persisted command intent. */
  @Transactional
  public void markCommandDispatched(ServiceDependencyHostResultEntityPK id,
      long requestId, long stageId, long taskId) {
    EntityManager entityManager = entityManagerProvider.get();
    ServiceDependencyHostResultEntity reference = entityManager.find(
        ServiceDependencyHostResultEntity.class, id);
    if (reference == null) {
      throw new StaleApprovalException("The persisted dependency command no longer exists");
    }
    ServiceDependencyBindingEntity binding = entityManager.find(
        ServiceDependencyBindingEntity.class, id.getBindingId(), LockModeType.PESSIMISTIC_WRITE);
    ServiceDependencyOperationEntity operation = entityManager.find(
        ServiceDependencyOperationEntity.class, reference.getOperationId(), LockModeType.PESSIMISTIC_WRITE);
    ServiceDependencyHostResultEntity command = entityManager.find(
        ServiceDependencyHostResultEntity.class, id, LockModeType.PESSIMISTIC_WRITE);
    requireCurrentCommandOwner(binding, operation, command);
    if ("SUCCEEDED".equals(command.getState())) {
      return;
    }
    if (!"SCHEDULING".equals(command.getState()) && !"DISPATCHED".equals(command.getState())) {
      throw new StaleApprovalException("The dependency command is not dispatchable");
    }
    command.setAmbariRequestId(requestId);
    command.setAmbariStageId(stageId);
    command.setAmbariTaskId(taskId);
    command.setState("DISPATCHED");
    command.setCheckTimestamp(System.currentTimeMillis());
    operation.setAmbariRequestId(requestId);
    operation.setState("DISPATCHED");
    operation.setUpdateTimestamp(System.currentTimeMillis());
    binding.setActiveRequestId(requestId);
    binding.setUpdateTimestamp(System.currentTimeMillis());
    entityManager.flush();
  }

  /**
   * Commits one validated result and its optional successor intent atomically.
   * This prevents restart from observing an applied provider effect without the
   * exact next command or terminal binding state.
   */
  @Transactional
  public void completeCommand(ServiceDependencyHostResultEntityPK id,
      long requestId, long stageId, long taskId, CommandCompletion completion) {
    EntityManager entityManager = entityManagerProvider.get();
    ServiceDependencyHostResultEntity reference = entityManager.find(
        ServiceDependencyHostResultEntity.class, id);
    if (reference == null) {
      throw new StaleApprovalException("The persisted dependency command no longer exists");
    }
    ServiceDependencyBindingEntity binding = entityManager.find(
        ServiceDependencyBindingEntity.class, id.getBindingId(), LockModeType.PESSIMISTIC_WRITE);
    ServiceDependencyOperationEntity operation = entityManager.find(
        ServiceDependencyOperationEntity.class, reference.getOperationId(), LockModeType.PESSIMISTIC_WRITE);
    ServiceDependencyHostResultEntity command = entityManager.find(
        ServiceDependencyHostResultEntity.class, id, LockModeType.PESSIMISTIC_WRITE);
    requireCurrentCommandOwner(binding, operation, command);
    if (command.getResultHash() != null) {
      if (!command.getResultHash().equals(completion.resultHash())) {
        throw new StaleApprovalException("A conflicting result was reported for this dependency command");
      }
      return;
    }
    if (command.getAmbariTaskId() == null
        || !command.getAmbariTaskId().equals(taskId)
        || !command.getAmbariRequestId().equals(requestId)
        || !command.getAmbariStageId().equals(stageId)) {
      throw new StaleApprovalException("The dependency result came from an unowned Ambari task");
    }
    command.setAmbariRequestId(requestId);
    command.setAmbariStageId(stageId);
    command.setAmbariTaskId(taskId);
    command.setResultJson(completion.resultJson());
    command.setResultHash(completion.resultHash());
    command.setState(completion.commandState());
    command.setFailureCode(completion.failureCode());
    command.setFailureMessage(completion.failureMessage());
    command.setCheckTimestamp(System.currentTimeMillis());
    command.setPreparationObservationId(completion.preparationObservationId());
    command.setPreparationRequestHash(completion.preparationRequestHash());
    command.setPreparationObservationFingerprint(completion.preparationObservationFingerprint());
    command.setPackageName(completion.packageName());
    command.setPackageVersion(completion.packageVersion());
    command.setClientSoftwareVersion(completion.clientSoftwareVersion());
    command.setObservedPackageHash(completion.observedPackageHash());
    command.setRenderedConfigHash(completion.renderedConfigHash());
    command.setIdentityFingerprint(completion.identityFingerprint());

    if ("INVALIDATE_BINDING_EPOCH".equals(command.getCheckKind())
        && "SUCCEEDED".equals(completion.commandState())) {
      operation.setState("SUCCEEDED");
      operation.setFailureCode(null);
      operation.setFailureMessage(null);
      operation.setUpdateTimestamp(System.currentTimeMillis());
      finalizeDetach(entityManager, binding);
      entityManager.flush();
      return;
    }

    if (completion.nextCommand() != null) {
      ServiceDependencyHostResultEntity next = completion.nextCommand();
      requireCurrentCommandOwner(binding, operation, next);
      ServiceDependencyHostResultEntity existing = entityManager.find(
          ServiceDependencyHostResultEntity.class, commandId(next), LockModeType.PESSIMISTIC_WRITE);
      if (existing == null) {
        entityManager.persist(next);
      } else if (!Objects.equals(existing.getCommandRequestHash(), next.getCommandRequestHash())
          || !Objects.equals(existing.getCommandJson(), next.getCommandJson())) {
        throw new StaleApprovalException("A different successor command already exists");
      }
    }

    long now = System.currentTimeMillis();
    boolean wasReady = "READY".equals(binding.getState())
        && Objects.equals(binding.getDesiredSnapshotVersion(), binding.getAppliedSnapshotVersion())
        && Objects.equals(binding.getProviderFingerprint(), binding.getAppliedProviderFingerprint());
    boolean affectsReadiness = affectsReadiness(command, completion.readinessHostIds());
    if (!wasReady || affectsReadiness) {
      binding.setState(completion.bindingState());
      binding.setProvisioningPhase(completion.bindingPhase());
      operation.setState(completion.operationState());
      if (completion.providerPreparationHash() != null) {
        binding.setProviderPreparationHash(completion.providerPreparationHash());
      }
      if (completion.appliedSnapshotVersion() != null) {
        binding.setAppliedSnapshotVersion(completion.appliedSnapshotVersion());
      }
      if (completion.appliedProviderFingerprint() != null) {
        binding.setAppliedProviderFingerprint(completion.appliedProviderFingerprint());
      }
      binding.setFailureCode(completion.failureCode());
      binding.setFailurePhase(completion.failurePhase());
      binding.setFailureMessage(completion.failureMessage());
      binding.setFailureRetryable(completion.retryable());
      operation.setFailureCode(completion.failureCode());
      operation.setFailureMessage(completion.failureMessage());
      if (completion.readinessHostIds() != null
          && allRequiredHostsVerified(entityManager, command, completion.readinessHostIds())) {
        binding.setState("READY");
        binding.setProvisioningPhase("READY");
        binding.setAppliedSnapshotVersion(binding.getDesiredSnapshotVersion());
        binding.setAppliedProviderFingerprint(binding.getProviderFingerprint());
        binding.setFailureCode(null);
        binding.setFailurePhase(null);
        binding.setFailureMessage(null);
        binding.setFailureRetryable(false);
        operation.setState("READY");
        operation.setFailureCode(null);
        operation.setFailureMessage(null);
      } else {
        ServiceDependencyHostResultEntity failure = currentFailure(entityManager, command);
        if (failure != null) {
          applyFailure(binding, operation, failure);
        }
      }
    }
    binding.setUpdateTimestamp(now);
    operation.setUpdateTimestamp(now);
    entityManager.flush();
  }

  /** Records invalid terminal task evidence without trusting raw task output. */
  @Transactional
  public void failTaskCommands(long requestId, long stageId, long taskId,
      String failureCode, String failureMessage) {
    EntityManager entityManager = entityManagerProvider.get();
    List<ServiceDependencyHostResultEntity> references = entityManager.createNamedQuery(
        "ServiceDependencyHostResultEntity.findByTask", ServiceDependencyHostResultEntity.class)
        .setParameter("taskId", taskId)
        .getResultList().stream()
        .sorted(java.util.Comparator.comparing(ServiceDependencyHostResultEntity::getBindingId))
        .toList();
    for (ServiceDependencyHostResultEntity reference : references) {
      ServiceDependencyBindingEntity binding = entityManager.find(
          ServiceDependencyBindingEntity.class, reference.getBindingId(),
          LockModeType.PESSIMISTIC_WRITE);
      ServiceDependencyOperationEntity operation = entityManager.find(
          ServiceDependencyOperationEntity.class, reference.getOperationId(),
          LockModeType.PESSIMISTIC_WRITE);
      ServiceDependencyHostResultEntity command = entityManager.find(
          ServiceDependencyHostResultEntity.class, commandId(reference),
          LockModeType.PESSIMISTIC_WRITE);
      try {
        requireCurrentCommandOwner(binding, operation, command);
      } catch (StaleApprovalException e) {
        continue;
      }
      if (command.getResultHash() != null) {
        continue;
      }
      if (!Objects.equals(command.getAmbariRequestId(), requestId)
          || !Objects.equals(command.getAmbariStageId(), stageId)
          || !Objects.equals(command.getAmbariTaskId(), taskId)) {
        continue;
      }
      long now = System.currentTimeMillis();
      command.setState("FAILED");
      command.setFailureCode(failureCode);
      command.setFailureMessage(failureMessage);
      command.setCheckTimestamp(now);
      boolean wasReady = "READY".equals(binding.getState())
          && Objects.equals(binding.getDesiredSnapshotVersion(), binding.getAppliedSnapshotVersion())
          && Objects.equals(binding.getProviderFingerprint(), binding.getAppliedProviderFingerprint());
      if (!wasReady || affectsReadiness(command, null)) {
        applyFailure(binding, operation, currentFailure(entityManager, command));
      }
      binding.setUpdateTimestamp(now);
      operation.setUpdateTimestamp(now);
    }
    entityManager.flush();
  }

  private ServiceDependencyHostResultEntity currentFailure(EntityManager entityManager,
      ServiceDependencyHostResultEntity current) {
    return entityManager.createQuery(
        "SELECT result FROM ServiceDependencyHostResultEntity result "
            + "WHERE result.bindingId=:bindingId AND result.snapshotVersion=:snapshotVersion "
            + "AND result.operationEpoch=:operationEpoch "
            + "AND result.state IN ('FAILED', 'STALE_REJECTED', 'RECONCILIATION_REQUIRED')",
        ServiceDependencyHostResultEntity.class)
        .setParameter("bindingId", current.getBindingId())
        .setParameter("snapshotVersion", current.getSnapshotVersion())
        .setParameter("operationEpoch", current.getOperationEpoch())
        .getResultStream()
        .sorted(Comparator.comparingInt(this::failurePriority)
            .thenComparing(ServiceDependencyHostResultEntity::getCheckTimestamp)
            .thenComparing(ServiceDependencyHostResultEntity::getHostId)
            .thenComparing(ServiceDependencyHostResultEntity::getDependencyType)
            .thenComparing(ServiceDependencyHostResultEntity::getCheckKind))
        .findFirst()
        .orElse(null);
  }

  private int failurePriority(ServiceDependencyHostResultEntity failure) {
    return switch (failure.getState()) {
      case "RECONCILIATION_REQUIRED" -> 0;
      case "STALE_REJECTED" -> 1;
      default -> 2;
    };
  }

  private void applyFailure(ServiceDependencyBindingEntity binding,
      ServiceDependencyOperationEntity operation, ServiceDependencyHostResultEntity failure) {
    boolean reconciliation = "RECONCILIATION_REQUIRED".equals(failure.getState());
    binding.setState(reconciliation ? "FENCING_UNCERTAIN" : "FAILED");
    binding.setProvisioningPhase(reconciliation
        ? "ZOOKEEPER_HANDOFF_RECONCILING" : failure.getCheckKind());
    binding.setFailureCode(failure.getFailureCode());
    binding.setFailurePhase(failure.getCheckKind());
    binding.setFailureMessage(failure.getFailureMessage());
    binding.setFailureRetryable("FAILED".equals(failure.getState()));
    operation.setState(failure.getState());
    operation.setFailureCode(failure.getFailureCode());
    operation.setFailureMessage(failure.getFailureMessage());
  }

  private void finalizeDetach(EntityManager entityManager,
      ServiceDependencyBindingEntity binding) {
    ServiceDependencySnapshotEntity snapshot = entityManager.find(
        ServiceDependencySnapshotEntity.class, new ServiceDependencySnapshotEntityPK(
            binding.getBindingId(), binding.getDesiredSnapshotVersion()));
    if (snapshot == null) {
      throw new StaleApprovalException("The dependency snapshot required for detach is missing");
    }
    ServiceDependencyFenceEntity fence = new ServiceDependencyFenceEntity();
    fence.setBindingId(binding.getBindingId());
    fence.setFinalEpoch(binding.getOperationEpoch());
    fence.setImmutableSpecHash(stateHash(binding.getBindingId(), binding.getDependencyType(),
        Long.toString(binding.getConsumerClusterId()), binding.getConsumerServiceName(),
        Long.toString(binding.getProviderClusterId()), binding.getProviderServiceName(),
        snapshot.getSnapshotFingerprint()));
    fence.setDependencyType(binding.getDependencyType());
    fence.setConsumerClusterId(binding.getConsumerClusterId());
    fence.setConsumerServiceName(binding.getConsumerServiceName());
    fence.setProviderClusterId(binding.getProviderClusterId());
    fence.setProviderServiceName(binding.getProviderServiceName());
    fence.setNamespaceHash(stateHash(binding.getNamespaceRoot(), binding.getNamespaceWal(),
        binding.getNamespaceZnode()));
    ServiceDependencyOperationEntity detachOperation = entityManager.find(
        ServiceDependencyOperationEntity.class, binding.getActiveOperationId());
    if (detachOperation == null || !"DETACH".equals(detachOperation.getOperationKind())) {
      throw new StaleApprovalException("The detach operation identity is missing");
    }
    fence.setDetachOperationId(detachOperation.getOperationId());
    fence.setDetachRequestHash(detachOperation.getRequestHash());
    fence.setDetachedByUserId(binding.getUpdatedByUserId());
    fence.setDetachTimestamp(System.currentTimeMillis());
    entityManager.persist(fence);

    for (ServiceDependencyHostResultEntity result : entityManager.createQuery(
        "SELECT result FROM ServiceDependencyHostResultEntity result "
            + "WHERE result.bindingId=:bindingId", ServiceDependencyHostResultEntity.class)
        .setParameter("bindingId", binding.getBindingId()).getResultList()) {
      entityManager.remove(result);
    }
    for (ServiceDependencyOperationEntity operation : entityManager.createNamedQuery(
        "ServiceDependencyOperationEntity.findByBinding", ServiceDependencyOperationEntity.class)
        .setParameter("bindingId", binding.getBindingId()).getResultList()) {
      entityManager.remove(operation);
    }
    for (ServiceDependencySnapshotEntity historical : entityManager.createQuery(
        "SELECT snapshot FROM ServiceDependencySnapshotEntity snapshot "
            + "WHERE snapshot.bindingId=:bindingId", ServiceDependencySnapshotEntity.class)
        .setParameter("bindingId", binding.getBindingId()).getResultList()) {
      entityManager.remove(historical);
    }
    entityManager.remove(binding);
  }

  private String stateHash(String... values) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      for (String value : values) {
        byte[] bytes = Objects.requireNonNullElse(value, "").getBytes(StandardCharsets.UTF_8);
        digest.update(Integer.toString(bytes.length).getBytes(StandardCharsets.US_ASCII));
        digest.update((byte) ':');
        digest.update(bytes);
      }
      return "sha256:" + HexFormat.of().formatHex(digest.digest());
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is required by the Java runtime", e);
    }
  }

  private boolean affectsReadiness(ServiceDependencyHostResultEntity command,
      Set<Long> requiredHostIds) {
    if (!command.getCheckKind().startsWith("PREPARE_")
        && !command.getCheckKind().startsWith("VERIFY_")) {
      return false;
    }
    if (requiredHostIds != null) {
      return requiredHostIds.contains(command.getHostId());
    }
    return Set.of("HBASE_MASTER", "HBASE_REGIONSERVER", "HBASE_THRIFT")
        .contains(command.getComponentName());
  }

  private boolean allRequiredHostsVerified(EntityManager entityManager,
      ServiceDependencyHostResultEntity command, Set<Long> requiredHostIds) {
    if (requiredHostIds.isEmpty()) {
      return false;
    }
    String verifyKind = "VERIFY_" + command.getDependencyType() + "_CONSUMER";
    String prepareKind = "PREPARE_" + command.getDependencyType() + "_CONSUMER";
    for (Long hostId : requiredHostIds) {
      ServiceDependencyHostResultEntity verification = entityManager.find(
          ServiceDependencyHostResultEntity.class, new ServiceDependencyHostResultEntityPK(
              command.getBindingId(), command.getSnapshotVersion(), command.getOperationEpoch(), hostId,
              command.getDependencyType(), verifyKind));
      ServiceDependencyHostResultEntity preparation = entityManager.find(
          ServiceDependencyHostResultEntity.class, new ServiceDependencyHostResultEntityPK(
              command.getBindingId(), command.getSnapshotVersion(), command.getOperationEpoch(), hostId,
              command.getDependencyType(), prepareKind));
      if (!isStrictCurrentPair(command, preparation, verification)) {
        return false;
      }
    }
    return true;
  }

  private boolean isStrictCurrentPair(ServiceDependencyHostResultEntity current,
      ServiceDependencyHostResultEntity preparation,
      ServiceDependencyHostResultEntity verification) {
    return preparation != null && verification != null
        && "SUCCEEDED".equals(preparation.getState())
        && "SUCCEEDED".equals(verification.getState())
        && preparation.getPreparationObservationId() != null
        && preparation.getCommandRequestHash() != null
        && preparation.getPreparationObservationFingerprint() != null
        && preparation.getPackageName() != null
        && preparation.getPackageVersion() != null
        && preparation.getClientSoftwareVersion() != null
        && preparation.getObservedPackageHash() != null
        && preparation.getRenderedConfigHash() != null
        && preparation.getIdentityFingerprint() != null
        && Objects.equals(current.getOperationId(), preparation.getOperationId())
        && Objects.equals(current.getOperationId(), verification.getOperationId())
        && Objects.equals(current.getOperationEpoch(), preparation.getOperationEpoch())
        && Objects.equals(current.getOperationEpoch(), verification.getOperationEpoch())
        && Objects.equals(preparation.getCommandRequestHash(),
            verification.getPreparationRequestHash())
        && Objects.equals(preparation.getPreparationObservationId(),
            verification.getPreparationObservationId())
        && Objects.equals(preparation.getPreparationObservationFingerprint(),
            verification.getPreparationObservationFingerprint())
        && Objects.equals(preparation.getPackageName(), verification.getPackageName())
        && Objects.equals(preparation.getPackageVersion(), verification.getPackageVersion())
        && Objects.equals(preparation.getClientSoftwareVersion(),
            verification.getClientSoftwareVersion())
        && Objects.equals(preparation.getObservedPackageHash(),
            verification.getObservedPackageHash())
        && Objects.equals(preparation.getRenderedConfigHash(), verification.getRenderedConfigHash())
        && Objects.equals(preparation.getIdentityFingerprint(), verification.getIdentityFingerprint())
        && verification.getObservedPackageHash() != null;
  }

  private void requireCurrentCommandOwner(ServiceDependencyBindingEntity binding,
      ServiceDependencyOperationEntity operation, ServiceDependencyHostResultEntity command) {
    if (binding == null || operation == null || command == null
        || !Objects.equals(binding.getActiveOperationId(), command.getOperationId())
        || !Objects.equals(binding.getOperationEpoch(), command.getOperationEpoch())
        || !Objects.equals(binding.getDesiredSnapshotVersion(), command.getSnapshotVersion())
        || !Objects.equals(operation.getBindingId(), command.getBindingId())
        || !Objects.equals(operation.getOperationEpoch(), command.getOperationEpoch())
        || !Objects.equals(operation.getTargetSnapshotVersion(), command.getSnapshotVersion())
        || "DETACHING".equals(binding.getState()) || "RETIRED".equals(binding.getState())) {
      throw new StaleApprovalException("The dependency command no longer owns the active operation");
    }
  }

  private void requireNextLifecycleOperation(ServiceDependencyBindingEntity binding,
      ServiceDependencyOperationEntity operation, String kind, long snapshotVersion) {
    if (!binding.getBindingId().equals(operation.getBindingId())
        || !kind.equals(operation.getOperationKind())
        || operation.getOperationEpoch() == null
        || operation.getOperationEpoch() != binding.getOperationEpoch() + 1
        || !Objects.equals(operation.getTargetSnapshotVersion(), snapshotVersion)
        || operation.getRequestHash() == null || operation.getRequestHash().isBlank()) {
      throw new StaleApprovalException("The lifecycle operation does not own the next binding epoch");
    }
  }

  private void requireCurrentCommandOwnerForTransition(ServiceDependencyBindingEntity binding,
      ServiceDependencyOperationEntity operation, ServiceDependencyHostResultEntity command) {
    if (command == null || !binding.getBindingId().equals(command.getBindingId())
        || !operation.getOperationId().equals(command.getOperationId())
        || !operation.getOperationEpoch().equals(command.getOperationEpoch())
        || !operation.getTargetSnapshotVersion().equals(command.getSnapshotVersion())
        || !"INVALIDATE_BINDING_EPOCH".equals(command.getCheckKind())
        || !Objects.equals(binding.getActionHostId(), command.getHostId())) {
      throw new StaleApprovalException("The detach command does not own the next binding epoch");
    }
  }

  private void requireExactLifecycleRetry(ServiceDependencyBindingEntity binding,
      ServiceDependencyOperationEntity existing, ServiceDependencyOperationEntity requested) {
    if (!binding.getBindingId().equals(existing.getBindingId())
        || !binding.getActiveOperationId().equals(existing.getOperationId())
        || !Objects.equals(binding.getOperationEpoch(), existing.getOperationEpoch())
        || !Objects.equals(existing.getBindingId(), requested.getBindingId())
        || !Objects.equals(existing.getOperationKind(), requested.getOperationKind())
        || !Objects.equals(existing.getOperationEpoch(), requested.getOperationEpoch())
        || !Objects.equals(existing.getTargetSnapshotVersion(), requested.getTargetSnapshotVersion())
        || !Objects.equals(existing.getRequestHash(), requested.getRequestHash())) {
      throw new StaleApprovalException("The operation UUID belongs to a different lifecycle request");
    }
  }

  private ServiceDependencyHostResultEntityPK commandId(ServiceDependencyHostResultEntity command) {
    return new ServiceDependencyHostResultEntityPK(command.getBindingId(), command.getSnapshotVersion(),
        command.getOperationEpoch(), command.getHostId(), command.getDependencyType(),
        command.getCheckKind());
  }

  private boolean isProviderCommand(String checkKind) {
    return Set.of("PREPARE_BINDING_JOURNAL", "INITIALIZE_BINDING_JOURNAL",
        "PROVISION_HDFS_NAMESPACE", "PROVISION_ZOOKEEPER_NAMESPACE",
        "INVALIDATE_BINDING_EPOCH").contains(checkKind);
  }

  private void lockAndValidateDraft(EntityManager entityManager, DraftGuard guard) {
    if (guard == null) {
      return;
    }
    ScopedWorkflowStateEntity draft = entityManager.find(ScopedWorkflowStateEntity.class,
        guard.scopeKey(), LockModeType.PESSIMISTIC_WRITE);
    if (draft == null || !Objects.equals(draft.getOwnerUserId(), guard.ownerUserId())
        || !Objects.equals(draft.getRevision(), guard.revision())
        || !Objects.equals(draft.getCreatedClusterId(), guard.consumerClusterId())
        || !"CLUSTER_CREATE".equals(draft.getWorkflow())) {
      throw new StaleApprovalException(
          "The cluster creation draft changed after dependency preview");
    }
  }

  private void lockAndValidateRepositories(EntityManager entityManager,
      List<RepositoryGuard> guards) {
    Map<Long, RepositoryGuard> unique = new LinkedHashMap<>();
    guards.stream().sorted(Comparator.comparingLong(RepositoryGuard::rowId))
        .forEach(guard -> unique.putIfAbsent(guard.rowId(), guard));
    for (RepositoryGuard guard : unique.values()) {
      RepositoryVersionEntity repository = entityManager.find(RepositoryVersionEntity.class,
          guard.rowId(), LockModeType.PESSIMISTIC_READ);
      if (repository == null || !Objects.equals(repository.getVersion(), guard.version())
          || repository.isResolved() != guard.resolved()) {
        throw new StaleApprovalException(
            "A repository version changed after dependency preview");
      }
    }
  }

  private void lockAndValidateServiceVersions(EntityManager entityManager,
      List<ServiceVersionGuard> guards) {
    for (ServiceVersionGuard guard : guards.stream().sorted(Comparator
        .comparingLong(ServiceVersionGuard::clusterId)
        .thenComparing(ServiceVersionGuard::serviceName)).toList()) {
      ServiceDesiredStateEntityPK serviceId = new ServiceDesiredStateEntityPK();
      serviceId.setClusterId(guard.clusterId());
      serviceId.setServiceName(guard.serviceName());
      ServiceDesiredStateEntity service = entityManager.find(ServiceDesiredStateEntity.class,
          serviceId, LockModeType.PESSIMISTIC_READ);
      if (service == null || service.getDesiredRepositoryVersion() == null
          || !Objects.equals(service.getDesiredRepositoryVersion().getId(), guard.repositoryRowId())) {
        throw new StaleApprovalException(
            "A service repository target changed after dependency preview");
      }

      List<ServiceComponentDesiredStateEntity> components = entityManager.createQuery(
          "SELECT component FROM ServiceComponentDesiredStateEntity component " +
              "WHERE component.clusterId=:clusterId AND component.serviceName=:serviceName " +
              "ORDER BY component.componentName",
          ServiceComponentDesiredStateEntity.class)
          .setParameter("clusterId", guard.clusterId())
          .setParameter("serviceName", guard.serviceName())
          .setLockMode(LockModeType.PESSIMISTIC_READ)
          .getResultList();
      if (!components.stream().map(ServiceComponentDesiredStateEntity::getComponentName)
          .collect(java.util.stream.Collectors.toSet()).equals(guard.componentNames())
          || components.stream().anyMatch(component -> component.getDesiredRepositoryVersion() == null
              || !Objects.equals(component.getDesiredRepositoryVersion().getId(), guard.repositoryRowId()))) {
        throw new StaleApprovalException(
            "Service component repository targets changed after dependency preview");
      }

      Map<String, String> actualVersions = new TreeMap<>();
      for (HostComponentStateEntity state : entityManager.createQuery(
          "SELECT state FROM HostComponentStateEntity state " +
              "WHERE state.clusterId=:clusterId AND state.serviceName=:serviceName ORDER BY state.id",
          HostComponentStateEntity.class)
          .setParameter("clusterId", guard.clusterId())
          .setParameter("serviceName", guard.serviceName())
          .setLockMode(LockModeType.PESSIMISTIC_READ)
          .getResultList()) {
        if (guard.versionAdvertisedComponents().contains(state.getComponentName())) {
          if (state.getUpgradeState() != org.apache.ambari.server.state.UpgradeState.NONE) {
            throw new StaleApprovalException(
                "A version-advertising component entered an upgrade after dependency preview");
          }
          actualVersions.put(state.getComponentName() + "\u0000" + state.getHostName(),
              state.getVersion());
        }
      }
      if (!actualVersions.equals(guard.observedVersions())) {
        throw new StaleApprovalException(
            "Advertised component versions changed after dependency preview");
      }
    }
  }

  private void lockService(EntityManager entityManager, ManagedDependencyServiceKey key) {
    ClusterServiceEntityPK id = new ClusterServiceEntityPK();
    id.setClusterId(key.clusterId());
    id.setServiceName(key.serviceName());
    if (entityManager.find(ClusterServiceEntity.class, id, LockModeType.PESSIMISTIC_WRITE) == null) {
      throw new StaleApprovalException("A referenced cluster service no longer exists");
    }
  }

  public record CreationGuard(DraftGuard draft, List<RepositoryGuard> repositories,
      List<ServiceVersionGuard> services) {
    public CreationGuard {
      repositories = repositories == null ? List.of() : List.copyOf(repositories);
      services = services == null ? List.of() : List.copyOf(services);
    }
  }

  public record DraftGuard(String scopeKey, int ownerUserId, long revision,
      long consumerClusterId) {
    public DraftGuard {
      Objects.requireNonNull(scopeKey, "scopeKey");
    }
  }

  public record RepositoryGuard(long rowId, String version, boolean resolved) {
    public RepositoryGuard {
      if (rowId <= 0) {
        throw new IllegalArgumentException("A positive repository row ID is required");
      }
      Objects.requireNonNull(version, "version");
    }
  }

  public record ServiceVersionGuard(long clusterId, String serviceName, long repositoryRowId,
      Set<String> componentNames, Set<String> versionAdvertisedComponents,
      Map<String, String> observedVersions) {
    public ServiceVersionGuard {
      if (clusterId <= 0 || repositoryRowId <= 0) {
        throw new IllegalArgumentException("Positive cluster and repository IDs are required");
      }
      Objects.requireNonNull(serviceName, "serviceName");
      componentNames = Set.copyOf(componentNames);
      versionAdvertisedComponents = Set.copyOf(versionAdvertisedComponents);
      observedVersions = Map.copyOf(observedVersions);
    }
  }

  public record LifecycleTransition(ServiceDependencyBindingEntity binding,
      ServiceDependencyOperationEntity operation,
      ServiceDependencyHostResultEntity command, boolean created) {
  }

  public record CommandCompletion(String resultJson, String resultHash, String commandState,
      String failureCode, String failurePhase, String failureMessage, boolean retryable,
      String bindingState, String bindingPhase, String operationState,
      String providerPreparationHash, Long appliedSnapshotVersion,
      String appliedProviderFingerprint, String preparationObservationId,
      String preparationRequestHash, String preparationObservationFingerprint,
      String packageName, String packageVersion, String clientSoftwareVersion,
      String observedPackageHash, String renderedConfigHash, String identityFingerprint,
      Set<Long> readinessHostIds,
      ServiceDependencyHostResultEntity nextCommand) {
    public CommandCompletion {
      Objects.requireNonNull(resultJson, "resultJson");
      Objects.requireNonNull(resultHash, "resultHash");
      Objects.requireNonNull(commandState, "commandState");
      Objects.requireNonNull(bindingState, "bindingState");
      Objects.requireNonNull(operationState, "operationState");
      readinessHostIds = readinessHostIds == null ? null : Set.copyOf(readinessHostIds);
    }
  }

  public static final class StaleApprovalException extends IllegalStateException {
    public StaleApprovalException(String message) {
      super(message);
    }
  }
}
