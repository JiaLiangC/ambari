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
package org.apache.ambari.server.controller.dependencies;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;

import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.RoleCommand;
import org.apache.ambari.server.actionmanager.HostRoleCommand;
import org.apache.ambari.server.actionmanager.Request;
import org.apache.ambari.server.actionmanager.Stage;
import org.apache.ambari.server.orm.dao.ServiceDependencyDAO;
import org.apache.ambari.server.orm.entities.ServiceDependencyBindingEntity;
import org.apache.ambari.server.orm.entities.ServiceDependencyHostResultEntity;
import org.apache.ambari.server.orm.entities.ServiceDependencyOperationEntity;
import org.apache.ambari.server.orm.entities.ServiceDependencySnapshotEntity;
import org.apache.ambari.server.state.Cluster;
import org.apache.ambari.server.state.ServiceComponentHost;
import org.apache.ambari.server.state.ServiceOsSpecific;
import org.apache.ambari.server.utils.StageUtils;

import com.google.gson.reflect.TypeToken;
import com.google.inject.Inject;
import com.google.inject.Singleton;

/** Plans the exact managed client profile transported with HBase host commands. */
@Singleton
public class ManagedDependencyRuntimePlanner {
  public static final String BUNDLE_PARAMETER = "managed_dependency_commands";

  private final ServiceDependencyDAO dependencyDAO;
  private final ManagedDependencyDescriptorResolver descriptorResolver;
  private final ManagedServiceDependencyCoordinator coordinator;

  @Inject
  public ManagedDependencyRuntimePlanner(ServiceDependencyDAO dependencyDAO,
      ManagedDependencyDescriptorResolver descriptorResolver,
      ManagedServiceDependencyCoordinator coordinator) {
    this.dependencyDAO = dependencyDAO;
    this.descriptorResolver = descriptorResolver;
    this.coordinator = coordinator;
  }

  public void augmentHostCommand(Cluster cluster, ServiceComponentHost host,
      RoleCommand roleCommand, Map<String, String> commandParameters,
      Map<String, Map<String, String>> commandConfigurations,
      Set<String> configurationTypeOverrides,
      String repositoryVersion) throws AmbariException {
    if (!"HBASE".equals(host.getServiceName())
        || roleCommand != RoleCommand.INSTALL && roleCommand != RoleCommand.START
            && roleCommand != RoleCommand.RESTART) {
      return;
    }
    List<ServiceDependencyBindingEntity> bindings = new ArrayList<>(
        dependencyDAO.findByConsumer(cluster.getClusterId(), "HBASE"));
    if (bindings.isEmpty()) {
      return;
    }
    bindings.sort(Comparator.comparing(ServiceDependencyBindingEntity::getDependencyType));
    List<Cluster> parents = new ArrayList<>();
    parents.add(cluster);
    bindings.stream().map(ServiceDependencyBindingEntity::getProviderClusterId)
        .distinct().map(descriptorResolver::cluster).forEach(parents::add);
    withClusterReadLocks(parents, 0, () -> {
      augmentHostCommandLocked(cluster, host, roleCommand, commandParameters,
          commandConfigurations, configurationTypeOverrides, repositoryVersion, bindings);
      return null;
    });
  }

  private void augmentHostCommandLocked(Cluster cluster, ServiceComponentHost host,
      RoleCommand roleCommand, Map<String, String> commandParameters,
      Map<String, Map<String, String>> commandConfigurations,
      Set<String> configurationTypeOverrides, String repositoryVersion,
      List<ServiceDependencyBindingEntity> bindings) throws AmbariException {
    for (ServiceDependencyBindingEntity binding : bindings) {
      coordinator.validateDispatchState(binding);
    }

    List<ManagedDependencyCommand> commands = roleCommand == RoleCommand.INSTALL
        ? planPreparations(cluster, host, commandParameters, repositoryVersion, bindings)
        : readyPreparations(cluster, host, bindings);
    if (commands.isEmpty()) {
      throw new AmbariException("Managed dependency preparation is unavailable for this HBase host");
    }
    String identityFingerprint = commands.get(0).parameters().get("identity.fingerprint");
    String consumerUser = commands.get(0).parameters().get("consumer.user");
    ManagedDependencyCommandBundle bundle = ManagedDependencyCommandBundle.of(
        host.getHost().getHostId(), consumerUser, identityFingerprint, commands);
    decorateCommandConfigurations(bundle, commandConfigurations, configurationTypeOverrides);
    commandParameters.put(BUNDLE_PARAMETER, StageUtils.getGson().toJson(bundle));
  }

  /** Applies the approved provider client profile only to this HBase execution command. */
  public void decoratePersistedCommandConfigurations(long hostId, String rawBundle,
      Map<String, Map<String, String>> commandConfigurations,
      Set<String> configurationTypeOverrides) throws AmbariException {
    try {
      ManagedDependencyCommandBundle bundle = StageUtils.getGson().fromJson(
          rawBundle, ManagedDependencyCommandBundle.class);
      if (bundle.hostId() != hostId) {
        throw new AmbariException("Managed dependency preparation targets a different host");
      }
      decorateCommandConfigurations(bundle, commandConfigurations, configurationTypeOverrides);
    } catch (IllegalArgumentException | com.google.gson.JsonParseException e) {
      throw new AmbariException("Managed dependency preparation bundle is invalid", e);
    }
  }

  private void decorateCommandConfigurations(ManagedDependencyCommandBundle bundle,
      Map<String, Map<String, String>> commandConfigurations,
      Set<String> configurationTypeOverrides) throws AmbariException {
    if (commandConfigurations == null || configurationTypeOverrides == null) {
      throw new AmbariException("HBase execution configurations are unavailable");
    }
    for (ManagedDependencyCommand command : bundle.commands()) {
      Map<String, Map<String, String>> client = clientConfig(command);
      merge(commandConfigurations, "hbase-site", client.get("zooKeeperClient"));
      if (command.name() == ManagedDependencyCommand.CommandName.PREPARE_HDFS_CONSUMER) {
        replace(commandConfigurations, "core-site", client.get("coreSite"));
        replace(commandConfigurations, "hdfs-site", client.get("hdfsSite"));
        configurationTypeOverrides.add("core-site");
        configurationTypeOverrides.add("hdfs-site");
        merge(commandConfigurations, "hbase-site", Map.of(
            "hbase.rootdir", command.parameters().get("expected.namespace.root.uri"),
            "hbase.wal.dir", command.parameters().get("expected.namespace.wal.uri")));
      }
      merge(commandConfigurations, "hbase-env", Map.of(
          "hbase_user", command.parameters().get("consumer.user")));
    }
  }

  private Map<String, Map<String, String>> clientConfig(ManagedDependencyCommand command)
      throws AmbariException {
    try {
      Map<String, Map<String, String>> parsed = StageUtils.getGson().fromJson(
          command.parameters().get("client.config.json"),
          new TypeToken<Map<String, Map<String, String>>>() { }.getType());
      if (parsed == null || !parsed.keySet().equals(Set.of(
          "coreSite", "hdfsSite", "zooKeeperClient"))
          || parsed.values().stream().anyMatch(Objects::isNull)) {
        throw new AmbariException("Managed dependency client configuration is invalid");
      }
      return parsed;
    } catch (com.google.gson.JsonParseException e) {
      throw new AmbariException("Managed dependency client configuration is invalid", e);
    }
  }

  private void merge(Map<String, Map<String, String>> configurations,
      String type, Map<String, String> values) {
    if (values == null || values.isEmpty()) {
      return;
    }
    configurations.computeIfAbsent(type, ignored -> new TreeMap<>()).putAll(values);
  }

  private void replace(Map<String, Map<String, String>> configurations,
      String type, Map<String, String> values) {
    configurations.put(type, values == null ? new TreeMap<>() : new TreeMap<>(values));
  }

  private List<ManagedDependencyCommand> planPreparations(Cluster cluster,
      ServiceComponentHost host,
      Map<String, String> commandParameters, String repositoryVersion,
      List<ServiceDependencyBindingEntity> bindings) throws AmbariException {
    if (repositoryVersion == null || repositoryVersion.isBlank()
        || repositoryVersion.indexOf('*') >= 0) {
      throw new AmbariException(
          "Managed dependency preparation requires an exact HBase repository version");
    }
    List<ServiceOsSpecific.Package> packages = StageUtils.getGson().fromJson(
        commandParameters.get("package_list"),
        new TypeToken<List<ServiceOsSpecific.Package>>() { }.getType());
    if (packages == null) {
      throw new AmbariException("Managed dependency preparation requires the exact install package list");
    }

    List<ManagedDependencyCommand> commands = new ArrayList<>();
    List<ServiceDependencyHostResultEntity> intents = new ArrayList<>();
    String preparationComponent = canonicalPreparationComponent(
        cluster, host.getHost().getHostId());
    for (ServiceDependencyBindingEntity binding : bindings) {
      if (!"APPROVED".equals(binding.getSnapshotApproval())
          || binding.getProviderPreparationHash() == null
          || !Set.of("PROVIDER_PREPARED", "CONSUMER_VERIFYING", "READY")
              .contains(binding.getProvisioningPhase())
          || !Set.of("PROVISIONING", "READY").contains(binding.getState())) {
        throw new AmbariException("Managed dependency provider preparation is not complete");
      }
      ServiceDependencySnapshotEntity snapshotEntity = snapshotEntity(binding);
      ManagedDependencySnapshot snapshot = snapshot(snapshotEntity);
      if (snapshot.securityMode() == ManagedDependencySecurityMode.KERBEROS) {
        throw new AmbariException(
            "Secure managed dependency dispatch requires the approved Kerberos integration");
      }
      ServiceDependencyOperationEntity operation = operation(binding);
      String packageName = packageName(packages, binding.getDependencyType(), repositoryVersion);
      String clientVersion = ManagedDependencyType.HDFS.name().equals(binding.getDependencyType())
          ? snapshot.providerVersion().serviceVersion()
          : snapshotEntity.getConsumerServiceVersion();
      String identityFingerprint = identityFingerprint(snapshot);
      ManagedDependencyCommand command = ManagedDependencyCommand.prepareConsumer(snapshot,
          UUID.fromString(operation.getOperationId()), operation.getOperationEpoch(),
          host.getHost().getHostId(), packageName, clientVersion, identityFingerprint);
      intents.add(ManagedDependencyOperationDispatcher.commandEntity(
          command, ManagedDependencyType.valueOf(binding.getDependencyType()),
          host.getHost().getHostId(), preparationComponent));
      commands.add(command);
    }
    dependencyDAO.planCommands(intents);
    return commands;
  }

  /** Associates the canonical per-host preparation owner in the Ambari action transaction. */
  public void associatePreparationTask(HostRoleCommand task) throws AmbariException {
    if (task.getRoleCommand() != RoleCommand.INSTALL) {
      return;
    }
    String rawBundle = task.getExecutionCommandWrapper().getExecutionCommand()
        .getCommandParams().get(BUNDLE_PARAMETER);
    if (rawBundle == null) {
      return;
    }
    ManagedDependencyCommandBundle bundle;
    try {
      bundle = StageUtils.getGson().fromJson(rawBundle, ManagedDependencyCommandBundle.class);
    } catch (RuntimeException e) {
      throw new AmbariException("Managed dependency preparation bundle is invalid", e);
    }
    if (bundle.hostId() != task.getHostId()) {
      throw new AmbariException("Managed dependency preparation task targets a different host");
    }
    List<Cluster> parents = new ArrayList<>();
    String clusterId = task.getExecutionCommandWrapper().getExecutionCommand().getClusterId();
    if (clusterId == null) {
      throw new AmbariException("Managed dependency preparation has no consumer cluster identity");
    }
    parents.add(descriptorResolver.cluster(Long.parseLong(clusterId)));
    bundle.commands().stream()
        .map(command -> Long.parseLong(command.parameters().get("provider.cluster.id")))
        .distinct().map(descriptorResolver::cluster).forEach(parents::add);
    withClusterReadLocks(parents, 0, () -> {
      for (ManagedDependencyCommand command : bundle.commands().stream()
          .sorted(Comparator.comparing(value -> value.envelope().bindingId()))
          .toList()) {
        ServiceDependencyBindingEntity binding = dependencyDAO.findBinding(
            command.envelope().bindingId().toString());
        if (binding == null) {
          throw new AmbariException("Managed dependency preparation parent is missing");
        }
        coordinator.validateDispatchState(binding);
        ServiceDependencyHostResultEntity expected =
            ManagedDependencyOperationDispatcher.commandEntity(command,
                ManagedDependencyType.valueOf(command.parameters().get("provider.service")),
                task.getHostId(), task.getRole().name());
        dependencyDAO.associatePreparationTask(expected, task.getRole().name(),
            task.getRequestId(), task.getStageId(), task.getTaskId());
      }
      return null;
    });
  }

  /** Holds every consumer/provider parent lock through the action publication transaction. */
  public void executeWithPreparationParentLocks(Request request, CheckedAction action)
      throws AmbariException {
    List<Cluster> parents = new ArrayList<>();
    boolean managedPreparation = false;
    for (Stage stage : request.getStages()) {
      for (HostRoleCommand task : stage.getOrderedHostRoleCommands()) {
        if (task.getRoleCommand() != RoleCommand.INSTALL
            || task.getExecutionCommandWrapper() == null
            || task.getExecutionCommandWrapper().getExecutionCommand().getCommandParams() == null) {
          continue;
        }
        String rawBundle = task.getExecutionCommandWrapper().getExecutionCommand()
            .getCommandParams().get(BUNDLE_PARAMETER);
        if (rawBundle == null) {
          continue;
        }
        managedPreparation = true;
        try {
          if (request.getClusterId() == null
              || Long.parseLong(task.getExecutionCommandWrapper().getExecutionCommand()
                  .getClusterId()) != request.getClusterId()) {
            throw new AmbariException(
                "Managed dependency task cluster does not match its request cluster");
          }
        } catch (NumberFormatException | NullPointerException e) {
          throw new AmbariException("Managed dependency task cluster identity is invalid", e);
        }
        ManagedDependencyCommandBundle bundle;
        try {
          bundle = StageUtils.getGson().fromJson(rawBundle, ManagedDependencyCommandBundle.class);
        } catch (RuntimeException e) {
          throw new AmbariException("Managed dependency preparation bundle is invalid", e);
        }
        if (bundle == null) {
          throw new AmbariException("Managed dependency preparation bundle is invalid");
        }
        for (ManagedDependencyCommand command : bundle.commands()) {
          try {
            parents.add(descriptorResolver.cluster(
                Long.parseLong(command.parameters().get("provider.cluster.id"))));
          } catch (RuntimeException e) {
            throw new AmbariException("Managed dependency provider cluster identity is invalid", e);
          }
        }
      }
    }
    if (!managedPreparation) {
      action.run();
      return;
    }
    if (request.getClusterId() == null || request.getClusterId() <= 0) {
      throw new AmbariException("Managed dependency consumer cluster identity is invalid");
    }
    parents.add(descriptorResolver.cluster(request.getClusterId()));
    withClusterReadLocks(parents, 0, () -> {
      action.run();
      return null;
    });
  }

  /** Reuses the exact successful preparation profile for a managed HBase custom command. */
  public String readyPreparationBundle(long consumerClusterId, long hostId)
      throws AmbariException {
    Cluster cluster = descriptorResolver.cluster(consumerClusterId);
    List<ServiceDependencyBindingEntity> bindings = new ArrayList<>(
        dependencyDAO.findByConsumer(consumerClusterId, "HBASE"));
    if (bindings.isEmpty()) {
      return null;
    }
    bindings.sort(Comparator.comparing(ServiceDependencyBindingEntity::getDependencyType));
    List<Cluster> parents = new ArrayList<>();
    parents.add(cluster);
    bindings.stream().map(ServiceDependencyBindingEntity::getProviderClusterId)
        .distinct().map(descriptorResolver::cluster).forEach(parents::add);
    return withClusterReadLocks(parents, 0, () -> {
      for (ServiceDependencyBindingEntity binding : bindings) {
        coordinator.validateDispatchState(binding);
        if (!"READY".equals(binding.getState())) {
          throw new AmbariException("Managed dependency preparation is not ready");
        }
      }
      ServiceComponentHost host = cluster.getService("HBASE").getServiceComponents().values()
          .stream().flatMap(component -> component.getServiceComponentHosts().values().stream())
          .filter(componentHost -> componentHost.getHost().getHostId() == hostId)
          .findFirst().orElseThrow(() -> new AmbariException(
              "Managed dependency preparation targets an unassigned HBase host"));
      List<ManagedDependencyCommand> commands = readyPreparations(cluster, host, bindings);
      ManagedDependencyCommand first = commands.get(0);
      return StageUtils.getGson().toJson(ManagedDependencyCommandBundle.of(hostId,
          first.parameters().get("consumer.user"),
          first.parameters().get("identity.fingerprint"), commands));
    });
  }

  private String canonicalPreparationComponent(Cluster cluster, long hostId)
      throws AmbariException {
    List<String> priority = List.of(
        "HBASE_MASTER", "HBASE_REGIONSERVER", "HBASE_THRIFT", "HBASE_CLIENT");
    Map<String, org.apache.ambari.server.state.ServiceComponent> components =
        cluster.getService("HBASE").getServiceComponents();
    for (String componentName : priority) {
      if (components.containsKey(componentName)
          && components.get(componentName).getServiceComponentHosts().values().stream()
              .anyMatch(candidate -> candidate.getHost().getHostId() == hostId)) {
        return componentName;
      }
    }
    throw new AmbariException("Managed dependency HBase host has no canonical component owner");
  }

  private List<ManagedDependencyCommand> readyPreparations(Cluster cluster, ServiceComponentHost host,
      List<ServiceDependencyBindingEntity> bindings) throws AmbariException {
    Set<Long> daemonHosts = daemonHostIds(cluster);
    for (ServiceDependencyBindingEntity binding : bindings) {
      if (!"READY".equals(binding.getState())
          || !binding.getDesiredSnapshotVersion().equals(binding.getAppliedSnapshotVersion())
          || !binding.getProviderFingerprint().equals(binding.getAppliedProviderFingerprint())) {
        throw new AmbariException("HBase cannot start until every managed dependency is verified");
      }
      String verifyKind = "VERIFY_" + binding.getDependencyType() + "_CONSUMER";
      Set<Long> verifiedHosts = strictlyVerifiedHostIds(binding, verifyKind);
      if (!verifiedHosts.containsAll(daemonHosts)) {
        throw new AmbariException(
            "HBase cannot start until every current daemon host is strictly verified");
      }
    }
    return persistedPreparationCommands(host.getHost().getHostId(), bindings, true);
  }

  private Set<Long> strictlyVerifiedHostIds(ServiceDependencyBindingEntity binding,
      String verifyKind) {
    String prepareKind = "PREPARE_" + binding.getDependencyType() + "_CONSUMER";
    return dependencyDAO.findHostResults(
        binding.getBindingId(), binding.getDesiredSnapshotVersion()).stream()
        .filter(result -> verifyKind.equals(result.getCheckKind()))
        .filter(result -> "SUCCEEDED".equals(result.getState()))
        .filter(result -> Objects.equals(binding.getOperationEpoch(), result.getOperationEpoch()))
        .filter(result -> {
          ServiceDependencyHostResultEntity preparation = dependencyDAO.findHostResult(
              binding.getBindingId(), binding.getDesiredSnapshotVersion(),
              binding.getOperationEpoch(), result.getHostId(),
              binding.getDependencyType(), prepareKind);
          return preparation != null && "SUCCEEDED".equals(preparation.getState())
              && preparation.getPreparationObservationId() != null
              && preparation.getPreparationObservationFingerprint() != null
              && preparation.getPackageName() != null
              && preparation.getPackageVersion() != null
              && preparation.getClientSoftwareVersion() != null
              && preparation.getObservedPackageHash() != null
              && preparation.getRenderedConfigHash() != null
              && preparation.getIdentityFingerprint() != null
              && Objects.equals(binding.getActiveOperationId(), preparation.getOperationId())
              && Objects.equals(binding.getActiveOperationId(), result.getOperationId())
              && Objects.equals(binding.getOperationEpoch(), preparation.getOperationEpoch())
              && Objects.equals(preparation.getCommandRequestHash(),
                  result.getPreparationRequestHash())
              && Objects.equals(preparation.getPreparationObservationId(),
                  result.getPreparationObservationId())
              && Objects.equals(preparation.getPreparationObservationFingerprint(),
                  result.getPreparationObservationFingerprint())
              && Objects.equals(preparation.getPackageName(), result.getPackageName())
              && Objects.equals(preparation.getPackageVersion(), result.getPackageVersion())
              && Objects.equals(preparation.getClientSoftwareVersion(),
                  result.getClientSoftwareVersion())
              && Objects.equals(preparation.getObservedPackageHash(),
                  result.getObservedPackageHash())
              && result.getRenderedConfigHash() != null
              && result.getIdentityFingerprint() != null;
        })
        .map(ServiceDependencyHostResultEntity::getHostId)
        .collect(java.util.stream.Collectors.toSet());
  }

  private Set<Long> daemonHostIds(Cluster cluster) throws AmbariException {
    Set<String> daemonComponents = Set.of(
        "HBASE_MASTER", "HBASE_REGIONSERVER", "HBASE_THRIFT");
    if (!cluster.getServices().containsKey("HBASE")) {
      throw new AmbariException("Managed dependency HBase service is missing");
    }
    Set<Long> hosts = cluster.getService("HBASE").getServiceComponents().values().stream()
        .filter(component -> daemonComponents.contains(component.getName()))
        .flatMap(component -> component.getServiceComponentHosts().values().stream())
        .map(componentHost -> componentHost.getHost().getHostId())
        .collect(java.util.stream.Collectors.toSet());
    if (hosts.isEmpty()) {
      throw new AmbariException("Managed dependency HBase has no daemon host assignments");
    }
    return Set.copyOf(hosts);
  }

  public String persistedPreparationBundle(long consumerClusterId, long hostId)
      throws AmbariException {
    List<ServiceDependencyBindingEntity> bindings = new ArrayList<>(
        dependencyDAO.findByConsumer(consumerClusterId, "HBASE"));
    bindings.sort(Comparator.comparing(ServiceDependencyBindingEntity::getDependencyType));
    List<ManagedDependencyCommand> commands = persistedPreparationCommands(hostId, bindings, false);
    if (commands.isEmpty()) {
      throw new AmbariException("No managed dependency preparation exists for this HBase host");
    }
    ManagedDependencyCommand first = commands.get(0);
    return StageUtils.getGson().toJson(ManagedDependencyCommandBundle.of(hostId,
        first.parameters().get("consumer.user"),
        first.parameters().get("identity.fingerprint"), commands));
  }

  private List<ManagedDependencyCommand> persistedPreparationCommands(long hostId,
      List<ServiceDependencyBindingEntity> bindings, boolean requireSucceeded) throws AmbariException {
    List<ManagedDependencyCommand> commands = new ArrayList<>();
    for (ServiceDependencyBindingEntity binding : bindings) {
      ServiceDependencyHostResultEntity preparation = dependencyDAO.findHostResult(
          binding.getBindingId(), binding.getDesiredSnapshotVersion(), binding.getOperationEpoch(), hostId,
          binding.getDependencyType(), "PREPARE_" + binding.getDependencyType() + "_CONSUMER");
      if (preparation == null || requireSucceeded
          && (preparation.getPreparationObservationId() == null
              || !"SUCCEEDED".equals(preparation.getState())
              || !Objects.equals(binding.getOperationEpoch(), preparation.getOperationEpoch()))) {
        throw new AmbariException(
            "HBase cannot use this host because its dependency preparation is incomplete");
      }
      commands.add(StageUtils.getGson().fromJson(
          preparation.getCommandJson(), ManagedDependencyCommand.class));
    }
    return commands;
  }

  private ServiceDependencySnapshotEntity snapshotEntity(ServiceDependencyBindingEntity binding)
      throws AmbariException {
    ServiceDependencySnapshotEntity entity = dependencyDAO.findSnapshot(
        binding.getBindingId(), binding.getDesiredSnapshotVersion());
    if (entity == null) {
      throw new AmbariException("Managed dependency snapshot is missing");
    }
    return entity;
  }

  private ServiceDependencyOperationEntity operation(ServiceDependencyBindingEntity binding)
      throws AmbariException {
    ServiceDependencyOperationEntity operation = dependencyDAO.findOperation(binding.getActiveOperationId());
    if (operation == null || !binding.getOperationEpoch().equals(operation.getOperationEpoch())) {
      throw new AmbariException("Managed dependency operation is missing or stale");
    }
    return operation;
  }

  private ManagedDependencySnapshot snapshot(ServiceDependencySnapshotEntity entity)
      throws AmbariException {
    try {
      return StageUtils.getGson().fromJson(entity.getSnapshotJson(), ManagedDependencySnapshot.class);
    } catch (RuntimeException e) {
      throw new AmbariException("Managed dependency snapshot is invalid", e);
    }
  }

  private String packageName(List<ServiceOsSpecific.Package> packages, String dependencyType,
      String repositoryVersion) throws AmbariException {
    String prefix = ManagedDependencyType.HDFS.name().equals(dependencyType) ? "hadoop" : "hbase";
    String template = packages.stream().map(ServiceOsSpecific.Package::getName)
        .filter(name -> name != null && name.contains("${stack_version}"))
        .filter(name -> name.startsWith(prefix + "_") || name.startsWith(prefix + "-"))
        .filter(name -> !ManagedDependencyType.HDFS.name().equals(dependencyType)
            || name.endsWith("-client"))
        .findFirst()
        .orElseThrow(() -> new AmbariException(
            "The HBase install plan has no supported managed dependency client package"));
    String delimiter = template.startsWith(prefix + "-") ? "-" : "_";
    String formattedVersion = repositoryVersion.replace(".", delimiter).replace("-", delimiter);
    return template.replace("${stack_version}", formattedVersion);
  }

  private String identityFingerprint(ManagedDependencySnapshot snapshot) {
    return hash(StageUtils.getGson().toJson(snapshot.consumerIdentity()));
  }

  private String hash(String value) {
    try {
      return "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
          .digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is required by the Java runtime", e);
    }
  }

  private <T> T withClusterReadLocks(List<Cluster> candidates, int index,
      CheckedSupplier<T> operation) throws AmbariException {
    List<Cluster> clusters = candidates.stream()
        .collect(java.util.stream.Collectors.toMap(Cluster::getClusterId, value -> value,
            (left, right) -> left, TreeMap::new))
        .values().stream().toList();
    return withOrderedClusterReadLocks(clusters, index, operation);
  }

  private <T> T withOrderedClusterReadLocks(List<Cluster> clusters, int index,
      CheckedSupplier<T> operation) throws AmbariException {
    if (index == clusters.size()) {
      return operation.get();
    }
    try {
      return clusters.get(index).executeUnderReadLock(() -> {
        try {
          return withOrderedClusterReadLocks(clusters, index + 1, operation);
        } catch (AmbariException e) {
          throw new PlannerException(e);
        }
      });
    } catch (PlannerException e) {
      throw e.getCause();
    }
  }

  @FunctionalInterface
  private interface CheckedSupplier<T> {
    T get() throws AmbariException;
  }

  @FunctionalInterface
  public interface CheckedAction {
    void run() throws AmbariException;
  }

  private static final class PlannerException extends RuntimeException {
    private final AmbariException cause;

    private PlannerException(AmbariException cause) {
      super(cause);
      this.cause = cause;
    }

    @Override
    public AmbariException getCause() {
      return cause;
    }
  }
}
