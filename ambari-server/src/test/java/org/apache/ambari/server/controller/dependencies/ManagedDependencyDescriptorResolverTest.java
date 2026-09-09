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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.ambari.server.api.services.AmbariMetaInfo;
import org.apache.ambari.server.api.services.PersistKeyValueImpl;
import org.apache.ambari.server.api.services.ScopedWorkflowState;
import org.apache.ambari.server.orm.dao.RepositoryVersionDAO;
import org.apache.ambari.server.orm.dao.ServiceDependencyDAO;
import org.apache.ambari.server.orm.entities.ClusterEntity;
import org.apache.ambari.server.orm.entities.RepositoryVersionEntity;
import org.apache.ambari.server.state.Cluster;
import org.apache.ambari.server.state.ClientConfigFileDefinition;
import org.apache.ambari.server.state.Clusters;
import org.apache.ambari.server.state.CommandScriptDefinition;
import org.apache.ambari.server.state.ComponentInfo;
import org.apache.ambari.server.state.Config;
import org.apache.ambari.server.state.Host;
import org.apache.ambari.server.state.SecurityType;
import org.apache.ambari.server.state.Service;
import org.apache.ambari.server.state.ServiceComponent;
import org.apache.ambari.server.state.ServiceComponentHost;
import org.apache.ambari.server.state.ServiceInfo;
import org.apache.ambari.server.state.StackId;
import org.apache.ambari.server.state.State;
import org.apache.ambari.server.state.UpgradeState;
import org.apache.ambari.server.state.configgroup.ConfigGroup;
import org.junit.jupiter.api.Test;

class ManagedDependencyDescriptorResolverTest {
  private final ManagedDependencyDescriptorResolver resolver =
      new ManagedDependencyDescriptorResolver(null, null, null, null, null);

  @Test
  void freshInitConsumerMayHaveUnknownPackageVersionButInstalledConsumerMayNot() {
    RepositoryVersionEntity repository = mock(RepositoryVersionEntity.class);
    when(repository.getId()).thenReturn(31L);
    when(repository.getVersion()).thenReturn("3.3.0-1");
    ServiceComponentHost host = mock(ServiceComponentHost.class);
    when(host.getUpgradeState()).thenReturn(UpgradeState.NONE);
    when(host.getState()).thenReturn(State.INIT);
    when(host.getDesiredState()).thenReturn(State.INIT);
    when(host.getVersion()).thenReturn(State.UNKNOWN.name());
    ServiceComponent component = mock(ServiceComponent.class);
    when(component.getDesiredRepositoryVersion()).thenReturn(repository);
    when(component.isVersionAdvertised()).thenReturn(true);
    when(component.getServiceComponentHosts()).thenReturn(Map.of("consumer.example.test", host));
    Service service = mock(Service.class);
    when(service.getServiceComponents()).thenReturn(Map.of("HBASE_CLIENT", component));

    assertDoesNotThrow(() -> resolver.validateActiveComponentVersions(service, repository, false));
    ManagedDependencyIntegrationException error = assertThrows(
        ManagedDependencyIntegrationException.class,
        () -> resolver.validateActiveComponentVersions(service, repository, true));
    assertEquals("DEPENDENCY_VERSION_UNSUPPORTED", error.getCode());
  }

  @Test
  void configGroupRejectsProviderSecurityOverrideAndAllowsUnrelatedProperty() {
    Host host = mock(Host.class);
    when(host.getHostName()).thenReturn("provider.example.test");
    Config config = mock(Config.class);
    when(config.getType()).thenReturn("zoo.cfg");
    when(config.getProperties()).thenReturn(Map.of("security.auth_to_local", "RULE:[1:$1]"));
    ConfigGroup group = mock(ConfigGroup.class);
    when(group.getHosts()).thenReturn(Map.of(7L, host));
    when(group.getConfigurations()).thenReturn(Map.of("zoo.cfg", config));
    Cluster cluster = mock(Cluster.class);
    when(cluster.getConfigGroups()).thenReturn(Map.of(3L, group));
    ServiceComponent component = mock(ServiceComponent.class);
    when(component.getServiceComponentHosts()).thenReturn(
        Map.of("provider.example.test", mock(ServiceComponentHost.class)));
    Service service = mock(Service.class);
    when(service.getServiceComponents()).thenReturn(Map.of("ZOOKEEPER_SERVER", component));

    ManagedDependencyIntegrationException error = assertThrows(
        ManagedDependencyIntegrationException.class,
        () -> resolver.validateProviderOverrides(cluster, service, ManagedDependencyType.ZOOKEEPER));
    assertEquals("DEPENDENCY_CONFIG_OVERRIDE_UNSUPPORTED", error.getCode());

    when(config.getProperties()).thenReturn(Map.of("autopurge.purgeInterval", "48"));
    assertDoesNotThrow(
        () -> resolver.validateProviderOverrides(cluster, service, ManagedDependencyType.ZOOKEEPER));
  }

  @Test
  void preservesUnsupportedZooKeeperTransportAndAuthenticationFacts() {
    Set<String> unsupported = resolver.unsupportedZooKeeperFeatures(Map.of(
        "secureClientPort", "2281",
        "authProvider.1", "example.CustomAuthenticationProvider",
        "requireClientAuthScheme", "digest"), true);

    assertTrue(unsupported.contains("zookeeper-tls:secureClientPort"));
    assertTrue(unsupported.contains("zookeeper-custom-auth-provider:authProvider.1"));
    assertTrue(unsupported.contains("zookeeper-custom-client-auth:digest"));
    assertTrue(resolver.unsupportedZooKeeperFeatures(Map.of(
        "authProvider.1", "org.apache.zookeeper.server.auth.SASLAuthenticationProvider",
        "requireClientAuthScheme", "sasl"), true).isEmpty());
    assertFalse(resolver.unsupportedZooKeeperFeatures(Map.of(
        "authProvider.1", "org.apache.zookeeper.server.auth.SASLAuthenticationProvider"),
        false).isEmpty());
  }

  @Test
  void addServicePlanWithoutHbaseMatchesFreshLiveConsumerFingerprint() throws Exception {
    Clusters clusters = mock(Clusters.class);
    AmbariMetaInfo metaInfo = mock(AmbariMetaInfo.class);
    RepositoryVersionDAO repositoryVersionDAO = mock(RepositoryVersionDAO.class);
    ServiceDependencyDAO dependencyDAO = mock(ServiceDependencyDAO.class);
    PersistKeyValueImpl persistKeyValue = mock(PersistKeyValueImpl.class);
    ManagedDependencyDescriptorResolver scopedResolver = new ManagedDependencyDescriptorResolver(
        clusters, metaInfo, repositoryVersionDAO, dependencyDAO, persistKeyValue);

    long clusterId = 27L;
    StackId stack = new StackId("BIGTOP", "3.3.0");
    Cluster cluster = mock(Cluster.class);
    ClusterEntity clusterEntity = new ClusterEntity();
    Map<String, Service> services = new HashMap<>();
    Service existing = mock(Service.class);
    Service hbase = mock(Service.class);
    RepositoryVersionEntity repository = mock(RepositoryVersionEntity.class);
    when(clusters.getClusterById(clusterId)).thenReturn(cluster);
    when(cluster.getClusterId()).thenReturn(clusterId);
    when(cluster.getClusterName()).thenReturn("consumer-a");
    when(cluster.getClusterEntity()).thenReturn(clusterEntity);
    when(cluster.getDesiredStackVersion()).thenReturn(stack);
    when(cluster.getCurrentStackVersion()).thenReturn(stack);
    when(cluster.getSecurityType()).thenReturn(SecurityType.NONE);
    when(cluster.getServices()).thenReturn(services);
    when(cluster.getService("HBASE")).thenReturn(hbase);
    when(existing.getDesiredRepositoryVersion()).thenReturn(repository);
    when(hbase.getDesiredRepositoryVersion()).thenReturn(repository);
    when(hbase.getDesiredState()).thenReturn(State.INIT);
    when(hbase.getServiceComponents()).thenReturn(Map.of());
    when(repository.getId()).thenReturn(31L);
    when(repository.getVersion()).thenReturn("3.3.0-1");
    when(repository.isResolved()).thenReturn(true);
    when(repositoryVersionDAO.findByPK(31L)).thenReturn(repository);
    when(dependencyDAO.findByConsumer(clusterId, "HBASE")).thenReturn(java.util.List.of());
    services.put("HDFS", existing);

    ServiceInfo hbaseInfo = mock(ServiceInfo.class);
    ComponentInfo hbaseClient = mock(ComponentInfo.class);
    when(metaInfo.getService("BIGTOP", "3.3.0", "HBASE")).thenReturn(hbaseInfo);
    when(hbaseInfo.getVersion()).thenReturn("2.4.17");
    when(hbaseInfo.getComponentByName("HBASE_CLIENT")).thenReturn(hbaseClient);
    when(hbaseClient.isClient()).thenReturn(true);
    when(hbaseClient.isVersionAdvertised()).thenReturn(true);
    when(hbaseClient.getCommandScript()).thenReturn(mock(CommandScriptDefinition.class));
    when(hbaseClient.getClientConfigFiles()).thenReturn(
        java.util.List.of(mock(ClientConfigFileDefinition.class)));
    ScopedWorkflowState workflow = new ScopedWorkflowState(9, "alice", "ADD_SERVICE",
        "SERVICES", Map.of("ADD_SERVICE", Map.of("addServiceSteps", Map.of(
            "SERVICES", Map.of("data", Map.of("services", Map.of(
                "HBASE", Map.of("selected", true))))))));
    when(persistKeyValue.getActiveOwnedClusterWorkflowState(
        clusterId, "ADD_SERVICE", 9)).thenReturn(workflow);

    ManagedDependencyDescriptor.Consumer plan = scopedResolver.resolveServicePlan(clusterId, 9);
    services.put("HBASE", hbase);
    ManagedDependencyDescriptor.Consumer live = scopedResolver.resolveService(
        new ManagedDependencyServiceKey(clusterId, "HBASE"));

    ManagedDependencySnapshotValidator validator = new ManagedDependencySnapshotValidator(false);
    assertEquals("SERVICE_PLAN", plan.sourceScope());
    assertEquals(ManagedDependencyDescriptor.ConsumerLifecycle.DRAFT, plan.lifecycle());
    assertEquals(validator.consumerFingerprint(plan), validator.consumerFingerprint(live));
  }
}
