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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Set;

import org.apache.ambari.server.orm.dao.ServiceDependencyDAO;
import org.apache.ambari.server.orm.entities.ServiceDependencyBindingEntity;
import org.apache.ambari.server.state.Cluster;
import org.junit.jupiter.api.Test;

class ManagedDependencyLifecyclePolicyTest {

  @Test
  void providerDeletionRequiresEveryDependentToDetach() {
    ServiceDependencyDAO dao = mock(ServiceDependencyDAO.class);
    Cluster cluster = cluster(11L);
    when(dao.findByProvider(11L, "HDFS")).thenReturn(List.of(binding()));

    ManagedDependencyIntegrationException error = assertThrows(
        ManagedDependencyIntegrationException.class,
        () -> new ManagedDependencyLifecyclePolicy(dao)
            .validateServiceDeletion(cluster, Set.of("HDFS")));

    assertEquals(409, error.getStatus());
    assertEquals("DEPENDENCY_PROVIDER_DELETE_BLOCKED", error.getCode());
  }

  @Test
  void consumerDeletionRequiresDetachButHistoricalFenceDoesNotBlock() {
    ServiceDependencyDAO dao = mock(ServiceDependencyDAO.class);
    Cluster cluster = cluster(11L);
    when(dao.findByProvider(11L, "HBASE")).thenReturn(List.of());
    when(dao.findByConsumer(11L, "HBASE")).thenReturn(List.of(binding()));
    ManagedDependencyLifecyclePolicy policy = new ManagedDependencyLifecyclePolicy(dao);

    ManagedDependencyIntegrationException error = assertThrows(
        ManagedDependencyIntegrationException.class,
        () -> policy.validateServiceDeletion(cluster, Set.of("HBASE")));
    assertEquals("DEPENDENCY_CONSUMER_DELETE_REQUIRES_DETACH", error.getCode());

    when(dao.findByConsumer(11L, "HBASE")).thenReturn(List.of());
    assertDoesNotThrow(() -> policy.validateServiceDeletion(cluster, Set.of("HBASE")));
  }

  @Test
  void bulkDeletionPrevalidatesAllReferences() {
    ServiceDependencyDAO dao = mock(ServiceDependencyDAO.class);
    Cluster cluster = cluster(11L);
    when(dao.findByProvider(11L, "HBASE")).thenReturn(List.of());
    when(dao.findByProvider(11L, "HDFS")).thenReturn(List.of(binding()));
    when(dao.findByConsumer(11L, "HBASE")).thenReturn(List.of());

    ManagedDependencyIntegrationException error = assertThrows(
        ManagedDependencyIntegrationException.class,
        () -> new ManagedDependencyLifecyclePolicy(dao)
            .validateServiceDeletion(cluster, Set.of("HBASE", "HDFS")));

    assertEquals("DEPENDENCY_PROVIDER_DELETE_BLOCKED", error.getCode());
  }

  private Cluster cluster(long id) {
    Cluster cluster = mock(Cluster.class);
    when(cluster.getClusterId()).thenReturn(id);
    return cluster;
  }

  private ServiceDependencyBindingEntity binding() {
    return new ServiceDependencyBindingEntity();
  }
}
