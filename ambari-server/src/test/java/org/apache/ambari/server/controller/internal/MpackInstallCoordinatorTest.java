/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ambari.server.controller.internal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.ambari.server.actionmanager.HostRoleStatus;
import org.apache.ambari.server.api.services.AmbariMetaInfo;
import org.apache.ambari.server.controller.AmbariManagementController;
import org.apache.ambari.server.controller.MpackInstallPlanRequest;
import org.apache.ambari.server.mpack.MpackManager;
import org.apache.ambari.server.orm.dao.RepositoryVersionDAO;
import org.apache.ambari.server.orm.dao.RequestDAO;
import org.apache.ambari.server.orm.entities.RepositoryVersionEntity;
import org.apache.ambari.server.orm.entities.RequestEntity;
import org.apache.ambari.server.orm.entities.StackEntity;
import org.apache.ambari.server.security.TestAuthenticationFactory;
import org.apache.ambari.server.state.Cluster;
import org.apache.ambari.server.state.Clusters;
import org.apache.ambari.server.state.ComponentInfo;
import org.apache.ambari.server.state.Config;
import org.apache.ambari.server.state.Service;
import org.apache.ambari.server.state.ServiceComponent;
import org.apache.ambari.server.state.ServiceInfo;
import org.apache.ambari.server.state.State;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.context.SecurityContextHolder;

public class MpackInstallCoordinatorTest {
  private static final String PLAN_ID = "00000000-0000-4000-8000-000000000001";

  private MpackInstallCoordinator coordinator;
  private AmbariManagementController controller;
  private Cluster cluster;
  private RepositoryVersionEntity repository;
  private RequestDAO requests;

  @Before
  public void setUp() throws Exception {
    SecurityContextHolder.getContext().setAuthentication(TestAuthenticationFactory.createAdministrator());
    coordinator = new MpackInstallCoordinator();
    RepositoryVersionDAO repositories = mock(RepositoryVersionDAO.class);
    setField("repositories", repositories);
    requests = mock(RequestDAO.class);
    setField("requests", requests);

    controller = mock(AmbariManagementController.class);
    Clusters clusters = mock(Clusters.class);
    cluster = mock(Cluster.class);
    when(controller.getClusters()).thenReturn(clusters);
    when(clusters.getCluster("cluster")).thenReturn(cluster);
    when(cluster.getClusterId()).thenReturn(7L);
    when(cluster.getResourceId()).thenReturn(9L);
    when(cluster.getHostNames()).thenReturn(Set.of("host.example"));
    when(cluster.getServices()).thenReturn(Collections.emptyMap());

    StackEntity stack = new StackEntity();
    stack.setStackName("MPACK_fixture");
    stack.setStackVersion("1");
    stack.setMpackId(4L);
    repository = new RepositoryVersionEntity();
    repository.setId(43L);
    repository.setStack(stack);
    when(repositories.findByPK(43L)).thenReturn(repository);

    ComponentInfo component = mock(ComponentInfo.class);
    when(component.getName()).thenReturn("HTTP_ECHO_SERVER");
    when(component.getCardinality()).thenReturn("1");
    ServiceInfo definition = mock(ServiceInfo.class);
    when(definition.getName()).thenReturn("HTTP_ECHO");
    when(definition.getComponents()).thenReturn(List.of(component));
    when(definition.getConfigTypeAttributes()).thenReturn(
        Map.of("http", Collections.emptyMap()));
    AmbariMetaInfo metaInfo = mock(AmbariMetaInfo.class);
    when(metaInfo.getService("MPACK_fixture", "1", "HTTP_ECHO")).thenReturn(definition);
    when(metaInfo.getMpackManager()).thenReturn(mock(MpackManager.class));
    when(controller.getAmbariMetaInfo()).thenReturn(metaInfo);
  }

  @After
  public void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  public void testValidatesCompletePlanWithoutMutation() throws Exception {
    MpackInstallPlanRequest plan = new MpackInstallPlanRequest(43L, "HTTP_ECHO",
        Map.of("HTTP_ECHO_SERVER", List.of("host.example")),
        Map.of("http", Map.of("port", "18080")), true);
    Map<String, Object> result = coordinator.apply(controller, "cluster", PLAN_ID, plan);
    assertEquals("VALIDATED", result.get("state"));
    assertEquals(PLAN_ID, result.get("planId"));
    assertEquals("HTTP_ECHO", result.get("serviceName"));
  }

  @Test
  public void testRejectsUnknownHostBeforeMutation() {
    MpackInstallPlanRequest plan = new MpackInstallPlanRequest(43L, "HTTP_ECHO",
        Map.of("HTTP_ECHO_SERVER", List.of("other.example")), Collections.emptyMap(), true);
    assertThrows(IllegalArgumentException.class,
        () -> coordinator.apply(controller, "cluster", PLAN_ID, plan));
  }

  @Test
  public void testRepeatedExecutedPlanReturnsExistingAmbariRequest() throws Exception {
    Service service = mock(Service.class);
    when(service.getDesiredRepositoryVersion()).thenReturn(repository);
    when(service.getDesiredState()).thenReturn(State.INSTALLED);
    when(service.getServiceComponents()).thenReturn(Collections.emptyMap());
    when(cluster.getServices()).thenReturn(Map.of("HTTP_ECHO", service));
    String context = "Mpack install " + PLAN_ID + " HTTP_ECHO 43";
    RequestEntity existing = new RequestEntity();
    existing.setRequestId(91L);
    existing.setStatus(HostRoleStatus.IN_PROGRESS);
    when(requests.findLatestByClusterAndContext(7L, context)).thenReturn(existing);
    MpackInstallPlanRequest plan = new MpackInstallPlanRequest(43L, "HTTP_ECHO",
        Map.of("HTTP_ECHO_SERVER", List.of("host.example")), Collections.emptyMap(), false);

    Map<String, Object> result = coordinator.apply(controller, "cluster", PLAN_ID, plan);

    assertEquals(91L, result.get("requestId"));
    assertEquals("IN_PROGRESS", result.get("state"));
    assertEquals(true, result.get("resumed"));
  }

  @Test
  public void testRejectsReusedPlanIdWithDifferentConfiguration() {
    Config existing = mock(Config.class);
    when(existing.getProperties()).thenReturn(Map.of("port", "19090"));
    String tag = "mpack-43-" + PLAN_ID;
    when(cluster.getConfigsByType("http")).thenReturn(Map.of(tag, existing));
    MpackInstallPlanRequest plan = new MpackInstallPlanRequest(43L, "HTTP_ECHO",
        Map.of("HTTP_ECHO_SERVER", List.of("host.example")),
        Map.of("http", Map.of("port", "18080")), true);

    assertThrows(IllegalStateException.class,
        () -> coordinator.apply(controller, "cluster", PLAN_ID, plan));
  }

  @Test
  public void testRejectsExistingHostOutsidePlan() {
    when(cluster.getHostNames()).thenReturn(Set.of("host.example", "other.example"));
    ServiceComponent component = mock(ServiceComponent.class);
    when(component.getServiceComponentHosts()).thenReturn(
        Collections.singletonMap("other.example", null));
    Service service = mock(Service.class);
    when(service.getDesiredRepositoryVersion()).thenReturn(repository);
    when(service.getDesiredState()).thenReturn(State.INSTALLED);
    when(service.getServiceComponents()).thenReturn(Map.of("HTTP_ECHO_SERVER", component));
    when(cluster.getServices()).thenReturn(Map.of("HTTP_ECHO", service));
    MpackInstallPlanRequest plan = new MpackInstallPlanRequest(43L, "HTTP_ECHO",
        Map.of("HTTP_ECHO_SERVER", List.of("host.example")), Collections.emptyMap(), true);

    assertThrows(IllegalStateException.class,
        () -> coordinator.apply(controller, "cluster", PLAN_ID, plan));
  }

  private void setField(String name, Object value) throws Exception {
    Field field = MpackInstallCoordinator.class.getDeclaredField(name);
    field.setAccessible(true);
    field.set(coordinator, value);
  }
}
