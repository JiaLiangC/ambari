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

package org.apache.ambari.server.api.services;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.apache.ambari.server.api.resources.ResourceInstance;
import org.apache.ambari.server.api.services.parsers.RequestBodyParser;
import org.apache.ambari.server.api.services.serializers.ResultSerializer;
import org.apache.ambari.server.controller.AmbariManagementController;
import org.apache.ambari.server.orm.dao.ClusterDAO;
import org.apache.ambari.server.orm.dao.HostDAO;
import org.apache.ambari.server.state.Clusters;
import org.apache.ambari.server.state.cluster.ClusterFactory;
import org.apache.ambari.server.state.cluster.ClustersImpl;
import org.apache.ambari.server.state.host.HostFactory;
import org.easymock.EasyMock;
import org.junit.Test;

/**
 * Unit tests for ClusterService.
 */
public class ClusterServiceTest extends BaseServiceTest {

  @Test
  public void testAbandonMpackResourceForwardsExactPreconditions() throws Exception {
    Clusters clusters = EasyMock.createNiceMock(Clusters.class);
    AmbariManagementController controller = EasyMock.createMock(AmbariManagementController.class);
    String targetKey = "a".repeat(64);
    EasyMock.expect(controller.abandonMpackResource("cluster one", targetKey, "HTTP_ECHO",
        "host.example", "HTTP_ECHO_SERVER", "00000000-0000-0000-0000-000000000001",
        301L, "PENDING", "ABANDON HTTP_ECHO/HTTP_ECHO_SERVER@host.example",
        "Agent host was retired")).andReturn(Map.of("state", "ABANDONED"));
    EasyMock.replay(controller);
    ClusterService service = new TestClusterService(clusters, "cluster one", controller);
    String body = "{\"MpackResourceAbandonment\":{"
        + "\"serviceName\":\"HTTP_ECHO\",\"hostName\":\"host.example\","
        + "\"componentName\":\"HTTP_ECHO_SERVER\","
        + "\"targetIncarnation\":\"00000000-0000-0000-0000-000000000001\","
        + "\"taskId\":301,\"expectedState\":\"PENDING\","
        + "\"confirmation\":\"ABANDON HTTP_ECHO/HTTP_ECHO_SERVER@host.example\","
        + "\"reason\":\"Agent host was retired\"}}";

    Response response = service.abandonMpackResource(body, "cluster one", targetKey);

    assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
    org.junit.Assert.assertTrue(response.getEntity().toString().contains("ABANDONED"));
    EasyMock.verify(controller);
  }

  @Test
  public void testAbandonMpackResourceRejectsMalformedAndStaleRequests() throws Exception {
    Clusters clusters = EasyMock.createNiceMock(Clusters.class);
    AmbariManagementController controller = EasyMock.createMock(AmbariManagementController.class);
    String targetKey = "a".repeat(64);
    EasyMock.expect(controller.abandonMpackResource(EasyMock.anyString(), EasyMock.anyString(),
        EasyMock.anyString(), EasyMock.anyString(), EasyMock.anyString(), EasyMock.anyString(),
        EasyMock.anyLong(), EasyMock.anyString(), EasyMock.anyString(), EasyMock.anyString()))
        .andThrow(new IllegalStateException("stale"));
    EasyMock.replay(controller);
    ClusterService service = new TestClusterService(clusters, "cluster", controller);

    assertEquals(Response.Status.BAD_REQUEST.getStatusCode(),
        service.abandonMpackResource("{}", "cluster", targetKey).getStatus());
    String complete = "{\"MpackResourceAbandonment\":{"
        + "\"serviceName\":\"S\",\"hostName\":\"H\",\"componentName\":\"C\","
        + "\"targetIncarnation\":\"00000000-0000-0000-0000-000000000001\","
        + "\"taskId\":1,\"expectedState\":\"PENDING\",\"confirmation\":\"x\",\"reason\":\"reason long\"}}";
    assertEquals(Response.Status.CONFLICT.getStatusCode(),
        service.abandonMpackResource(complete, "cluster", targetKey).getStatus());
    EasyMock.verify(controller);
  }


  @Override
  public List<ServiceTestInvocation> getTestInvocations() throws Exception {
    List<ServiceTestInvocation> listInvocations = new ArrayList<>();

    ClusterDAO clusterDAO = EasyMock.createNiceMock(ClusterDAO.class);
    HostDAO hostDAO = EasyMock.createNiceMock(HostDAO.class);

    EasyMock.expect(clusterDAO.findAll()).andReturn(new ArrayList<>()).atLeastOnce();
    EasyMock.expect(hostDAO.findAll()).andReturn(new ArrayList<>()).atLeastOnce();

    EasyMock.replay(clusterDAO, hostDAO);

    Clusters clusters = new TestClusters(clusterDAO, EasyMock.createNiceMock(ClusterFactory.class),
        hostDAO, EasyMock.createNiceMock(HostFactory.class));

    ClusterService clusterService;
    Method m;
    Object[] args;

    //getCluster
    clusterService = new TestClusterService(clusters, "clusterName");
    m = clusterService.getClass().getMethod("getCluster", HttpHeaders.class, UriInfo.class, String.class);
    args = new Object[] {getHttpHeaders(), getUriInfo(), "clusterName"};
    listInvocations.add(new ServiceTestInvocation(Request.Type.GET, clusterService, m, args, null));

    //getClusters
    clusterService = new TestClusterService(clusters, null);
    m = clusterService.getClass().getMethod("getClusters", HttpHeaders.class, UriInfo.class);
    args = new Object[] {getHttpHeaders(), getUriInfo()};
    listInvocations.add(new ServiceTestInvocation(Request.Type.GET, clusterService, m, args, null));

    //createCluster
    clusterService = new TestClusterService(clusters, "clusterName");
    m = clusterService.getClass().getMethod("createCluster", String.class, HttpHeaders.class, UriInfo.class, String.class);
    args = new Object[] {"body", getHttpHeaders(), getUriInfo(), "clusterName"};
    listInvocations.add(new ServiceTestInvocation(Request.Type.POST, clusterService, m, args, "body"));

    //updateCluster
    clusterService = new TestClusterService(clusters, "clusterName");
    m = clusterService.getClass().getMethod("updateCluster", String.class, HttpHeaders.class, UriInfo.class, String.class);
    args = new Object[] {"body", getHttpHeaders(), getUriInfo(), "clusterName"};
    listInvocations.add(new ServiceTestInvocation(Request.Type.PUT, clusterService, m, args, "body"));

    //deleteCluster
    clusterService = new TestClusterService(clusters, "clusterName");
    m = clusterService.getClass().getMethod("deleteCluster", HttpHeaders.class, UriInfo.class, String.class);
    args = new Object[] {getHttpHeaders(), getUriInfo(), "clusterName"};
    listInvocations.add(new ServiceTestInvocation(Request.Type.DELETE, clusterService, m, args, null));

    //createClusterArtifact
    clusterService = new TestClusterService(clusters, "clusterName");
    m = clusterService.getClass().getMethod("createClusterArtifact", String.class, HttpHeaders.class, UriInfo.class, String.class, String.class);
    args = new Object[] {"body", getHttpHeaders(), getUriInfo(), "clusterName", "artifactName"};
    listInvocations.add(new ServiceTestInvocation(Request.Type.POST, clusterService, m, args, "body"));

    //getClusterArtifact
    clusterService = new TestClusterService(clusters, "clusterName");
    m = clusterService.getClass().getMethod("getClusterArtifact", HttpHeaders.class, UriInfo.class, String.class, String.class);
    args = new Object[] {getHttpHeaders(), getUriInfo(), "clusterName", "artifact_name"};
    listInvocations.add(new ServiceTestInvocation(Request.Type.GET, clusterService, m, args, null));

    //getClusterArtifacts
    clusterService = new TestClusterService(clusters, "clusterName");
    m = clusterService.getClass().getMethod("getClusterArtifacts", HttpHeaders.class, UriInfo.class, String.class);
    args = new Object[] {getHttpHeaders(), getUriInfo(), "clusterName"};
    listInvocations.add(new ServiceTestInvocation(Request.Type.GET, clusterService, m, args, null));

    //updateClusterArtifact
    clusterService = new TestClusterService(clusters, "clusterName");
    m = clusterService.getClass().getMethod("updateClusterArtifact", String.class, HttpHeaders.class, UriInfo.class, String.class, String.class);
    args = new Object[] {"body", getHttpHeaders(), getUriInfo(), "clusterName", "artifactName"};
    listInvocations.add(new ServiceTestInvocation(Request.Type.PUT, clusterService, m, args, "body"));

    //updateClusterArtifacts
    clusterService = new TestClusterService(clusters, "clusterName");
    m = clusterService.getClass().getMethod("updateClusterArtifacts", String.class, HttpHeaders.class, UriInfo.class, String.class);
    args = new Object[] {"body", getHttpHeaders(), getUriInfo(), "clusterName"};
    listInvocations.add(new ServiceTestInvocation(Request.Type.PUT, clusterService, m, args, "body"));

    //deleteClusterArtifact
    clusterService = new TestClusterService(clusters, "clusterName");
    m = clusterService.getClass().getMethod("deleteClusterArtifact", String.class, HttpHeaders.class, UriInfo.class, String.class, String.class);
    args = new Object[] {"body", getHttpHeaders(), getUriInfo(), "clusterName", "artifactName"};
    listInvocations.add(new ServiceTestInvocation(Request.Type.DELETE, clusterService, m, args, "body"));

    //deleteClusterArtifacts
    clusterService = new TestClusterService(clusters, "clusterName");
    m = clusterService.getClass().getMethod("deleteClusterArtifacts", String.class, HttpHeaders.class, UriInfo.class, String.class);
    args = new Object[] {"body", getHttpHeaders(), getUriInfo(), "clusterName"};
    listInvocations.add(new ServiceTestInvocation(Request.Type.DELETE, clusterService, m, args, "body"));

    return listInvocations;
  }


  private class TestClusterService extends ClusterService {
    private String m_clusterId;
    private AmbariManagementController m_controller;

    private TestClusterService(Clusters clusters, String clusterId) {
      this(clusters, clusterId, null);
    }

    private TestClusterService(Clusters clusters, String clusterId,
        AmbariManagementController controller) {
      super(clusters);
      m_clusterId = clusterId;
      m_controller = controller;
    }

    @Override
    protected AmbariManagementController getManagementController() {
      return m_controller == null ? super.getManagementController() : m_controller;
    }

    @Override
    ResourceInstance createClusterResource(String clusterName) {
      assertEquals(m_clusterId, clusterName);
      return getTestResource();
    }

    @Override
    ResourceInstance createArtifactResource(String clusterName, String artifactName) {
      assertEquals(m_clusterId, clusterName);
      return getTestResource();
    }

    @Override
    RequestFactory getRequestFactory() {
      return getTestRequestFactory();
    }

    @Override
    protected RequestBodyParser getBodyParser() {
      return getTestBodyParser();
    }

    @Override
    protected ResultSerializer getResultSerializer() {
      return getTestResultSerializer();
    }
  }

  private class TestClusters extends ClustersImpl {
    public TestClusters(ClusterDAO clusterDAO, ClusterFactory clusterFactory, HostDAO hostDAO,
        HostFactory hostFactory) {

      super(clusterDAO, clusterFactory, hostDAO, hostFactory);
    }

    @Override
    public boolean checkPermission(String clusterName, boolean readOnly) {
      return true;
    }
  }

  //todo: test getHostHandler, getServiceHandler, getHostComponentHandler
}
