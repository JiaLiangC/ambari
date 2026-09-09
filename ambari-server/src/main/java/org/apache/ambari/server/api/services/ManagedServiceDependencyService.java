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

import java.util.Map;
import java.util.Set;

import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;

import org.apache.ambari.server.StaticallyInject;
import org.apache.ambari.server.controller.dependencies.ManagedDependencyType;
import org.apache.ambari.server.controller.dependencies.ManagedServiceDependencyCoordinator;
import org.apache.ambari.server.controller.dependencies.ManagedServiceDependencyCoordinator.ConsumerReference;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.inject.Inject;

@StaticallyInject
public class ManagedServiceDependencyService {
  @Inject
  private static ManagedServiceDependencyCoordinator coordinator;

  private final String clusterName;
  private final String serviceName;

  public ManagedServiceDependencyService(String clusterName, String serviceName) {
    this.clusterName = clusterName;
    this.serviceName = serviceName;
  }

  @GET
  public Response list() {
    return ManagedDependencyApiSupport.invoke(
        () -> Map.of("items", coordinator.list(clusterName, serviceName)));
  }

  @GET
  @Path("/candidates")
  public Response candidates(@QueryParam("type") String dependencyType) {
    return ManagedDependencyApiSupport.invoke(() -> {
      long clusterId = coordinator.consumerClusterId(clusterName, serviceName);
      return Map.of("items", coordinator.candidates(ConsumerReference.service(clusterId),
          ManagedDependencyApiSupport.type(dependencyType)));
    });
  }

  @POST
  @Path("/preview")
  public Response preview(String body) {
    return ManagedDependencyApiSupport.invoke(() -> {
      JsonNode root = ManagedDependencyApiSupport.body(body,
          Set.of("binding_id", "dependency_type", "provider"));
      ManagedDependencyType type = ManagedDependencyApiSupport.type(
          ManagedDependencyApiSupport.text(root, "dependency_type"));
      JsonNode provider = ManagedDependencyApiSupport.requiredObject(root, "provider",
          Set.of("cluster_id", "service_name"));
      long clusterId = coordinator.consumerClusterId(clusterName, serviceName);
      return coordinator.preview(ConsumerReference.service(clusterId), type,
          ManagedDependencyApiSupport.provider(provider),
          ManagedDependencyApiSupport.optionalUuid(root, "binding_id"));
    });
  }

  @POST
  public Response create(String body) {
    return ManagedDependencyApiSupport.accepted(() -> coordinator.create(
        clusterName, serviceName, ManagedDependencyApiSupport.createRequest(body)));
  }

  @GET
  @Path("/{bindingId}")
  public Response get(@PathParam("bindingId") String bindingId) {
    return ManagedDependencyApiSupport.invoke(() -> coordinator.get(clusterName, serviceName,
        ManagedDependencyApiSupport.uuid(bindingId)));
  }

  @POST
  @Path("/{bindingId}/actions/retry")
  public Response retry(@PathParam("bindingId") String bindingId, String body) {
    return ManagedDependencyApiSupport.accepted(() -> coordinator.retry(
        clusterName, serviceName, ManagedDependencyApiSupport.uuid(bindingId),
        ManagedDependencyApiSupport.lifecycleRequest(body)));
  }

  @DELETE
  @Path("/{bindingId}")
  public Response detach(@PathParam("bindingId") String bindingId, String body) {
    return ManagedDependencyApiSupport.accepted(() -> coordinator.detach(
        clusterName, serviceName, ManagedDependencyApiSupport.uuid(bindingId),
        ManagedDependencyApiSupport.lifecycleRequest(body)));
  }
}
