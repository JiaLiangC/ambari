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

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.controller.AmbariManagementController;
import org.apache.ambari.server.controller.ClusterRequest;
import org.apache.ambari.server.controller.ConfigurationRequest;
import org.apache.ambari.server.controller.MpackInstallPlanRequest;
import org.apache.ambari.server.controller.RequestStatusResponse;
import org.apache.ambari.server.controller.ServiceComponentHostRequest;
import org.apache.ambari.server.controller.ServiceComponentRequest;
import org.apache.ambari.server.controller.ServiceRequest;
import org.apache.ambari.server.mpack.MpackManager;
import org.apache.ambari.server.orm.dao.RepositoryVersionDAO;
import org.apache.ambari.server.orm.dao.RequestDAO;
import org.apache.ambari.server.orm.entities.RepositoryVersionEntity;
import org.apache.ambari.server.orm.entities.RequestEntity;
import org.apache.ambari.server.security.authorization.AuthorizationException;
import org.apache.ambari.server.security.authorization.AuthorizationHelper;
import org.apache.ambari.server.security.authorization.ResourceType;
import org.apache.ambari.server.security.authorization.RoleAuthorization;
import org.apache.ambari.server.state.Cluster;
import org.apache.ambari.server.state.ComponentInfo;
import org.apache.ambari.server.state.Config;
import org.apache.ambari.server.state.Service;
import org.apache.ambari.server.state.ServiceComponent;
import org.apache.ambari.server.state.ServiceInfo;
import org.apache.ambari.server.state.State;
import org.apache.ambari.server.topology.Cardinality;

import com.google.inject.Inject;
import com.google.inject.Singleton;

/** Validates and applies the formerly browser-orchestrated package install saga. */
@Singleton
public class MpackInstallCoordinator {
  private static final int MAX_ASSIGNMENTS = 10000;
  private static final int MAX_CONFIG_TYPES = 128;
  private static final int MAX_CONFIG_PROPERTIES = 4096;

  @Inject
  private RepositoryVersionDAO repositories;
  @Inject
  private RequestDAO requests;

  public synchronized Map<String, Object> apply(AmbariManagementController controller,
      String clusterName, String planId, MpackInstallPlanRequest plan)
      throws AmbariException, AuthorizationException {
    Context context = validate(controller, clusterName, planId, plan);
    Map<String, Object> result = result(context, planId, "VALIDATED");
    if (plan.isValidateOnly()) {
      return result;
    }

    RequestEntity existingRequest = requests.findLatestByClusterAndContext(
        context.cluster.getClusterId(), context.requestContext);
    if (existingRequest != null) {
      result.put("state", existingRequest.getStatus().name());
      result.put("requestId", existingRequest.getRequestId());
      result.put("resumed", true);
      return result;
    }

    ServiceResourceProvider serviceProvider = (ServiceResourceProvider)
        AbstractControllerResourceProvider.getResourceProvider(
            org.apache.ambari.server.controller.spi.Resource.Type.Service, controller);
    Service service = context.service;
    if (service == null) {
      ServiceRequest request = new ServiceRequest(clusterName, plan.getServiceName(),
          plan.getRepositoryVersionId(), null);
      serviceProvider.createServices(Set.of(request));
      service = context.cluster.getService(plan.getServiceName());
    }

    Set<ServiceComponentRequest> missingComponents = new LinkedHashSet<>();
    for (ComponentInfo component : context.definition.getComponents()) {
      if (!service.getServiceComponents().containsKey(component.getName())) {
        missingComponents.add(new ServiceComponentRequest(
            clusterName, plan.getServiceName(), component.getName(), null));
      }
    }
    if (!missingComponents.isEmpty()) {
      ComponentResourceProvider componentProvider = (ComponentResourceProvider)
          AbstractControllerResourceProvider.getResourceProvider(
              org.apache.ambari.server.controller.spi.Resource.Type.Component, controller);
      componentProvider.createComponents(missingComponents);
    }

    Set<ServiceComponentHostRequest> missingHosts = new LinkedHashSet<>();
    for (Map.Entry<String, List<String>> assignment : plan.getAssignments().entrySet()) {
      ServiceComponent component = service.getServiceComponent(assignment.getKey());
      for (String host : assignment.getValue()) {
        if (!component.getServiceComponentHosts().containsKey(host)) {
          missingHosts.add(new ServiceComponentHostRequest(
              clusterName, plan.getServiceName(), assignment.getKey(), host, null));
        }
      }
    }
    if (!missingHosts.isEmpty()) {
      controller.createHostComponents(missingHosts);
    }

    List<ConfigurationRequest> missingConfigurations = new ArrayList<>();
    for (Map.Entry<String, Map<String, String>> configuration : plan.getConfigurations().entrySet()) {
      String tag = configurationTag(plan, planId);
      Config existing = config(context.cluster, configuration.getKey(), tag);
      if (!context.cluster.getDesiredConfigs().containsKey(configuration.getKey())
          || !tag.equals(context.cluster.getDesiredConfigs().get(configuration.getKey()).getTag())) {
        Map<String, String> properties = existing == null ? configuration.getValue() : Map.of();
        missingConfigurations.add(new ConfigurationRequest(
            clusterName, configuration.getKey(), tag, properties, null));
      }
    }
    if (!missingConfigurations.isEmpty()) {
      ClusterRequest update = new ClusterRequest(
          context.cluster.getClusterId(), clusterName, null, null);
      update.setDesiredConfig(missingConfigurations);
      controller.updateClusters(Set.of(update), Map.of());
    }

    if (service.getDesiredState() == State.STARTED) {
      throw new IllegalStateException("The package service is already running");
    }
    if (service.getDesiredState() != State.INSTALLED) {
      ServiceRequest install = new ServiceRequest(clusterName, plan.getServiceName(), null, "INSTALLED");
      RequestStageContainer stages = serviceProvider.updateServices(null, Set.of(install),
          Map.of(RequestResourceProvider.CONTEXT, context.requestContext), false, false, false);
      if (stages != null) {
        stages.persist();
        RequestStatusResponse status = stages.getRequestStatusResponse();
        result.put("requestId", status.getRequestId());
        result.put("state", "SUBMITTED");
      }
    } else {
      result.put("state", "INSTALLED");
      result.put("resumed", true);
    }
    return result;
  }

  private Context validate(AmbariManagementController controller, String clusterName,
      String planId, MpackInstallPlanRequest plan) throws AmbariException, AuthorizationException {
    if (plan == null || clusterName == null || plan.getRepositoryVersionId() == null
        || plan.getRepositoryVersionId() <= 0 || plan.getServiceName() == null
        || !plan.getServiceName().matches("[A-Za-z][A-Za-z0-9_.-]{0,127}")) {
      throw new IllegalArgumentException("A package repository and service are required");
    }
    try {
      if (!UUID.fromString(planId).toString().equals(planId.toLowerCase())) {
        throw new IllegalArgumentException("Install plan ID is not canonical");
      }
    } catch (RuntimeException invalid) {
      throw new IllegalArgumentException("Install plan ID must be a UUID", invalid);
    }

    Cluster cluster = controller.getClusters().getCluster(clusterName);
    requireAuthorization(cluster, RoleAuthorization.SERVICE_ADD_DELETE_SERVICES);
    requireAuthorization(cluster, RoleAuthorization.HOST_ADD_DELETE_COMPONENTS);
    requireAuthorization(cluster, RoleAuthorization.SERVICE_START_STOP);
    if (!plan.getConfigurations().isEmpty()) {
      requireAuthorization(cluster, RoleAuthorization.SERVICE_MODIFY_CONFIGS);
    }

    RepositoryVersionEntity repository = repositories.findByPK(plan.getRepositoryVersionId());
    if (repository == null || repository.getStack() == null || repository.getStack().getMpackId() == null) {
      throw new IllegalArgumentException("The selected repository is not an imported Mpack release");
    }
    ServiceInfo definition = controller.getAmbariMetaInfo().getService(
        repository.getStackName(), repository.getStackVersion(), plan.getServiceName());
    Map<String, ComponentInfo> components = new LinkedHashMap<>();
    for (ComponentInfo component : definition.getComponents()) {
      components.put(component.getName(), component);
    }
    if (!plan.getAssignments().keySet().equals(components.keySet())) {
      throw new IllegalArgumentException("Assignments must cover every declared component exactly once");
    }
    Set<String> clusterHosts = cluster.getHostNames();
    int assignmentCount = 0;
    for (Map.Entry<String, List<String>> assignment : plan.getAssignments().entrySet()) {
      if (assignment.getValue() == null || assignment.getValue().size() != new HashSet<>(assignment.getValue()).size()
          || !clusterHosts.containsAll(assignment.getValue())) {
        throw new IllegalArgumentException("Assignments contain duplicate or unknown hosts");
      }
      assignmentCount += assignment.getValue().size();
      ComponentInfo component = components.get(assignment.getKey());
      boolean cardinalityMatches = "ALL".equals(component.getCardinality())
          ? assignment.getValue().size() == clusterHosts.size()
          : new Cardinality(component.getCardinality()).isValidCount(assignment.getValue().size());
      if (!cardinalityMatches || assignmentCount > MAX_ASSIGNMENTS) {
        throw new IllegalArgumentException("Component assignment violates its cardinality or size limit");
      }
    }

    if (plan.getConfigurations().size() > MAX_CONFIG_TYPES
        || !definition.getConfigTypeAttributes().keySet().containsAll(plan.getConfigurations().keySet())) {
      throw new IllegalArgumentException("Configurations contain an unknown type or exceed their limit");
    }
    int propertyCount = 0;
    MpackManager manager = controller.getAmbariMetaInfo().getMpackManager();
    for (Map.Entry<String, Map<String, String>> configuration : plan.getConfigurations().entrySet()) {
      if (configuration.getValue() == null) {
        throw new IllegalArgumentException("Configuration properties are required");
      }
      propertyCount += configuration.getValue().size();
      try {
        manager.validateConfiguration(repository.getStack().getMpackId(), plan.getServiceName(),
            configuration.getKey(), configuration.getValue());
      } catch (IOException invalid) {
        throw new IllegalArgumentException("Package configuration is invalid", invalid);
      }
      Config existing = config(cluster, configuration.getKey(), configurationTag(plan, planId));
      if (existing != null && !configuration.getValue().equals(existing.getProperties())) {
        throw new IllegalStateException("The install plan ID is already bound to different configuration");
      }
    }
    if (propertyCount > MAX_CONFIG_PROPERTIES) {
      throw new IllegalArgumentException("Configuration property limit exceeded");
    }

    Service service = cluster.getServices().get(plan.getServiceName());
    if (service != null) {
      RepositoryVersionEntity desiredRepository = service.getDesiredRepositoryVersion();
      if (desiredRepository == null || !plan.getRepositoryVersionId().equals(desiredRepository.getId())) {
        throw new IllegalStateException("The service already belongs to another package release");
      }
      for (Map.Entry<String, ServiceComponent> component : service.getServiceComponents().entrySet()) {
        List<String> expectedHosts = plan.getAssignments().get(component.getKey());
        if (expectedHosts == null
            || !expectedHosts.containsAll(component.getValue().getServiceComponentHosts().keySet())) {
          throw new IllegalStateException("Existing service components conflict with the install plan");
        }
      }
      if (service.getDesiredState() == State.STARTED) {
        throw new IllegalStateException("The package service is already running");
      }
    }
    return new Context(cluster, service, definition,
        "Mpack install " + planId + " " + plan.getServiceName() + " " + plan.getRepositoryVersionId());
  }

  private void requireAuthorization(Cluster cluster, RoleAuthorization authorization)
      throws AuthorizationException {
    if (!AuthorizationHelper.isAuthorized(
        ResourceType.CLUSTER, cluster.getResourceId(), authorization)) {
      throw new AuthorizationException("The package install plan is not authorized");
    }
  }

  private Config config(Cluster cluster, String type, String tag) {
    Map<String, Config> configurations = cluster.getConfigsByType(type);
    return configurations == null ? null : configurations.get(tag);
  }

  private String configurationTag(MpackInstallPlanRequest plan, String planId) {
    return "mpack-" + plan.getRepositoryVersionId() + "-" + planId;
  }

  private Map<String, Object> result(Context context, String planId, String state) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("planId", planId);
    result.put("serviceName", context.definition.getName());
    result.put("state", state);
    return result;
  }

  private static final class Context {
    private final Cluster cluster;
    private final Service service;
    private final ServiceInfo definition;
    private final String requestContext;

    private Context(Cluster cluster, Service service, ServiceInfo definition, String requestContext) {
      this.cluster = cluster;
      this.service = service;
      this.definition = definition;
      this.requestContext = requestContext;
    }
  }
}
