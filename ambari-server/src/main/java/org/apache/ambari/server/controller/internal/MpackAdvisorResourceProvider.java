/**
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
package org.apache.ambari.server.controller.internal;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

import org.apache.ambari.server.StaticallyInject;
import org.apache.ambari.server.api.services.mpackadvisor.MpackAdvisorHelper;
import org.apache.ambari.server.api.services.mpackadvisor.MpackAdvisorRequest;
import org.apache.ambari.server.api.services.mpackadvisor.MpackAdvisorRequest.ComponentContext;
import org.apache.ambari.server.api.services.mpackadvisor.MpackAdvisorRequest.MpackContext;
import org.apache.ambari.server.api.services.mpackadvisor.MpackAdvisorRequest.ServiceContext;
import org.apache.ambari.server.api.services.stackadvisor.StackAdvisorRequest.StackAdvisorRequestType;
import org.apache.ambari.server.configuration.Configuration;
import org.apache.ambari.server.controller.AmbariManagementController;
import org.apache.ambari.server.controller.spi.Request;
import org.apache.ambari.server.controller.spi.Resource;
import org.apache.ambari.server.security.authorization.RoleAuthorization;
import org.apache.ambari.server.state.ChangedConfigInfo;

import com.google.inject.Inject;

/**
 * Shared request parsing for package-aware advisor resources.
 */
@StaticallyInject
public abstract class MpackAdvisorResourceProvider extends AbstractControllerResourceProvider {

  protected static final String HOSTS_PROPERTY_ID = "hosts";
  protected static final String SERVICES_PROPERTY_ID = "services";
  protected static final String ITEMS_PROPERTY_ID = "items";
  protected static final String RECOMMENDATIONS_PROPERTY_ID = "recommendations";
  protected static final String BLUEPRINT_CONFIGURATIONS_PROPERTY_ID =
      "recommendations/blueprint/configurations";
  protected static final String BLUEPRINT_HOST_GROUPS_PROPERTY_ID =
      "recommendations/blueprint/host_groups";
  protected static final String BLUEPRINT_MPACK_INSTANCES_PROPERTY_ID =
      "recommendations/blueprint/mpack_instances";
  protected static final String BINDING_HOST_GROUPS_PROPERTY_ID =
      "recommendations/blueprint_cluster_binding/host_groups";

  private static final String CHANGED_CONFIGURATIONS_PROPERTY_ID = "changed_configurations";
  private static final String USER_CONTEXT_OPERATION_PROPERTY_ID = "user_context/operation";
  private static final String USER_CONTEXT_DETAILS_PROPERTY_ID = "user_context/operation_details";

  protected static MpackAdvisorHelper mpackAdvisorHelper;
  private static Configuration configuration;

  @Inject
  public static void init(MpackAdvisorHelper helper, Configuration serverConfiguration) {
    mpackAdvisorHelper = helper;
    configuration = serverConfiguration;
  }

  protected MpackAdvisorResourceProvider(Resource.Type type, Set<String> propertyIds,
      Map<Resource.Type, String> keyPropertyIds,
      AmbariManagementController managementController) {
    super(type, propertyIds, keyPropertyIds, managementController);
    setRequiredCreateAuthorizations(
        EnumSet.of(RoleAuthorization.AMBARI_MANAGE_STACK_VERSIONS));
  }

  protected abstract String getRequestTypePropertyId();

  protected MpackAdvisorRequest prepareMpackAdvisorRequest(Request request) {
    try {
      StackAdvisorRequestType requestType = StackAdvisorRequestType.fromString(
          stringValue(getRequestProperty(request, getRequestTypePropertyId())));
      List<String> hosts = stringList(getRequestProperty(request, HOSTS_PROPERTY_ID));
      if (hosts.isEmpty()) {
        throw new IllegalArgumentException("At least one host is required");
      }

      List<MpackContext> mpacks = parseMpacks(request);
      if (mpacks.isEmpty()) {
        throw new IllegalArgumentException("At least one mpack instance is required");
      }
      validateUniqueMpackNames(mpacks);

      Map<String, List<ComponentContext>> hostGroups = parseHostGroups(request, mpacks);
      Map<String, Set<String>> bindings = parseBindings(request);
      Map<String, Map<String, Map<String, String>>> configurations =
          parseConfigurations(request.getProperties(), BLUEPRINT_CONFIGURATIONS_PROPERTY_ID + "/");
      List<ChangedConfigInfo> changedConfigurations = requestType
          == StackAdvisorRequestType.CONFIGURATION_DEPENDENCIES
          ? parseChangedConfigurations(request) : Collections.emptyList();
      Map<String, String> userContext = new LinkedHashMap<>();
      putIfPresent(userContext, "operation",
          getRequestProperty(request, USER_CONTEXT_OPERATION_PROPERTY_ID));
      putIfPresent(userContext, "operation_details",
          getRequestProperty(request, USER_CONTEXT_DETAILS_PROPERTY_ID));

      return new MpackAdvisorRequest(requestType, hosts, mpacks, hostGroups, bindings,
          configurations, changedConfigurations, userContext,
          configuration.getGplLicenseAccepted());
    } catch (Exception e) {
      LOG.warn("Error preparing mpack advisor request", e);
      throw new WebApplicationException(Response.status(Response.Status.BAD_REQUEST)
          .entity("Request body is not correct, error: " + e.getMessage()).build());
    }
  }

  @SuppressWarnings("unchecked")
  private List<MpackContext> parseMpacks(Request request) {
    List<MpackContext> result = new ArrayList<>();
    for (Object value : collection(getRequestProperty(request,
        BLUEPRINT_MPACK_INSTANCES_PROPERTY_ID))) {
      Map<String, Object> mpack = (Map<String, Object>) value;
      String name = required(mpack, "name", "Mpack instance name is required");
      String type = required(mpack, "type", "Mpack type is required for " + name);
      String version = required(mpack, "version", "Mpack version is required for " + name);
      List<ServiceContext> services = new ArrayList<>();
      for (Object serviceValue : collection(mpack.get("service_instances"))) {
        Map<String, Object> service = (Map<String, Object>) serviceValue;
        String serviceName = required(service, "name",
            "Service instance name is required for " + name);
        String serviceType = stringValue(service.get("type"));
        if (serviceType == null || serviceType.isBlank()) {
          serviceType = serviceName;
        }
        services.add(new ServiceContext(serviceName, serviceType,
            parseConfigurations(Set.of(service), "configurations/")));
      }
      if (services.isEmpty()) {
        throw new IllegalArgumentException("Mpack instance " + name + " has no services");
      }
      services.sort(java.util.Comparator.comparing(ServiceContext::getName));
      result.add(new MpackContext(name, type, version, services));
    }
    result.sort(java.util.Comparator.comparing(MpackContext::getName));
    return result;
  }

  @SuppressWarnings("unchecked")
  private Map<String, List<ComponentContext>> parseHostGroups(Request request,
      List<MpackContext> mpacks) {
    Map<String, List<ComponentContext>> result = new LinkedHashMap<>();
    String defaultMpack = mpacks.size() == 1 ? mpacks.get(0).getName() : null;
    for (Object value : collection(getRequestProperty(request,
        BLUEPRINT_HOST_GROUPS_PROPERTY_ID))) {
      Map<String, Object> group = (Map<String, Object>) value;
      String name = required(group, "name", "Host group name is required");
      List<ComponentContext> components = new ArrayList<>();
      for (Object componentValue : collection(group.get("components"))) {
        Map<String, Object> component = (Map<String, Object>) componentValue;
        String componentName = required(component, "name",
            "Component name is required in host group " + name);
        String mpackName = stringValue(component.get("mpack_instance"));
        if (mpackName == null) {
          mpackName = defaultMpack;
        }
        if (mpackName == null) {
          throw new IllegalArgumentException("Component " + componentName
              + " must identify its mpack_instance");
        }
        String serviceName = stringValue(component.get("service_instance"));
        components.add(new ComponentContext(componentName, mpackName, serviceName));
      }
      if (result.putIfAbsent(name, components) != null) {
        throw new IllegalArgumentException("Duplicate host group " + name);
      }
    }
    return result;
  }

  @SuppressWarnings("unchecked")
  private Map<String, Set<String>> parseBindings(Request request) {
    Map<String, Set<String>> result = new LinkedHashMap<>();
    for (Object value : collection(getRequestProperty(request,
        BINDING_HOST_GROUPS_PROPERTY_ID))) {
      Map<String, Object> group = (Map<String, Object>) value;
      String name = required(group, "name", "Binding host group name is required");
      Set<String> hosts = new LinkedHashSet<>();
      for (Object hostValue : collection(group.get("hosts"))) {
        String host;
        if (hostValue instanceof Map) {
          host = stringValue(((Map<String, Object>) hostValue).get("fqdn"));
        } else {
          host = stringValue(hostValue);
        }
        if (host == null || host.isBlank()) {
          throw new IllegalArgumentException("Binding host name is required for " + name);
        }
        hosts.add(host);
      }
      if (result.putIfAbsent(name, hosts) != null) {
        throw new IllegalArgumentException("Duplicate binding host group " + name);
      }
    }
    return result;
  }

  @SuppressWarnings("unchecked")
  private List<ChangedConfigInfo> parseChangedConfigurations(Request request) {
    List<ChangedConfigInfo> result = new ArrayList<>();
    for (Object value : collection(getRequestProperty(request,
        CHANGED_CONFIGURATIONS_PROPERTY_ID))) {
      Map<String, Object> changed = (Map<String, Object>) value;
      result.add(new ChangedConfigInfo(stringValue(changed.get("type")),
          stringValue(changed.get("name")), stringValue(changed.get("old_value"))));
    }
    return result;
  }

  private Map<String, Map<String, Map<String, String>>> parseConfigurations(
      Collection<Map<String, Object>> propertyMaps, String prefix) {
    Map<String, Map<String, Map<String, String>>> result = new LinkedHashMap<>();
    for (Map<String, Object> properties : propertyMaps) {
      for (Map.Entry<String, Object> property : properties.entrySet()) {
        if (!property.getKey().startsWith(prefix) || property.getValue() == null) {
          continue;
        }
        String[] path = property.getKey().substring(prefix.length()).split("/", 3);
        if (path.length != 3 || path[0].isBlank() || path[1].isBlank()
            || path[2].isBlank()) {
          throw new IllegalArgumentException("Invalid configuration property path "
              + property.getKey());
        }
        result.computeIfAbsent(path[0], ignored -> new LinkedHashMap<>())
            .computeIfAbsent(path[1], ignored -> new LinkedHashMap<>())
            .put(path[2], String.valueOf(property.getValue()));
      }
    }
    return result;
  }

  private void validateUniqueMpackNames(List<MpackContext> mpacks) {
    Set<String> names = new HashSet<>();
    Set<String> runtimeServiceNames = new HashSet<>();
    for (MpackContext mpack : mpacks) {
      if (!names.add(mpack.getName())) {
        throw new IllegalArgumentException("Duplicate mpack instance " + mpack.getName());
      }
      Set<String> serviceNames = new HashSet<>();
      for (ServiceContext service : mpack.getServices()) {
        if (!service.getName().equals(service.getType())) {
          throw new IllegalArgumentException("Service instance " + service.getName()
              + " cannot alias type " + service.getType()
              + " because runtime service identity is service_name");
        }
        if (!serviceNames.add(service.getName())) {
          throw new IllegalArgumentException("Duplicate service instance "
              + mpack.getName() + "/" + service.getName());
        }
        if (!runtimeServiceNames.add(service.getName())) {
          throw new IllegalArgumentException("Runtime service " + service.getName()
              + " is declared by more than one mpack instance");
        }
      }
    }
  }

  private Object getRequestProperty(Request request, String propertyName) {
    for (Map<String, Object> properties : request.getProperties()) {
      if (properties.containsKey(propertyName)) {
        return properties.get(propertyName);
      }
    }
    return null;
  }

  private Collection<?> collection(Object value) {
    if (value == null) {
      return Collections.emptyList();
    }
    if (!(value instanceof Collection)) {
      throw new IllegalArgumentException("Expected a list but received "
          + value.getClass().getSimpleName());
    }
    return (Collection<?>) value;
  }

  private List<String> stringList(Object value) {
    List<String> result = new ArrayList<>();
    for (Object item : collection(value)) {
      String text = stringValue(item);
      if (text == null || text.isBlank()) {
        throw new IllegalArgumentException("List values must not be blank");
      }
      result.add(text);
    }
    return result;
  }

  private String required(Map<String, Object> values, String key, String message) {
    String value = stringValue(values.get(key));
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(message);
    }
    return value;
  }

  private String stringValue(Object value) {
    return value == null ? null : String.valueOf(value);
  }

  private void putIfPresent(Map<String, String> target, String key, Object value) {
    if (value != null) {
      target.put(key, String.valueOf(value));
    }
  }
}
