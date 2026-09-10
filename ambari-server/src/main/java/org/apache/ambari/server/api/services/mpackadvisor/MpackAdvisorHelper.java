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
package org.apache.ambari.server.api.services.mpackadvisor;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.api.services.AmbariMetaInfo;
import org.apache.ambari.server.api.services.mpackadvisor.MpackAdvisorRequest.ComponentContext;
import org.apache.ambari.server.api.services.mpackadvisor.MpackAdvisorRequest.MpackContext;
import org.apache.ambari.server.api.services.mpackadvisor.MpackAdvisorRequest.ServiceContext;
import org.apache.ambari.server.api.services.mpackadvisor.MpackValidationResponse.Item;
import org.apache.ambari.server.api.services.stackadvisor.StackAdvisorException;
import org.apache.ambari.server.api.services.stackadvisor.StackAdvisorHelper;
import org.apache.ambari.server.api.services.stackadvisor.StackAdvisorRequest;
import org.apache.ambari.server.api.services.stackadvisor.recommendations.RecommendationResponse;
import org.apache.ambari.server.api.services.stackadvisor.recommendations.RecommendationResponse.BindingHostGroup;
import org.apache.ambari.server.api.services.stackadvisor.recommendations.RecommendationResponse.Blueprint;
import org.apache.ambari.server.api.services.stackadvisor.recommendations.RecommendationResponse.BlueprintClusterBinding;
import org.apache.ambari.server.api.services.stackadvisor.recommendations.RecommendationResponse.BlueprintConfigurations;
import org.apache.ambari.server.api.services.stackadvisor.recommendations.RecommendationResponse.ConfigGroup;
import org.apache.ambari.server.api.services.stackadvisor.recommendations.RecommendationResponse.HostGroup;
import org.apache.ambari.server.api.services.stackadvisor.recommendations.RecommendationResponse.Recommendation;
import org.apache.ambari.server.api.services.stackadvisor.validations.ValidationResponse;
import org.apache.ambari.server.api.services.stackadvisor.validations.ValidationResponse.ValidationItem;
import org.apache.ambari.server.state.ComponentInfo;
import org.apache.ambari.server.state.ServiceInfo;
import org.apache.ambari.server.state.ValueAttributesInfo;

import com.google.inject.Inject;
import com.google.inject.Singleton;

/**
 * Adapts package-aware requests to the current Python 3 stack advisor API.
 * Each mpack is evaluated independently and results are merged only when the
 * advisor outputs agree.
 */
@Singleton
public class MpackAdvisorHelper {

  private final StackAdvisorHelper stackAdvisorHelper;
  private final AmbariMetaInfo metaInfo;
  private final AtomicLong requestIds = new AtomicLong();

  @Inject
  public MpackAdvisorHelper(StackAdvisorHelper stackAdvisorHelper, AmbariMetaInfo metaInfo) {
    this.stackAdvisorHelper = stackAdvisorHelper;
    this.metaInfo = metaInfo;
  }

  public MpackRecommendationResponse recommend(MpackAdvisorRequest request)
      throws MpackAdvisorException {
    validateRequest(request);

    Recommendation combined = new Recommendation();
    Blueprint blueprint = new Blueprint();
    blueprint.setConfigurations(new LinkedHashMap<>());
    blueprint.setHostGroups(new LinkedHashSet<>());
    combined.setBlueprint(blueprint);
    combined.setBlueprintClusterBinding(bindingFrom(request.getHostGroupBindings()));
    combined.setConfigGroups(new LinkedHashSet<>());

    Set<String> services = new LinkedHashSet<>();
    for (MpackContext mpack : orderedMpacks(request)) {
      RecommendationResponse response;
      try {
        response = stackAdvisorHelper.recommend(project(request, mpack));
      } catch (StackAdvisorException | AmbariException e) {
        throw new MpackAdvisorException(String.format(
            "Advisor failed for mpack instance %s (%s-%s)",
            mpack.getName(), mpack.getType(), mpack.getVersion()), e);
      }

      mergeRecommendation(combined, response, mpack);
      mpack.getServices().stream().map(ServiceContext::getType).sorted().forEach(services::add);
    }

    return new MpackRecommendationResponse(requestIds.incrementAndGet(),
        new LinkedHashSet<>(request.getHosts()), services, combined, orderedMpacks(request));
  }

  public MpackValidationResponse validate(MpackAdvisorRequest request)
      throws MpackAdvisorException {
    validateRequest(request);
    List<Item> items = new ArrayList<>();

    for (MpackContext mpack : orderedMpacks(request)) {
      ValidationResponse response;
      try {
        response = stackAdvisorHelper.validate(project(request, mpack));
      } catch (StackAdvisorException e) {
        throw new MpackAdvisorException(String.format(
            "Advisor validation failed for mpack instance %s (%s-%s)",
            mpack.getName(), mpack.getType(), mpack.getVersion()), e);
      }

      if (response != null && response.getItems() != null) {
        response.getItems().stream()
            .sorted(Comparator.comparing(ValidationItem::getType,
                Comparator.nullsFirst(Comparator.naturalOrder()))
                .thenComparing(ValidationItem::getMessage,
                    Comparator.nullsFirst(Comparator.naturalOrder())))
            .forEach(item -> items.add(new Item(mpack,
                findServiceInstance(mpack, item.getComponentName()), item)));
      }
    }

    return new MpackValidationResponse(requestIds.incrementAndGet(), items);
  }

  private StackAdvisorRequest project(MpackAdvisorRequest request, MpackContext mpack)
      throws MpackAdvisorException {
    List<String> services = mpack.getServices().stream()
        .map(ServiceContext::getType)
        .sorted()
        .toList();
    String serviceName = services.stream()
        .filter(service -> !service.endsWith("_CLIENTS"))
        .findFirst()
        .orElseThrow(() -> new MpackAdvisorException(
            "Mpack instance " + mpack.getName() + " has no advisor-capable service"));

    Map<String, Set<String>> hostGroupComponents = new LinkedHashMap<>();
    Map<String, Set<String>> componentHosts = new LinkedHashMap<>();
    request.getHostGroupComponents().forEach((hostGroup, components) -> {
      Set<String> names = new LinkedHashSet<>();
      for (ComponentContext component : components) {
        if (mpack.getName().equals(component.getMpackInstance())) {
          names.add(component.getName());
          componentHosts.computeIfAbsent(component.getName(), ignored -> new LinkedHashSet<>())
              .addAll(request.getHostGroupBindings().getOrDefault(hostGroup, Set.of()));
        }
      }
      if (!names.isEmpty()) {
        hostGroupComponents.put(hostGroup, names);
      }
    });

    Map<String, Map<String, Map<String, String>>> configurations =
        copyConfigurations(request.getConfigurations());
    for (ServiceContext service : mpack.getServices()) {
      mergeInputConfigurations(configurations, service.getConfigurations(),
          mpack.getName() + "/" + service.getName());
    }

    return StackAdvisorRequest.StackAdvisorRequestBuilder
        .forStack(mpack.getType(), mpack.getVersion())
        .ofType(request.getRequestType())
        .forHosts(request.getHosts())
        .forServices(services)
        .forHostComponents(hostGroupComponents)
        .forHostsGroupBindings(request.getHostGroupBindings())
        .withComponentHostsMap(componentHosts)
        .withConfigurations(configurations)
        .withChangedConfigurations(request.getChangedConfigurations())
        .withUserContext(request.getUserContext())
        .withGPLLicenseAccepted(request.getGplLicenseAccepted())
        .withServiceName(serviceName)
        .build();
  }

  private void mergeRecommendation(Recommendation combined, RecommendationResponse response,
      MpackContext mpack) throws MpackAdvisorException {
    if (response == null || response.getRecommendations() == null
        || response.getRecommendations().getBlueprint() == null) {
      throw new MpackAdvisorException("Advisor returned no blueprint for mpack instance "
          + mpack.getName());
    }

    Blueprint source = response.getRecommendations().getBlueprint();
    mergeConfigurations(combined.getBlueprint().getConfigurations(),
        source.getConfigurations(), mpack.getName());
    mergeHostGroups(combined.getBlueprint().getHostGroups(), source.getHostGroups(), mpack);

    Set<ConfigGroup> configGroups = response.getRecommendations().getConfigGroups();
    if (configGroups != null) {
      combined.getConfigGroups().addAll(configGroups);
    }
  }

  private void mergeConfigurations(Map<String, BlueprintConfigurations> target,
      Map<String, BlueprintConfigurations> source, String mpackName)
      throws MpackAdvisorException {
    if (source == null) {
      return;
    }
    for (Map.Entry<String, BlueprintConfigurations> configEntry : source.entrySet()) {
      BlueprintConfigurations targetConfig = target.computeIfAbsent(configEntry.getKey(),
          ignored -> new BlueprintConfigurations());
      BlueprintConfigurations sourceConfig = configEntry.getValue();
      if (sourceConfig == null) {
        continue;
      }

      for (Map.Entry<String, String> property : sourceConfig.getProperties().entrySet()) {
        String existing = targetConfig.getProperties().putIfAbsent(property.getKey(),
            property.getValue());
        if (existing != null && !Objects.equals(existing, property.getValue())) {
          throw new MpackAdvisorException(String.format(
              "Conflicting advisor values for %s/%s while merging mpack instance %s",
              configEntry.getKey(), property.getKey(), mpackName));
        }
      }
      mergeAttributes(targetConfig, sourceConfig, configEntry.getKey(), mpackName);
    }
  }

  private void mergeAttributes(BlueprintConfigurations target, BlueprintConfigurations source,
      String configType, String mpackName) throws MpackAdvisorException {
    if (source.getPropertyAttributes() == null) {
      return;
    }
    if (target.getPropertyAttributes() == null) {
      target.setPropertyAttributes(new HashMap<>());
    }
    for (Map.Entry<String, ValueAttributesInfo> attribute
        : source.getPropertyAttributes().entrySet()) {
      ValueAttributesInfo existing = target.getPropertyAttributes().putIfAbsent(
          attribute.getKey(), attribute.getValue());
      if (existing != null && !Objects.equals(existing, attribute.getValue())) {
        throw new MpackAdvisorException(String.format(
            "Conflicting advisor attributes for %s/%s while merging mpack instance %s",
            configType, attribute.getKey(), mpackName));
      }
    }
  }

  private void mergeHostGroups(Set<HostGroup> target, Set<HostGroup> source,
      MpackContext mpack) throws MpackAdvisorException {
    if (source == null) {
      return;
    }
    Map<String, HostGroup> byName = new LinkedHashMap<>();
    target.forEach(group -> byName.put(group.getName(), group));
    for (HostGroup sourceGroup : source) {
      HostGroup targetGroup = byName.computeIfAbsent(sourceGroup.getName(), name -> {
        HostGroup group = new HostGroup();
        group.setName(name);
        group.setComponents(new LinkedHashSet<>());
        target.add(group);
        return group;
      });
      if (sourceGroup.getComponents() == null) {
        continue;
      }
      for (Map<String, String> sourceComponent : sourceGroup.getComponents()) {
        Map<String, String> component = new LinkedHashMap<>(sourceComponent);
        String componentName = component.get("name");
        component.put("mpack_instance", mpack.getName());
        String service = findServiceInstance(mpack, componentName);
        if (service == null) {
          throw new MpackAdvisorException(String.format(
              "Component %s returned for mpack instance %s has no unique owning service",
              componentName, mpack.getName()));
        }
        component.put("service_instance", service);
        targetGroup.getComponents().add(component);
      }
    }
  }

  private String findServiceInstance(MpackContext mpack, String componentName) {
    if (componentName == null && mpack.getServices().size() == 1) {
      return mpack.getServices().get(0).getName();
    }
    if (componentName == null) {
      return null;
    }
    String match = null;
    for (ServiceContext service : mpack.getServices()) {
      try {
        ServiceInfo info = metaInfo.getService(mpack.getType(), mpack.getVersion(),
            service.getType());
        boolean ownsComponent = info.getComponents().stream()
            .map(ComponentInfo::getName)
            .anyMatch(componentName::equals);
        if (ownsComponent) {
          if (match != null) {
            return null;
          }
          match = service.getName();
        }
      } catch (AmbariException e) {
        return null;
      }
    }
    return match;
  }

  private void validateRequest(MpackAdvisorRequest request) throws MpackAdvisorException {
    if (request == null || request.getRequestType() == null) {
      throw new MpackAdvisorException("Advisor request type is required");
    }
    if (request.getHosts().isEmpty()) {
      throw new MpackAdvisorException("At least one host is required");
    }
    if (request.getMpackInstances().isEmpty()) {
      throw new MpackAdvisorException("At least one mpack instance is required");
    }

    Set<String> hosts = new LinkedHashSet<>(request.getHosts());
    if (hosts.size() != request.getHosts().size()) {
      throw new MpackAdvisorException("Advisor hosts must be unique");
    }
    Map<String, MpackContext> mpacks = new LinkedHashMap<>();
    for (MpackContext mpack : request.getMpackInstances()) {
      mpacks.put(mpack.getName(), mpack);
      for (ServiceContext service : mpack.getServices()) {
        if (!service.getName().equals(service.getType())) {
          throw new MpackAdvisorException(String.format(
              "Service instance %s cannot alias type %s because runtime service identity is service_name",
              service.getName(), service.getType()));
        }
        try {
          metaInfo.getService(mpack.getType(), mpack.getVersion(), service.getType());
        } catch (AmbariException e) {
          throw new MpackAdvisorException(String.format(
              "Unknown service %s for mpack %s-%s",
              service.getType(), mpack.getType(), mpack.getVersion()), e);
        }
      }
    }

    for (Map.Entry<String, List<ComponentContext>> group
        : request.getHostGroupComponents().entrySet()) {
      for (ComponentContext component : group.getValue()) {
        MpackContext mpack = mpacks.get(component.getMpackInstance());
        if (mpack == null) {
          throw new MpackAdvisorException("Unknown mpack instance "
              + component.getMpackInstance() + " for component " + component.getName());
        }
        String owner = findServiceInstance(mpack, component.getName());
        if (owner == null) {
          throw new MpackAdvisorException(String.format(
              "Component %s in host group %s has no unique service owner in mpack instance %s",
              component.getName(), group.getKey(), mpack.getName()));
        }
        if (component.getServiceInstance() != null
            && !owner.equals(component.getServiceInstance())) {
          throw new MpackAdvisorException(String.format(
              "Component %s is owned by service %s, not %s",
              component.getName(), owner, component.getServiceInstance()));
        }
      }
    }

    for (Map.Entry<String, Set<String>> binding : request.getHostGroupBindings().entrySet()) {
      if (!request.getHostGroupComponents().containsKey(binding.getKey())) {
        throw new MpackAdvisorException("Binding references unknown host group " + binding.getKey());
      }
      for (String host : binding.getValue()) {
        if (!hosts.contains(host)) {
          throw new MpackAdvisorException("Host group " + binding.getKey()
              + " references undeclared host " + host);
        }
      }
    }
  }

  private List<MpackContext> orderedMpacks(MpackAdvisorRequest request) {
    return request.getMpackInstances().stream()
        .sorted(Comparator.comparing(MpackContext::getName))
        .toList();
  }

  private BlueprintClusterBinding bindingFrom(Map<String, Set<String>> bindings) {
    BlueprintClusterBinding result = new BlueprintClusterBinding();
    Set<BindingHostGroup> hostGroups = new LinkedHashSet<>();
    bindings.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> {
      BindingHostGroup hostGroup = new BindingHostGroup();
      hostGroup.setName(entry.getKey());
      Set<Map<String, String>> hosts = new LinkedHashSet<>();
      entry.getValue().stream().sorted().forEach(host -> hosts.add(Map.of("fqdn", host)));
      hostGroup.setHosts(hosts);
      hostGroups.add(hostGroup);
    });
    result.setHostGroups(hostGroups);
    return result;
  }

  private Map<String, Map<String, Map<String, String>>> copyConfigurations(
      Map<String, Map<String, Map<String, String>>> source) {
    Map<String, Map<String, Map<String, String>>> result = new LinkedHashMap<>();
    source.forEach((configType, sections) -> {
      Map<String, Map<String, String>> copiedSections = new LinkedHashMap<>();
      sections.forEach((section, properties) -> copiedSections.put(section,
          new LinkedHashMap<>(properties)));
      result.put(configType, copiedSections);
    });
    return result;
  }

  private void mergeInputConfigurations(
      Map<String, Map<String, Map<String, String>>> target,
      Map<String, Map<String, Map<String, String>>> source, String owner)
      throws MpackAdvisorException {
    for (Map.Entry<String, Map<String, Map<String, String>>> config : source.entrySet()) {
      Map<String, Map<String, String>> sections = target.computeIfAbsent(config.getKey(),
          ignored -> new LinkedHashMap<>());
      for (Map.Entry<String, Map<String, String>> section : config.getValue().entrySet()) {
        Map<String, String> properties = sections.computeIfAbsent(section.getKey(),
            ignored -> new LinkedHashMap<>());
        for (Map.Entry<String, String> property : section.getValue().entrySet()) {
          String existing = properties.putIfAbsent(property.getKey(), property.getValue());
          if (existing != null && !Objects.equals(existing, property.getValue())) {
            throw new MpackAdvisorException(String.format(
                "Conflicting input values for %s/%s/%s from %s",
                config.getKey(), section.getKey(), property.getKey(), owner));
          }
        }
      }
    }
  }
}
