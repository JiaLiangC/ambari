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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.ambari.server.api.services.stackadvisor.StackAdvisorRequest.StackAdvisorRequestType;
import org.apache.ambari.server.state.ChangedConfigInfo;

/**
 * A package-aware advisor request which can be losslessly projected to the
 * current stack advisor contract without changing runtime service identity.
 */
public class MpackAdvisorRequest {

  private final StackAdvisorRequestType requestType;
  private final List<String> hosts;
  private final List<MpackContext> mpackInstances;
  private final Map<String, List<ComponentContext>> hostGroupComponents;
  private final Map<String, Set<String>> hostGroupBindings;
  private final Map<String, Map<String, Map<String, String>>> configurations;
  private final List<ChangedConfigInfo> changedConfigurations;
  private final Map<String, String> userContext;
  private final Boolean gplLicenseAccepted;

  public MpackAdvisorRequest(StackAdvisorRequestType requestType, List<String> hosts,
      List<MpackContext> mpackInstances, Map<String, List<ComponentContext>> hostGroupComponents,
      Map<String, Set<String>> hostGroupBindings,
      Map<String, Map<String, Map<String, String>>> configurations,
      List<ChangedConfigInfo> changedConfigurations, Map<String, String> userContext,
      Boolean gplLicenseAccepted) {
    this.requestType = requestType;
    this.hosts = immutableList(hosts);
    this.mpackInstances = immutableList(mpackInstances);
    this.hostGroupComponents = immutableListMap(hostGroupComponents);
    this.hostGroupBindings = immutableSetMap(hostGroupBindings);
    this.configurations = immutableConfigurations(configurations);
    this.changedConfigurations = immutableList(changedConfigurations);
    this.userContext = Collections.unmodifiableMap(new LinkedHashMap<>(userContext));
    this.gplLicenseAccepted = gplLicenseAccepted;
  }

  public StackAdvisorRequestType getRequestType() {
    return requestType;
  }

  public List<String> getHosts() {
    return hosts;
  }

  public List<MpackContext> getMpackInstances() {
    return mpackInstances;
  }

  public Map<String, List<ComponentContext>> getHostGroupComponents() {
    return hostGroupComponents;
  }

  public Map<String, Set<String>> getHostGroupBindings() {
    return hostGroupBindings;
  }

  public Map<String, Map<String, Map<String, String>>> getConfigurations() {
    return configurations;
  }

  public List<ChangedConfigInfo> getChangedConfigurations() {
    return changedConfigurations;
  }

  public Map<String, String> getUserContext() {
    return userContext;
  }

  public Boolean getGplLicenseAccepted() {
    return gplLicenseAccepted;
  }

  public static class MpackContext {
    private final String name;
    private final String type;
    private final String version;
    private final List<ServiceContext> services;

    public MpackContext(String name, String type, String version, List<ServiceContext> services) {
      this.name = name;
      this.type = type;
      this.version = version;
      this.services = immutableList(services);
    }

    public String getName() {
      return name;
    }

    public String getType() {
      return type;
    }

    public String getVersion() {
      return version;
    }

    public List<ServiceContext> getServices() {
      return services;
    }
  }

  public static class ServiceContext {
    private final String name;
    private final String type;
    private final Map<String, Map<String, Map<String, String>>> configurations;

    public ServiceContext(String name, String type,
        Map<String, Map<String, Map<String, String>>> configurations) {
      this.name = name;
      this.type = type;
      this.configurations = immutableConfigurations(configurations);
    }

    public String getName() {
      return name;
    }

    public String getType() {
      return type;
    }

    public Map<String, Map<String, Map<String, String>>> getConfigurations() {
      return configurations;
    }
  }

  public static class ComponentContext {
    private final String name;
    private final String mpackInstance;
    private final String serviceInstance;

    public ComponentContext(String name, String mpackInstance, String serviceInstance) {
      this.name = name;
      this.mpackInstance = mpackInstance;
      this.serviceInstance = serviceInstance;
    }

    public String getName() {
      return name;
    }

    public String getMpackInstance() {
      return mpackInstance;
    }

    public String getServiceInstance() {
      return serviceInstance;
    }
  }

  private static <T> List<T> immutableList(List<T> values) {
    return Collections.unmodifiableList(new ArrayList<>(values));
  }

  private static <T> Map<String, List<T>> immutableListMap(Map<String, List<T>> values) {
    Map<String, List<T>> copy = new LinkedHashMap<>();
    values.forEach((key, value) -> copy.put(key, immutableList(value)));
    return Collections.unmodifiableMap(copy);
  }

  private static Map<String, Set<String>> immutableSetMap(Map<String, Set<String>> values) {
    Map<String, Set<String>> copy = new LinkedHashMap<>();
    values.forEach((key, value) -> copy.put(key,
        Collections.unmodifiableSet(new LinkedHashSet<>(value))));
    return Collections.unmodifiableMap(copy);
  }

  private static Map<String, Map<String, Map<String, String>>> immutableConfigurations(
      Map<String, Map<String, Map<String, String>>> values) {
    Map<String, Map<String, Map<String, String>>> copy = new LinkedHashMap<>();
    values.forEach((configType, sections) -> {
      Map<String, Map<String, String>> sectionCopy = new LinkedHashMap<>();
      sections.forEach((section, properties) -> sectionCopy.put(section,
          Collections.unmodifiableMap(new LinkedHashMap<>(properties))));
      copy.put(configType, Collections.unmodifiableMap(sectionCopy));
    });
    return Collections.unmodifiableMap(copy);
  }
}
