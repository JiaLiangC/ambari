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
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.api.services.mpackadvisor.MpackAdvisorException;
import org.apache.ambari.server.api.services.mpackadvisor.MpackAdvisorRequest;
import org.apache.ambari.server.api.services.mpackadvisor.MpackAdvisorRequest.MpackContext;
import org.apache.ambari.server.api.services.mpackadvisor.MpackAdvisorRequest.ServiceContext;
import org.apache.ambari.server.api.services.mpackadvisor.MpackRecommendationResponse;
import org.apache.ambari.server.api.services.stackadvisor.recommendations.RecommendationResponse.BindingHostGroup;
import org.apache.ambari.server.api.services.stackadvisor.recommendations.RecommendationResponse.HostGroup;
import org.apache.ambari.server.controller.AmbariManagementController;
import org.apache.ambari.server.controller.spi.NoSuchParentResourceException;
import org.apache.ambari.server.controller.spi.Request;
import org.apache.ambari.server.controller.spi.RequestStatus;
import org.apache.ambari.server.controller.spi.Resource;
import org.apache.ambari.server.controller.spi.ResourceAlreadyExistsException;
import org.apache.ambari.server.controller.spi.SystemException;
import org.apache.ambari.server.controller.spi.UnsupportedPropertyException;
import org.apache.ambari.server.controller.utilities.PropertyHelper;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Sets;

/**
 * Creates package-aware recommendations.
 */
public class MpackRecommendationResourceProvider extends MpackAdvisorResourceProvider {

  private static final String ID_PROPERTY_ID = PropertyHelper.getPropertyId(
      "MpackRecommendation", "id");
  private static final String RECOMMEND_PROPERTY_ID = "recommend";
  private static final Map<Resource.Type, String> KEY_PROPERTY_IDS = ImmutableMap.of(
      Resource.Type.MpackRecommendation, ID_PROPERTY_ID);
  private static final Set<String> PROPERTY_IDS = Sets.newHashSet(ID_PROPERTY_ID,
      RECOMMEND_PROPERTY_ID, HOSTS_PROPERTY_ID, SERVICES_PROPERTY_ID,
      RECOMMENDATIONS_PROPERTY_ID, BLUEPRINT_CONFIGURATIONS_PROPERTY_ID,
      BLUEPRINT_HOST_GROUPS_PROPERTY_ID, BLUEPRINT_MPACK_INSTANCES_PROPERTY_ID,
      BINDING_HOST_GROUPS_PROPERTY_ID);

  protected MpackRecommendationResourceProvider(
      AmbariManagementController managementController) {
    super(Resource.Type.MpackRecommendation, PROPERTY_IDS, KEY_PROPERTY_IDS,
        managementController);
  }

  @Override
  protected String getRequestTypePropertyId() {
    return RECOMMEND_PROPERTY_ID;
  }

  @Override
  protected RequestStatus createResourcesAuthorized(Request request) throws SystemException,
      UnsupportedPropertyException, ResourceAlreadyExistsException,
      NoSuchParentResourceException {
    MpackAdvisorRequest advisorRequest = prepareMpackAdvisorRequest(request);
    final MpackRecommendationResponse response;
    try {
      response = mpackAdvisorHelper.recommend(advisorRequest);
    } catch (MpackAdvisorException e) {
      throw new SystemException(e.getMessage(), e);
    }

    Resource recommendation = createResources(new Command<Resource>() {
      @Override
      public Resource invoke() throws AmbariException {
        Resource resource = new ResourceImpl(Resource.Type.MpackRecommendation);
        setResourceProperty(resource, ID_PROPERTY_ID, response.getId(), getPropertyIds());
        setResourceProperty(resource, HOSTS_PROPERTY_ID, response.getHosts(), getPropertyIds());
        setResourceProperty(resource, SERVICES_PROPERTY_ID, response.getServices(),
            getPropertyIds());
        setResourceProperty(resource, BLUEPRINT_CONFIGURATIONS_PROPERTY_ID,
            response.getRecommendations().getBlueprint().getConfigurations(), getPropertyIds());
        setResourceProperty(resource, BLUEPRINT_HOST_GROUPS_PROPERTY_ID,
            hostGroups(response), getPropertyIds());
        setResourceProperty(resource, BLUEPRINT_MPACK_INSTANCES_PROPERTY_ID,
            mpackInstances(response), getPropertyIds());
        setResourceProperty(resource, BINDING_HOST_GROUPS_PROPERTY_ID,
            bindingHostGroups(response), getPropertyIds());
        return resource;
      }
    });
    notifyCreate(Resource.Type.MpackRecommendation, request);
    return new RequestStatusImpl(null, new HashSet<>(Arrays.asList(recommendation)));
  }

  private List<Map<String, Object>> hostGroups(MpackRecommendationResponse response) {
    List<Map<String, Object>> result = new ArrayList<>();
    for (HostGroup hostGroup : response.getRecommendations().getBlueprint().getHostGroups()) {
      Map<String, Object> values = new LinkedHashMap<>();
      values.put("name", hostGroup.getName());
      values.put("components", hostGroup.getComponents());
      result.add(values);
    }
    return result;
  }

  private List<Map<String, Object>> bindingHostGroups(MpackRecommendationResponse response) {
    List<Map<String, Object>> result = new ArrayList<>();
    for (BindingHostGroup hostGroup : response.getRecommendations()
        .getBlueprintClusterBinding().getHostGroups()) {
      Map<String, Object> values = new LinkedHashMap<>();
      values.put("name", hostGroup.getName());
      values.put("hosts", hostGroup.getHosts());
      result.add(values);
    }
    return result;
  }

  private List<Map<String, Object>> mpackInstances(MpackRecommendationResponse response) {
    List<Map<String, Object>> result = new ArrayList<>();
    for (MpackContext mpack : response.getMpackInstances()) {
      Map<String, Object> values = new LinkedHashMap<>();
      values.put("name", mpack.getName());
      values.put("type", mpack.getType());
      values.put("version", mpack.getVersion());
      List<Map<String, Object>> services = new ArrayList<>();
      for (ServiceContext service : mpack.getServices()) {
        Map<String, Object> serviceValues = new LinkedHashMap<>();
        serviceValues.put("name", service.getName());
        serviceValues.put("type", service.getType());
        serviceValues.put("configurations", service.getConfigurations());
        services.add(serviceValues);
      }
      values.put("service_instances", services);
      result.add(values);
    }
    return result;
  }

  @Override
  protected Set<String> getPKPropertyIds() {
    return new HashSet<>(KEY_PROPERTY_IDS.values());
  }
}
