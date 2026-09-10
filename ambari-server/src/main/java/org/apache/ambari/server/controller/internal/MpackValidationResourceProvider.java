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
import org.apache.ambari.server.api.services.mpackadvisor.MpackValidationResponse;
import org.apache.ambari.server.api.services.mpackadvisor.MpackValidationResponse.Item;
import org.apache.ambari.server.api.services.stackadvisor.validations.ValidationResponse.ValidationItem;
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
 * Creates package-aware advisor validations.
 */
public class MpackValidationResourceProvider extends MpackAdvisorResourceProvider {

  private static final String ID_PROPERTY_ID = PropertyHelper.getPropertyId(
      "MpackValidation", "id");
  private static final String VALIDATE_PROPERTY_ID = "validate";
  private static final Map<Resource.Type, String> KEY_PROPERTY_IDS = ImmutableMap.of(
      Resource.Type.MpackValidation, ID_PROPERTY_ID);
  private static final Set<String> PROPERTY_IDS = Sets.newHashSet(ID_PROPERTY_ID,
      VALIDATE_PROPERTY_ID, ITEMS_PROPERTY_ID);

  protected MpackValidationResourceProvider(AmbariManagementController managementController) {
    super(Resource.Type.MpackValidation, PROPERTY_IDS, KEY_PROPERTY_IDS, managementController);
  }

  @Override
  protected String getRequestTypePropertyId() {
    return VALIDATE_PROPERTY_ID;
  }

  @Override
  protected RequestStatus createResourcesAuthorized(Request request) throws SystemException,
      UnsupportedPropertyException, ResourceAlreadyExistsException,
      NoSuchParentResourceException {
    MpackAdvisorRequest advisorRequest = prepareMpackAdvisorRequest(request);
    final MpackValidationResponse response;
    try {
      response = mpackAdvisorHelper.validate(advisorRequest);
    } catch (MpackAdvisorException e) {
      throw new SystemException(e.getMessage(), e);
    }

    Resource validation = createResources(new Command<Resource>() {
      @Override
      public Resource invoke() throws AmbariException {
        Resource resource = new ResourceImpl(Resource.Type.MpackValidation);
        setResourceProperty(resource, ID_PROPERTY_ID, response.getId(), getPropertyIds());
        setResourceProperty(resource, ITEMS_PROPERTY_ID, items(response), getPropertyIds());
        return resource;
      }
    });
    notifyCreate(Resource.Type.MpackValidation, request);
    return new RequestStatusImpl(null, new HashSet<>(Arrays.asList(validation)));
  }

  private List<Map<String, Object>> items(MpackValidationResponse response) {
    List<Map<String, Object>> result = new ArrayList<>();
    for (Item item : response.getItems()) {
      ValidationItem validation = item.getValidation();
      Map<String, Object> values = new LinkedHashMap<>();
      values.put("type", validation.getType());
      values.put("level", validation.getLevel());
      values.put("message", validation.getMessage());
      values.put("mpack_instance_name", item.getMpack().getName());
      values.put("mpack_instance_type", item.getMpack().getType());
      values.put("mpack_version", item.getMpack().getVersion());
      putIfPresent(values, "service_instance_name", item.getServiceInstance());
      putIfPresent(values, "component_instance_name", validation.getComponentName());
      putIfPresent(values, "host", validation.getHost());
      putIfPresent(values, "config_type", validation.getConfigType());
      putIfPresent(values, "config_name", validation.getConfigName());
      result.add(values);
    }
    return result;
  }

  private void putIfPresent(Map<String, Object> values, String key, Object value) {
    if (value != null) {
      values.put(key, value);
    }
  }

  @Override
  protected Set<String> getPKPropertyIds() {
    return new HashSet<>(KEY_PROPERTY_IDS.values());
  }
}
