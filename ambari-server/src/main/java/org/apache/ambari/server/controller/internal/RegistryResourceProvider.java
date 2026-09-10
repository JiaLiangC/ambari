/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ambari.server.controller.internal;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.StaticallyInject;
import org.apache.ambari.server.controller.AmbariManagementController;
import org.apache.ambari.server.controller.RegistryRequest;
import org.apache.ambari.server.controller.RegistryResponse;
import org.apache.ambari.server.controller.spi.NoSuchParentResourceException;
import org.apache.ambari.server.controller.spi.NoSuchResourceException;
import org.apache.ambari.server.controller.spi.Predicate;
import org.apache.ambari.server.controller.spi.Request;
import org.apache.ambari.server.controller.spi.RequestStatus;
import org.apache.ambari.server.controller.spi.Resource;
import org.apache.ambari.server.controller.spi.ResourceAlreadyExistsException;
import org.apache.ambari.server.controller.spi.SystemException;
import org.apache.ambari.server.controller.spi.UnsupportedPropertyException;
import org.apache.ambari.server.controller.utilities.PropertyHelper;
import org.apache.ambari.server.registry.RegistryType;
import org.apache.ambari.server.security.authorization.RoleAuthorization;
import org.apache.commons.lang3.Validate;

/**
 * ResourceProvider for software registry
 */
@StaticallyInject
public class RegistryResourceProvider extends AbstractControllerResourceProvider {
  public static final String RESPONSE_KEY = "RegistryInfo";
  public static final String ALL_PROPERTIES = RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "*";
  public static final String REGISTRY_ID =  RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP +  "registry_id";
  public static final String REGISTRY_NAME = RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "registry_name";
  public static final String REGISTRY_TYPE = RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "registry_type";
  public static final String REGISTRY_URI = RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "registry_uri";

  private static Set<String> pkPropertyIds = new HashSet<>(
    Arrays.asList(REGISTRY_ID));

  /**
   * The property ids for a software registry resource.
   */
  private static final Set<String> PROPERTY_IDS = new HashSet<>();

  /**
   * The key property ids for a software registry resource.
   */
  private static final Map<Resource.Type, String> KEY_PROPERTY_IDS = new HashMap<>();

  static {
    // properties
    PROPERTY_IDS.add(REGISTRY_ID);
    PROPERTY_IDS.add(REGISTRY_NAME);
    PROPERTY_IDS.add(REGISTRY_TYPE);
    PROPERTY_IDS.add(REGISTRY_URI);

    // keys
    KEY_PROPERTY_IDS.put(Resource.Type.Registry, REGISTRY_ID);

  }

  /**
   * Create a  new resource provider for the given management controller.
   *
   * @param managementController the management controller
   */
  protected RegistryResourceProvider(
    final AmbariManagementController managementController) {
    super(Resource.Type.Registry, PROPERTY_IDS, KEY_PROPERTY_IDS, managementController);
    setRequiredCreateAuthorizations(EnumSet.of(RoleAuthorization.AMBARI_MANAGE_STACK_VERSIONS));
    setRequiredDeleteAuthorizations(EnumSet.of(RoleAuthorization.AMBARI_MANAGE_STACK_VERSIONS));
    setRequiredUpdateAuthorizations(EnumSet.of(RoleAuthorization.AMBARI_MANAGE_STACK_VERSIONS));
  }

  @Override
  protected Set<String> getPKPropertyIds() {
    return pkPropertyIds;
  }

  @Override
  public RequestStatus createResourcesAuthorized(Request request)
    throws SystemException,
    UnsupportedPropertyException,
    ResourceAlreadyExistsException,
    NoSuchParentResourceException {

    Validate.isTrue(request.getProperties().size() == 1,
        "Exactly one registry may be created per request");
    final Set<RegistryRequest> requests = new HashSet<>();
    for (Map<String, Object> propertyMap : request.getProperties()) {
      RegistryRequest registryRequest = getRequest(propertyMap);
      if(registryRequest.getRegistryType() == null) {
        registryRequest.setRegistryType(RegistryType.JSON);
      }
      requests.add(registryRequest);
    }
    Set<RegistryResponse> responses = createResources(new Command<Set<RegistryResponse>>() {
      @Override
      public Set<RegistryResponse> invoke() throws AmbariException {
        return addRegistries(requests);
      }
    });
    notifyCreate(Resource.Type.Registry, request);

    Set<Resource> associatedResources = new HashSet<>();
    for(RegistryResponse response : responses) {
      Resource resource = new ResourceImpl(Resource.Type.Registry);
      resource.setProperty(REGISTRY_ID, response.getRegistryId());
      resource.setProperty(REGISTRY_NAME, response.getRegistryName());
      resource.setProperty(REGISTRY_TYPE, response.getRegistryType());
      resource.setProperty(REGISTRY_URI, response.getRegistryUri());
      associatedResources.add(resource);
    }
    return getRequestStatus(null, associatedResources);
  }

  @Override
  protected RequestStatus updateResourcesAuthorized(Request request, Predicate predicate)
      throws SystemException, NoSuchResourceException, NoSuchParentResourceException {
    Validate.isTrue(request.getProperties().size() == 1,
        "Exactly one registry may be updated per request");
    Set<Map<String, Object>> selectorMaps = getPropertyMaps(predicate);
    Validate.isTrue(selectorMaps.size() == 1, "A single registry ID is required for update");
    Map<String, Object> selector = selectorMaps.iterator().next();
    Validate.isTrue(selector.get(REGISTRY_ID) != null, "Registry ID is required for update");

    RegistryRequest update = getRequest(request.getProperties().iterator().next());
    Long selectedId = Long.valueOf(String.valueOf(selector.get(REGISTRY_ID)));
    Validate.isTrue(update.getRegistryId() == null || selectedId.equals(update.getRegistryId()),
        "Registry ID in the request does not match the selected registry");
    update.setRegistryId(selectedId);
    validateCompleteRequest(update);

    RegistryResponse response = modifyResources(new Command<RegistryResponse>() {
      @Override
      public RegistryResponse invoke() throws AmbariException {
        return getManagementController().updateRegistry(update);
      }
    });
    notifyUpdate(Resource.Type.Registry, request, predicate);
    return getRequestStatus(null, Collections.singleton(toResource(response, PROPERTY_IDS)));
  }

  @Override
  protected RequestStatus deleteResourcesAuthorized(Request request, Predicate predicate)
      throws SystemException, NoSuchResourceException, NoSuchParentResourceException {
    Set<Map<String, Object>> selectorMaps = getPropertyMaps(predicate);
    Validate.isTrue(selectorMaps.size() == 1, "A single registry ID is required for delete");
    Object value = selectorMaps.iterator().next().get(REGISTRY_ID);
    Validate.notNull(value, "Registry ID is required for delete");
    Long registryId = Long.valueOf(String.valueOf(value));

    modifyResources(new Command<Void>() {
      @Override
      public Void invoke() throws AmbariException {
        getManagementController().removeRegistry(registryId);
        return null;
      }
    });
    notifyDelete(Resource.Type.Registry, predicate);
    DeleteStatusMetaData metadata = new DeleteStatusMetaData();
    metadata.addDeletedKey(registryId.toString());
    return getRequestStatus(null, null, metadata);
  }

  @Override
  public Set<Resource> getResourcesAuthorized(Request request, Predicate predicate)
    throws SystemException, UnsupportedPropertyException,
    NoSuchResourceException, NoSuchParentResourceException {

    final Set<RegistryRequest> requests = new HashSet<>();

    if (predicate == null) {
      requests.add(getRequest(Collections.<String, Object>emptyMap()));
    } else {
      for (Map<String, Object> propertyMap : getPropertyMaps(predicate)) {
        requests.add(getRequest(propertyMap));
      }
    }

    Set<String> requestedIds = getRequestPropertyIds(request, predicate);

    Set<RegistryResponse> responses = getResources(new Command<Set<RegistryResponse>>() {
      @Override
      public Set<RegistryResponse> invoke() throws AmbariException {
        return getManagementController().getRegistries(requests);
      }
    });

    Set<Resource> resources = new HashSet<>();
    for (RegistryResponse response : responses) {
      resources.add(toResource(response, requestedIds));
    }
    return resources;
  }


  private RegistryRequest getRequest(Map<String, Object> properties) {

    Long registryId = properties.containsKey(REGISTRY_ID) && properties.get(REGISTRY_ID) != null
        ? Long.valueOf(String.valueOf(properties.get(REGISTRY_ID))) : null;
    String registryName = properties.containsKey(REGISTRY_NAME)
        ? String.valueOf(properties.get(REGISTRY_NAME)) : null;
    RegistryType registryType = properties.containsKey(REGISTRY_TYPE) && properties.get(REGISTRY_TYPE) != null
        ? RegistryType.valueOf(String.valueOf(properties.get(REGISTRY_TYPE)).toUpperCase(Locale.ROOT)) : null;
    String registryUri = properties.containsKey(REGISTRY_URI)
        ? String.valueOf(properties.get(REGISTRY_URI)) : null;
    return new RegistryRequest(registryId, registryName, registryType, registryUri);
  }

  /**
   * Add software registries for the given requests
   *
   * @param requests software registry requests
   */
  private Set<RegistryResponse> addRegistries(Set<RegistryRequest> requests) throws AmbariException {
    Set<RegistryResponse> responses = new HashSet<>();
    if (requests.isEmpty()) {
      LOG.warn("Received an empty requests set");
      // Return an empty response set
      return responses;
    }

    validateCreateRequests(requests);

    for (RegistryRequest request : requests) {
      RegistryResponse response = getManagementController().addRegistry(request);
      if (response != null) {
        responses.add(response);
      }
    }

    return responses;
  }

  private void validateCreateRequests(Set<RegistryRequest> requests) {
    Set<String> names = new HashSet<>();
    for (RegistryRequest request : requests) {
      final Long registryId = request.getRegistryId();
      final String registryName = request.getRegistryName();

      validateCompleteRequest(request);
      Validate.isTrue(registryId == null, "Registry ID should not be set when adding a new software registry");
      Validate.isTrue(names.add(registryName.trim()),
          "Duplicate registry name in request: " + registryName.trim());

      LOG.info("Received a createRegistry request"
        + ", registryName=" + registryName
        + ", registryType=" + request.getRegistryType());

    }
  }

  private void validateCompleteRequest(RegistryRequest request) {
    Validate.notBlank(request.getRegistryName(),
        "Registry name should be provided for a software registry");
    Validate.notNull(request.getRegistryType(),
        "Registry type should be provided for a software registry");
    Validate.notBlank(request.getRegistryUri(),
        "Registry URI should be provided for a software registry");
  }

  private Resource toResource(RegistryResponse response, Set<String> requestedIds) {
    Resource resource = new ResourceImpl(Resource.Type.Registry);
    setResourceProperty(resource, REGISTRY_ID, response.getRegistryId(), requestedIds);
    setResourceProperty(resource, REGISTRY_NAME, response.getRegistryName(), requestedIds);
    setResourceProperty(resource, REGISTRY_TYPE, response.getRegistryType(), requestedIds);
    setResourceProperty(resource, REGISTRY_URI, response.getRegistryUri(), requestedIds);
    return resource;
  }
}
