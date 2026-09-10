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



import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.StaticallyInject;
import org.apache.ambari.server.api.services.parsers.BodyParseException;
import org.apache.ambari.server.controller.AmbariManagementController;
import org.apache.ambari.server.controller.MpackRequest;
import org.apache.ambari.server.controller.MpackResponse;
import org.apache.ambari.server.controller.spi.NoSuchParentResourceException;
import org.apache.ambari.server.controller.spi.NoSuchResourceException;
import org.apache.ambari.server.controller.spi.Predicate;
import org.apache.ambari.server.controller.spi.Request;
import org.apache.ambari.server.controller.spi.RequestStatus;
import org.apache.ambari.server.controller.spi.Resource;
import org.apache.ambari.server.controller.spi.ResourceAlreadyExistsException;
import org.apache.ambari.server.controller.spi.SystemException;
import org.apache.ambari.server.controller.spi.UnsupportedPropertyException;
import org.apache.ambari.server.controller.utilities.PredicateHelper;
import org.apache.ambari.server.controller.utilities.PropertyHelper;
import org.apache.ambari.server.orm.dao.BlueprintDAO;
import org.apache.ambari.server.orm.dao.MpackDAO;
import org.apache.ambari.server.orm.dao.RepositoryVersionDAO;
import org.apache.ambari.server.orm.dao.StackDAO;
import org.apache.ambari.server.orm.entities.BlueprintEntity;
import org.apache.ambari.server.orm.entities.BlueprintSettingEntity;
import org.apache.ambari.server.orm.entities.MpackEntity;
import org.apache.ambari.server.orm.entities.RepositoryVersionEntity;
import org.apache.ambari.server.orm.entities.StackEntity;
import org.apache.ambari.server.registry.Registry;
import org.apache.ambari.server.registry.RegistryMpack;
import org.apache.ambari.server.registry.RegistryMpackVersion;
import org.apache.ambari.server.security.authorization.RoleAuthorization;
import org.apache.ambari.server.state.Cluster;
import org.apache.ambari.server.state.Module;
import org.apache.ambari.server.state.Service;
import org.apache.ambari.server.state.ServiceComponent;
import org.apache.ambari.server.state.StackId;
import org.apache.ambari.server.topology.MpackReference;
import org.apache.commons.lang3.Validate;

import com.google.gson.Gson;
import com.google.inject.Inject;


/**
 * ResourceProvider for Mpack instances
 */
@StaticallyInject
public class MpackResourceProvider extends AbstractControllerResourceProvider {

  public static final String RESPONSE_KEY = "MpackInfo";
  public static final String ALL_PROPERTIES = RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "*";
  public static final String MPACK_RESOURCE_ID = RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "id";
  public static final String REGISTRY_ID = RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "registry_id";
  public static final String MPACK_ID = RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "mpack_id";
  public static final String MPACK_NAME = RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "mpack_name";
  public static final String MPACK_VERSION = RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "mpack_version";
  public static final String MPACK_DESCRIPTION = RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "mpack_description";
  public static final String MPACK_DISPLAY_NAME = RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "mpack_display_name";
  public static final String MPACK_URI = RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "mpack_uri";
  public static final String MODULES = RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "modules";
  public static final String STACK_NAME_PROPERTY_ID = RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "stack_name";
  public static final String STACK_VERSION_PROPERTY_ID =
    RESPONSE_KEY + PropertyHelper.EXTERNAL_PATH_SEP + "stack_version";

  private static Set<String> pkPropertyIds = new HashSet<>(
    Arrays.asList(MPACK_RESOURCE_ID, STACK_NAME_PROPERTY_ID, STACK_VERSION_PROPERTY_ID));

  /**
   * The property ids for an mpack resource.
   */
  private static final Set<String> PROPERTY_IDS = new HashSet<>();

  /**
   * The key property ids for a mpack resource.
   */
  private static final Map<Resource.Type, String> KEY_PROPERTY_IDS = new HashMap<>();

  @Inject
  protected static MpackDAO mpackDAO;

  @Inject
  protected static BlueprintDAO blueprintDAO;

  @Inject
  protected static StackDAO stackDAO;

  @Inject
  protected static RepositoryVersionDAO repositoryVersionDAO;

  @Inject
  protected static Gson gson;

  static {
    // properties
    PROPERTY_IDS.add(MPACK_RESOURCE_ID);
    PROPERTY_IDS.add(REGISTRY_ID);
    PROPERTY_IDS.add(MPACK_ID);
    PROPERTY_IDS.add(MPACK_NAME);
    PROPERTY_IDS.add(MPACK_VERSION);
    PROPERTY_IDS.add(MPACK_URI);
    PROPERTY_IDS.add(MPACK_DESCRIPTION);
    PROPERTY_IDS.add(MODULES);
    PROPERTY_IDS.add(STACK_NAME_PROPERTY_ID);
    PROPERTY_IDS.add(STACK_VERSION_PROPERTY_ID);
    PROPERTY_IDS.add(MPACK_DISPLAY_NAME);

    // keys
    KEY_PROPERTY_IDS.put(Resource.Type.Mpack, MPACK_RESOURCE_ID);
    KEY_PROPERTY_IDS.put(Resource.Type.Stack, STACK_NAME_PROPERTY_ID);
    KEY_PROPERTY_IDS.put(Resource.Type.StackVersion, STACK_VERSION_PROPERTY_ID);

  }

  MpackResourceProvider(AmbariManagementController controller) {
    super(Resource.Type.Mpack, PROPERTY_IDS, KEY_PROPERTY_IDS, controller);

    setRequiredCreateAuthorizations(EnumSet.of(RoleAuthorization.AMBARI_MANAGE_STACK_VERSIONS));
    setRequiredDeleteAuthorizations(EnumSet.of(RoleAuthorization.AMBARI_MANAGE_STACK_VERSIONS));
    setRequiredGetAuthorizations(EnumSet.of(
        RoleAuthorization.AMBARI_MANAGE_STACK_VERSIONS,
        RoleAuthorization.AMBARI_EDIT_STACK_REPOS,
        RoleAuthorization.CLUSTER_VIEW_STACK_DETAILS,
        RoleAuthorization.CLUSTER_UPGRADE_DOWNGRADE_STACK));
  }

  @Override
  protected Set<String> getPKPropertyIds() {
    return pkPropertyIds;
  }

  @Override
  protected RequestStatus createResourcesAuthorized(final Request request)
          throws SystemException, UnsupportedPropertyException,
          ResourceAlreadyExistsException, NoSuchParentResourceException, IllegalArgumentException {
    Set<Resource> associatedResources = new HashSet<>();
    try {
      MpackRequest mpackRequest = getRequest(request);
      if (mpackRequest == null) {
        throw new BodyParseException("Please provide " + MPACK_NAME + " ," + MPACK_VERSION + " ," + MPACK_URI);
      }
      validateCreateRequest(mpackRequest);
      MpackResponse response = getManagementController().registerMpack(mpackRequest);
      if (response == null) {
        throw new SystemException("Mpack registration returned no response");
      }
      notifyCreate(Resource.Type.Mpack, request);
      Resource resource = new ResourceImpl(Resource.Type.Mpack);
      resource.setProperty(MPACK_RESOURCE_ID, response.getId());
      resource.setProperty(MPACK_ID, response.getMpackId());
      resource.setProperty(MPACK_NAME, response.getMpackName());
      resource.setProperty(MPACK_VERSION, response.getMpackVersion());
      resource.setProperty(MPACK_URI, response.getMpackUri());
      resource.setProperty(MPACK_DESCRIPTION, response.getDescription());
      resource.setProperty(REGISTRY_ID, response.getRegistryId());
      resource.setProperty(MPACK_DISPLAY_NAME, response.getDisplayName());
      associatedResources.add(resource);
      return getRequestStatus(null, associatedResources);
    } catch (IOException e) {
      throw new SystemException("Unable to register mpack: " + e.getMessage(), e);
    } catch (BodyParseException e) {
      throw new IllegalArgumentException(e.getMessage(), e);
    }
  }

  /***
   * Validates the request body for the required properties in order to create an Mpack resource.
   *
   * @param mpackRequest
   */
  private void validateCreateRequest(MpackRequest mpackRequest) {
    final String mpackName = mpackRequest.getMpackName();
    final String mpackUrl = mpackRequest.getMpackUri();
    final Long registryId = mpackRequest.getRegistryId();
    final String mpackVersion = mpackRequest.getMpackVersion();

    Validate.notBlank(mpackUrl, registryId == null
        ? "Mpack URI should not be empty"
        : "Registry-backed mpack URI was not resolved");
    if (registryId == null) {
      LOG.info("Received a direct createMpack request");
    } else {
      Validate.notNull(mpackName, "MpackName should not be null");
      Validate.notNull(mpackVersion, "MpackVersion should not be null");
      LOG.info("Received a createMpack request"
        + ", mpackName=" + mpackName
        + ", mpackVersion=" + mpackVersion
        + ", registryId=" + registryId);
    }
    try {
      URI uri = new URI(mpackUrl);
      Validate.isTrue(uri.isAbsolute(), "Mpack URI must be absolute");
    } catch (Exception e) {
      throw new IllegalArgumentException(
          mpackUrl + " is an invalid mpack URI. Please check the download link.", e);
    }
  }

  public MpackRequest getRequest(Request request) throws AmbariException {
    MpackRequest mpackRequest = new MpackRequest();
    Set<Map<String, Object>> properties = request.getProperties();
    if (properties.size() != 1) {
      throw new IllegalArgumentException("Exactly one mpack may be registered per request");
    }
    for (Map propertyMap : properties) {
      boolean hasUri = propertyMap.containsKey(MPACK_URI);
      boolean hasRegistry = propertyMap.containsKey(REGISTRY_ID);
      if (!hasUri && !hasRegistry) {
        return null;
      }
      if (hasUri && hasRegistry) {
        throw new IllegalArgumentException("Specify either an mpack URI or a registry ID, not both");
      }
      if (hasRegistry) {
        mpackRequest.setRegistryId(Long.valueOf(String.valueOf(propertyMap.get(REGISTRY_ID))));
        mpackRequest.setMpackName((String) propertyMap.get(MPACK_NAME));
        mpackRequest.setMpackVersion((String) propertyMap.get(MPACK_VERSION));
        mpackRequest.setMpackUri(resolveRegistryMpackUri(mpackRequest));
      } else {
        mpackRequest.setMpackUri((String) propertyMap.get(MPACK_URI));
      }
    }
    return mpackRequest;
  }

  private String resolveRegistryMpackUri(MpackRequest request) throws AmbariException {
    Validate.notBlank(request.getMpackName(), "Mpack name is required for registry registration");
    Validate.notBlank(request.getMpackVersion(), "Mpack version is required for registry registration");
    Registry registry = getManagementController().getRegistry(request.getRegistryId());
    RegistryMpack registryMpack = registry.getRegistryMpack(request.getMpackName());
    RegistryMpackVersion registryMpackVersion = registryMpack.getMpackVersion(request.getMpackVersion());
    return registryMpackVersion.getMpackUri();
  }


  @Override
  protected Set<Resource> getResourcesAuthorized(Request request, Predicate predicate)
    throws SystemException, UnsupportedPropertyException,
    NoSuchResourceException, NoSuchParentResourceException {

    Set<Resource> results = new LinkedHashSet<>();
    Long mpackId = null;
    //Fetch all mpacks
    if (predicate == null) {
      // Fetch all mpacks
      Set<MpackResponse> responses = getManagementController().getMpacks();
      if (null == responses) {
        responses = Collections.emptySet();
      }

      for (MpackResponse response : responses) {
        Resource resource = setResources(response);
        Set<String> requestIds = getRequestPropertyIds(request, predicate);
        if (requestIds.contains(MODULES)) {
          List<Module> modules = getManagementController().getModules(response.getId());
          resource.setProperty(MODULES, modules);
        }
        results.add(resource);
      }
    } else {
      // Fetch a particular mpack based on id
      Map<String, Object> propertyMap = new HashMap<>(PredicateHelper.getProperties(predicate));
      if (propertyMap.containsKey(MPACK_RESOURCE_ID)) {
        Object objMpackId = propertyMap.get(MPACK_RESOURCE_ID);
        if (objMpackId == null) {
          throw new IllegalArgumentException("Mpack ID must not be null");
        }
        mpackId = Long.valueOf(String.valueOf(objMpackId));
        MpackResponse response = getManagementController().getMpack(mpackId);

        if (null != response) {
          Resource resource = setResources(response);
          List<Module> modules = getManagementController().getModules(response.getId());
          resource.setProperty(MODULES, modules);
          results.add(resource);
        }
      } //Fetch an mpack based on a stackVersion query
      else if (propertyMap.containsKey(STACK_NAME_PROPERTY_ID)
              && propertyMap.containsKey(STACK_VERSION_PROPERTY_ID)) {
        String stackName = (String) propertyMap.get(STACK_NAME_PROPERTY_ID);
        String stackVersion = (String) propertyMap.get(STACK_VERSION_PROPERTY_ID);
        StackEntity stackEntity = stackDAO.find(stackName, stackVersion);
        if (stackEntity == null) {
          throw new NoSuchResourceException("The requested stack does not exist: "
              + stackName + "-" + stackVersion);
        }
        mpackId = stackEntity.getMpackId();
        if (mpackId == null) {
          throw new NoSuchResourceException("The requested stack has no registered mpack: "
              + stackName + "-" + stackVersion);
        }
        MpackResponse response = getManagementController().getMpack(mpackId);

        if (null != response) {
          Resource resource = setResources(response);
          resource.setProperty(STACK_NAME_PROPERTY_ID, stackName);
          resource.setProperty(STACK_VERSION_PROPERTY_ID, stackVersion);
          results.add(resource);
        }
      }
      if (null == mpackId) {
        throw new IllegalArgumentException(
                "Either the management pack ID or the stack name and version are required when searching");
      }

      if (results.isEmpty()) {
        throw new NoSuchResourceException("The requested resource doesn't exist: " + predicate);
      }
    }
    return results;
  }

  private Resource setResources(MpackResponse response) {
    Resource resource = new ResourceImpl(Resource.Type.Mpack);
    resource.setProperty(MPACK_RESOURCE_ID, response.getId());
    resource.setProperty(MPACK_ID, response.getMpackId());
    resource.setProperty(MPACK_NAME, response.getMpackName());
    resource.setProperty(MPACK_VERSION, response.getMpackVersion());
    resource.setProperty(MPACK_URI, response.getMpackUri());
    resource.setProperty(MPACK_DESCRIPTION, response.getDescription());
    resource.setProperty(REGISTRY_ID, response.getRegistryId());
    resource.setProperty(MPACK_DISPLAY_NAME, response.getDisplayName());
    return resource;
  }

  @Override
  protected RequestStatus deleteResourcesAuthorized(final Request request, Predicate predicate)
    throws SystemException, UnsupportedPropertyException, NoSuchResourceException, NoSuchParentResourceException {

    final Long mpackId;
    Map<String, Object> propertyMap = new HashMap<>(PredicateHelper.getProperties(predicate));
    DeleteStatusMetaData deleteStatusMetaData = null;

    if (propertyMap.containsKey(MPACK_RESOURCE_ID)) {
      Object objMpackId = propertyMap.get(MPACK_RESOURCE_ID);
      if (objMpackId == null) {
        throw new IllegalArgumentException("Mpack ID must not be null");
      }
      mpackId = Long.valueOf(String.valueOf(objMpackId));
      LOG.info("Deleting Mpack, id = " + mpackId);

      MpackEntity mpackEntity = mpackDAO.findById(mpackId);
      StackEntity stackEntity = stackDAO.findByMpack(mpackId);
      if (mpackEntity == null) {
        throw new NoSuchResourceException("The requested resource doesn't exist: " + predicate);
      }
      if (isReferenced(stackEntity, mpackId)) {
        throw new SystemException("Mpack " + mpackId
            + " cannot be deleted while it is referenced by a cluster or Blueprint");
      }

      try {
        getManagementController().removeMpack(mpackEntity, stackEntity);
        deleteStatusMetaData = new DeleteStatusMetaData();
        if (stackEntity != null) {
          notifyDelete(Resource.Type.Stack, predicate);
        }
        notifyDelete(Resource.Type.Mpack, predicate);
        deleteStatusMetaData.addDeletedKey(mpackId.toString());
      } catch (IOException e) {
        throw new SystemException("Unable to remove mpack files: " + e.getMessage(), e);
      }
    } else {
      throw new UnsupportedPropertyException(Resource.Type.Mpack, null);
    }

    return getRequestStatus(null, null, deleteStatusMetaData);
  }

  private boolean isReferenced(StackEntity stackEntity, Long mpackId) {
    if (stackEntity != null) {
      for (Cluster cluster : getManagementController().getClusters().getClusters().values()) {
        if (matches(stackEntity, cluster.getCurrentStackVersion())
            || matches(stackEntity, cluster.getDesiredStackVersion())) {
          return true;
        }
        for (Service service : cluster.getServices().values()) {
          if (matches(stackEntity, service.getDesiredRepositoryVersion())) {
            return true;
          }
          for (ServiceComponent component : service.getServiceComponents().values()) {
            if (matches(stackEntity, component.getDesiredRepositoryVersion())) {
              return true;
            }
          }
        }
      }
    }

    for (BlueprintEntity blueprint : blueprintDAO.findAll()) {
      if (blueprint.getSettings() == null) {
        continue;
      }
      for (BlueprintSettingEntity setting : blueprint.getSettings()) {
        if (!MpackReference.SETTING_NAME.equals(setting.getSettingName())) {
          continue;
        }
        final List<Map<String, String>> references;
        try {
          references = gson.fromJson(setting.getSettingData(), List.class);
        } catch (RuntimeException e) {
          LOG.warn("Blocking mpack deletion because Blueprint {} contains malformed persisted "
              + "mpack reference data", blueprint.getBlueprintName(), e);
          return true;
        }
        if (references == null) {
          LOG.warn("Blocking mpack deletion because Blueprint {} contains an empty persisted "
              + "mpack reference setting", blueprint.getBlueprintName());
          return true;
        }
        for (Map<String, String> reference : references) {
          if (reference == null) {
            LOG.warn("Blocking mpack deletion because Blueprint {} contains a null persisted "
                + "mpack reference", blueprint.getBlueprintName());
            return true;
          }
          try {
            if (mpackId.equals(MpackReference.fromSettingMap(reference).getMpackId())) {
              return true;
            }
          } catch (RuntimeException e) {
            LOG.warn("Blocking mpack deletion because Blueprint {} contains an invalid persisted "
                + "mpack reference", blueprint.getBlueprintName(), e);
            return true;
          }
        }
      }
    }
    return false;
  }

  private boolean matches(StackEntity expected, RepositoryVersionEntity repositoryVersion) {
    return repositoryVersion != null && matches(expected, repositoryVersion.getStackId());
  }

  private boolean matches(StackEntity expected, StackId actual) {
    return actual != null && expected.getStackName().equals(actual.getStackName())
        && expected.getStackVersion().equals(actual.getStackVersion());
  }
}
