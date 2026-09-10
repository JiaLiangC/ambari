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
package org.apache.ambari.server.controller.internal;

import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.apache.ambari.server.StaticallyInject;
import org.apache.ambari.server.api.services.AmbariMetaInfo;
import org.apache.ambari.server.controller.AmbariManagementController;
import org.apache.ambari.server.controller.spi.NoSuchParentResourceException;
import org.apache.ambari.server.controller.spi.NoSuchResourceException;
import org.apache.ambari.server.controller.spi.Predicate;
import org.apache.ambari.server.controller.spi.Request;
import org.apache.ambari.server.controller.spi.Resource;
import org.apache.ambari.server.controller.spi.SystemException;
import org.apache.ambari.server.controller.spi.UnsupportedPropertyException;
import org.apache.ambari.server.controller.utilities.PropertyHelper;
import org.apache.ambari.server.security.authorization.RoleAuthorization;
import org.apache.ambari.server.state.Mpack;
import org.apache.ambari.server.state.stack.RepositoryXml;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.inject.Inject;
import com.google.inject.Provider;

/**
 * Exposes the immutable repository metadata shipped in an mpack artifact.
 */
@StaticallyInject
public class MpackOperatingSystemResourceProvider extends AbstractControllerResourceProvider {
  public static final String MPACK_ID = PropertyHelper.getPropertyId("MpackOperatingSystems", "mpack_id");
  public static final String OS_TYPE = PropertyHelper.getPropertyId("MpackOperatingSystems", "os_type");
  public static final String REPOSITORIES = PropertyHelper.getPropertyId(
      "MpackOperatingSystems", "repositories");

  private static final Set<String> PROPERTY_IDS = ImmutableSet.of(MPACK_ID, OS_TYPE, REPOSITORIES);
  private static final Set<String> PK_PROPERTY_IDS = ImmutableSet.of(MPACK_ID, OS_TYPE);
  private static final Map<Resource.Type, String> KEY_PROPERTY_IDS = ImmutableMap.of(
      Resource.Type.Mpack, MPACK_ID,
      Resource.Type.MpackOperatingSystem, OS_TYPE);

  @Inject
  private static Provider<AmbariMetaInfo> ambariMetaInfoProvider;

  MpackOperatingSystemResourceProvider(AmbariManagementController managementController) {
    super(Resource.Type.MpackOperatingSystem, PROPERTY_IDS, KEY_PROPERTY_IDS, managementController);
    setRequiredGetAuthorizations(EnumSet.of(
        RoleAuthorization.AMBARI_MANAGE_STACK_VERSIONS,
        RoleAuthorization.AMBARI_EDIT_STACK_REPOS,
        RoleAuthorization.CLUSTER_VIEW_STACK_DETAILS,
        RoleAuthorization.CLUSTER_UPGRADE_DOWNGRADE_STACK));
  }

  @Override
  protected Set<String> getPKPropertyIds() {
    return PK_PROPERTY_IDS;
  }

  @Override
  protected Set<Resource> getResourcesAuthorized(Request request, Predicate predicate)
      throws SystemException, UnsupportedPropertyException, NoSuchResourceException,
      NoSuchParentResourceException {
    Set<Resource> results = new LinkedHashSet<>();
    Set<String> requestedIds = getRequestPropertyIds(request, predicate);
    for (Map<String, Object> propertyMap : getPropertyMaps(predicate)) {
      Object rawMpackId = propertyMap.get(MPACK_ID);
      if (rawMpackId == null) {
        throw new NoSuchParentResourceException("Mpack id is required");
      }
      Long mpackId;
      try {
        mpackId = Long.valueOf(String.valueOf(rawMpackId));
      } catch (NumberFormatException e) {
        throw new NoSuchParentResourceException("Invalid mpack id: " + rawMpackId);
      }
      Mpack mpack = ambariMetaInfoProvider.get().getMpack(mpackId);
      if (mpack == null) {
        throw new NoSuchParentResourceException("Mpack " + mpackId + " does not exist");
      }

      String requestedOs = propertyMap.get(OS_TYPE) == null
          ? null : String.valueOf(propertyMap.get(OS_TYPE));
      RepositoryXml repositoryXml = mpack.getRepositoryXml();
      if (repositoryXml == null) {
        continue;
      }
      for (RepositoryXml.Os operatingSystem : repositoryXml.getOses()) {
        if (requestedOs != null && !requestedOs.equals(operatingSystem.getFamily())) {
          continue;
        }
        Resource resource = new ResourceImpl(Resource.Type.MpackOperatingSystem);
        setResourceProperty(resource, MPACK_ID, mpackId, requestedIds);
        setResourceProperty(resource, OS_TYPE, operatingSystem.getFamily(), requestedIds);
        setResourceProperty(resource, REPOSITORIES, operatingSystem.getRepos(), requestedIds);
        results.add(resource);
      }
    }
    if (results.isEmpty() && predicate != null) {
      throw new NoSuchResourceException("No matching mpack operating system metadata was found");
    }
    return results;
  }
}
