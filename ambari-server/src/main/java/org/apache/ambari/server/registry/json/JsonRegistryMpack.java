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
package org.apache.ambari.server.registry.json;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.exceptions.RegistryMpackVersionNotFoundException;
import org.apache.ambari.server.registry.RegistryMpack;
import org.apache.ambari.server.registry.RegistryMpackVersion;
import org.apache.commons.lang3.StringUtils;

import com.google.gson.annotations.SerializedName;

/**
 * JSON implementation of {@link RegistryMpack}
 */
public class JsonRegistryMpack implements RegistryMpack {

  @SerializedName("id")
  private String id;

  @SerializedName("name")
  private String name;

  @SerializedName("description")
  private String description;

  @SerializedName("displayName")
  private String displayName;

  @SerializedName("logoUri")
  private String logoUri;

  @SerializedName("versions")
  private ArrayList<JsonRegistryMpackVersion> mpackVersions;

  @Override
  public String getMpackId() {
    return id;
  }

  @Override
  public String getMpackName() {
    return name;
  }

  @Override
  public String getMpackDisplayName() {
    return displayName;
  }

  @Override
  public String getMpackDescription() {
    return description;
  }

  @Override
  public String getMpackLogoUri() {
    return logoUri;
  }

  @Override
  public List<? extends RegistryMpackVersion> getMpackVersions() {
    return mpackVersions == null ? Collections.emptyList() : Collections.unmodifiableList(mpackVersions);
  }

  @Override
  public RegistryMpackVersion getMpackVersion(String mpackVersion)
    throws AmbariException {
    RegistryMpackVersion registryMpackVersion = null;
    if (StringUtils.isBlank(mpackVersion)) {
      throw new AmbariException("Registry mpack version must not be empty");
    }
    for(RegistryMpackVersion rmv : getMpackVersions()) {
      if(rmv.getMpackVersion().equals(mpackVersion)) {
        registryMpackVersion = rmv;
      }
    }
    if(registryMpackVersion == null) {
      throw new RegistryMpackVersionNotFoundException(getMpackName(), mpackVersion);
    }
    return registryMpackVersion;
  }

  void validateAndResolve(URI registryUri) throws AmbariException {
    if (StringUtils.isBlank(id)) {
      throw new AmbariException("Registry mpack id must not be empty");
    }
    if (StringUtils.isBlank(name)) {
      throw new AmbariException("Registry mpack name must not be empty");
    }
    if (StringUtils.isNotBlank(logoUri)) {
      logoUri = RegistryUriLoader.resolve(registryUri, logoUri, "mpack logo URI").toString();
    }
    if (getMpackVersions().isEmpty()) {
      throw new AmbariException("Registry mpack " + name + " must declare at least one version");
    }
    Set<String> versions = new HashSet<>();
    for (JsonRegistryMpackVersion mpackVersion : mpackVersions) {
      if (mpackVersion == null) {
        throw new AmbariException("Registry mpack " + name + " contains a null version");
      }
      mpackVersion.validateAndResolve(registryUri, name);
      if (!versions.add(mpackVersion.getMpackVersion())) {
        throw new AmbariException(
            "Duplicate version " + mpackVersion.getMpackVersion() + " for registry mpack " + name);
      }
    }
  }
}
