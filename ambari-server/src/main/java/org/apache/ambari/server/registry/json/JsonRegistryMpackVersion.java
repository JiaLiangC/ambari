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
import org.apache.ambari.server.registry.RegistryMpackDependency;
import org.apache.ambari.server.registry.RegistryMpackVersion;
import org.apache.ambari.server.state.Module;
import org.apache.ambari.server.utils.MpackVersion;
import org.apache.commons.lang3.StringUtils;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import com.google.gson.annotations.SerializedName;

/**
 * JSON implemenation of {@link RegistryMpackVersion}
 */
public class JsonRegistryMpackVersion implements RegistryMpackVersion {
  @SerializedName("version")
  private String version;

  @SerializedName("mpackUri")
  private String mpackUri;

  @SerializedName("docUri")
  private String docUri;

  @SerializedName("dependencies")
  private ArrayList<JsonRegistryMpackDependency> dependencies;

  private volatile List<Module> modules;
  private transient String expectedMpackName;

  @Override
  public String getMpackVersion() {
    return version;
  }

  @Override
  public String getMpackUri() {
    return mpackUri;
  }

  @Override
  public String getMpackDocUri() {
    return docUri;
  }

  @Override
  public List<? extends RegistryMpackDependency> getDependencies() {
    return dependencies == null ? Collections.emptyList() : Collections.unmodifiableList(dependencies);
  }

  @Override
  public List<Module> getModules() throws AmbariException {
    List<Module> result = modules;
    if (result == null) {
      synchronized (this) {
        result = modules;
        if (result == null) {
          URI uri = RegistryUriLoader.parseAbsolute(mpackUri, "mpack metadata URI");
          String json = RegistryUriLoader.readUtf8(uri, 1024L * 1024L, "mpack metadata");
          org.apache.ambari.server.state.Mpack mpack;
          try {
            mpack = new Gson().fromJson(json, org.apache.ambari.server.state.Mpack.class);
          } catch (JsonParseException e) {
            throw new AmbariException("Unable to parse mpack metadata", e);
          }
          if (mpack == null) {
            throw new AmbariException("Mpack metadata is empty");
          }
          if (!expectedMpackName.equals(mpack.getName()) || !version.equals(mpack.getVersion())) {
            throw new AmbariException("Mpack metadata identity does not match the registry entry");
          }
          result = mpack.getModules() == null
              ? Collections.emptyList()
              : Collections.unmodifiableList(new ArrayList<>(mpack.getModules()));
          modules = result;
        }
      }
    }
    return result;
  }

  void validateAndResolve(URI registryUri, String mpackName) throws AmbariException {
    if (StringUtils.isBlank(version)) {
      throw new AmbariException("Registry mpack version must not be empty");
    }
    parseVersion(version, "registry mpack version");
    expectedMpackName = mpackName;
    mpackUri = RegistryUriLoader.resolve(registryUri, mpackUri, "mpack metadata URI").toString();
    if (StringUtils.isNotBlank(docUri)) {
      docUri = RegistryUriLoader.resolve(registryUri, docUri, "mpack documentation URI").toString();
    }
    Set<String> dependencyNames = new HashSet<>();
    for (RegistryMpackDependency dependency : getDependencies()) {
      if (dependency == null || StringUtils.isBlank(dependency.getName())) {
        throw new AmbariException("Registry mpack version " + version + " has an empty dependency name");
      }
      if (!dependencyNames.add(dependency.getName())) {
        throw new AmbariException("Registry mpack version " + version
            + " contains duplicate dependency " + dependency.getName());
      }
      MpackVersion minimum = StringUtils.isBlank(dependency.getMinVersion()) ? null
          : parseVersion(dependency.getMinVersion(), "dependency minimum version");
      MpackVersion maximum = StringUtils.isBlank(dependency.getMaxVersion()) ? null
          : parseVersion(dependency.getMaxVersion(), "dependency maximum version");
      if (minimum != null && maximum != null && minimum.compareTo(maximum) >= 0) {
        throw new AmbariException("Dependency " + dependency.getName()
            + " must have a minimum version lower than its exclusive maximum version");
      }
    }
  }

  private MpackVersion parseVersion(String value, String description) throws AmbariException {
    try {
      return MpackVersion.parse(value, false);
    } catch (IllegalArgumentException e) {
      throw new AmbariException("Invalid " + description + ": " + value, e);
    }
  }
}
