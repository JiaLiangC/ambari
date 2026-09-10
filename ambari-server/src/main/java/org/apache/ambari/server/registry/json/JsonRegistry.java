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
package org.apache.ambari.server.registry.json;

import java.net.URI;
import java.util.List;

import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.exceptions.RegistryMpackNotFoundException;
import org.apache.ambari.server.exceptions.RegistryScenarioNotFoundException;
import org.apache.ambari.server.orm.entities.RegistryEntity;
import org.apache.ambari.server.registry.Registry;
import org.apache.ambari.server.registry.RegistryMpack;
import org.apache.ambari.server.registry.RegistryScenario;
import org.apache.ambari.server.registry.RegistryType;
import org.apache.commons.lang3.StringUtils;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;

/** JSON-backed software registry with bounded, lazy document loading. */
public class JsonRegistry implements Registry {
  private static final long MAX_REGISTRY_BYTES = 4L * 1024L * 1024L;

  private final RegistryEntity registryEntity;
  private final Gson gson;
  private volatile JsonRegistryDefinition registryDefinition;

  public JsonRegistry(RegistryEntity registryEntity, Gson gson) {
    this.registryEntity = registryEntity;
    this.gson = gson;
  }

  @Override
  public Long getRegistryId() {
    return registryEntity.getRegistryId();
  }

  @Override
  public String getRegistryName() {
    return registryEntity.getRegistryName();
  }

  @Override
  public RegistryType getRegistryType() {
    return registryEntity.getRegistryType();
  }

  @Override
  public String getRegistryUri() {
    return registryEntity.getRegistryUri();
  }

  @Override
  public List<? extends RegistryScenario> getRegistryScenarios() throws AmbariException {
    return definition().getScenarios();
  }

  @Override
  public RegistryScenario getRegistryScenario(String scenarioName) throws AmbariException {
    if (StringUtils.isBlank(scenarioName)) {
      throw new AmbariException("Registry scenario name must not be empty");
    }
    for (RegistryScenario scenario : getRegistryScenarios()) {
      if (scenarioName.equals(scenario.getScenarioName())) {
        return scenario;
      }
    }
    throw new RegistryScenarioNotFoundException(getRegistryName(), scenarioName);
  }

  @Override
  public List<? extends RegistryMpack> getRegistryMpacks() throws AmbariException {
    return definition().getMpacks();
  }

  @Override
  public RegistryMpack getRegistryMpack(String mpackName) throws AmbariException {
    if (StringUtils.isBlank(mpackName)) {
      throw new AmbariException("Registry mpack name must not be empty");
    }
    for (RegistryMpack mpack : getRegistryMpacks()) {
      if (mpackName.equals(mpack.getMpackName())) {
        return mpack;
      }
    }
    throw new RegistryMpackNotFoundException(getRegistryName(), mpackName);
  }

  @Override
  public void validate() throws AmbariException {
    definition();
  }

  private JsonRegistryDefinition definition() throws AmbariException {
    JsonRegistryDefinition result = registryDefinition;
    if (result == null) {
      synchronized (this) {
        result = registryDefinition;
        if (result == null) {
          URI uri = RegistryUriLoader.parseAbsolute(getRegistryUri(), "registry URI");
          String json = RegistryUriLoader.readUtf8(uri, MAX_REGISTRY_BYTES, "registry document");
          try {
            result = gson.fromJson(json, JsonRegistryDefinition.class);
          } catch (JsonParseException e) {
            throw new AmbariException("Unable to parse registry document", e);
          }
          if (result == null) {
            throw new AmbariException("Registry document is empty");
          }
          result.validateAndResolve(uri);
          registryDefinition = result;
        }
      }
    }
    return result;
  }
}
