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
import org.apache.commons.lang3.StringUtils;

import com.google.gson.annotations.SerializedName;

/**
 * Json Registry Definition
 */
public class JsonRegistryDefinition {

  /**
   * List of scenarios defined in the software registry
   */
  @SerializedName("scenarios")
  private ArrayList<JsonRegistryScenario> scenarios;

  /**
   * List of mpacks defined in the software registry
   */
  @SerializedName("mpacks")
  private ArrayList<JsonRegistryMpack> mpacks;

  /**
   * Get list of scenarios
   * @return
   */
  public List<JsonRegistryScenario> getScenarios() {
    return scenarios == null ? Collections.emptyList() : Collections.unmodifiableList(scenarios);
  }

  /**
   * Get list of mpacks
   * @return
   */
  public List<JsonRegistryMpack> getMpacks() {
    return mpacks == null ? Collections.emptyList() : Collections.unmodifiableList(mpacks);
  }

  void validateAndResolve(URI registryUri) throws AmbariException {
    Set<String> mpackNames = new HashSet<>();
    Set<String> mpackIds = new HashSet<>();
    for (JsonRegistryMpack mpack : getMpacks()) {
      if (mpack == null) {
        throw new AmbariException("Registry document contains a null mpack");
      }
      mpack.validateAndResolve(registryUri);
      if (!mpackNames.add(mpack.getMpackName())) {
        throw new AmbariException("Duplicate registry mpack name: " + mpack.getMpackName());
      }
      if (!mpackIds.add(mpack.getMpackId())) {
        throw new AmbariException("Duplicate registry mpack id: " + mpack.getMpackId());
      }
    }

    for (JsonRegistryMpack mpack : getMpacks()) {
      for (RegistryMpackVersion version : mpack.getMpackVersions()) {
        for (RegistryMpackDependency dependency : version.getDependencies()) {
          if (!mpackNames.contains(dependency.getName())) {
            throw new AmbariException("Registry mpack " + mpack.getMpackName()
                + " references unknown dependency " + dependency.getName());
          }
          if (mpack.getMpackName().equals(dependency.getName())) {
            throw new AmbariException("Registry mpack " + mpack.getMpackName()
                + " must not depend on itself");
          }
        }
      }
    }

    Set<String> scenarioNames = new HashSet<>();
    for (JsonRegistryScenario scenario : getScenarios()) {
      if (scenario == null || StringUtils.isBlank(scenario.getScenarioName())) {
        throw new AmbariException("Registry scenario name must not be empty");
      }
      if (!scenarioNames.add(scenario.getScenarioName())) {
        throw new AmbariException("Duplicate registry scenario: " + scenario.getScenarioName());
      }
      scenario.validate(mpackNames);
    }
  }
}
