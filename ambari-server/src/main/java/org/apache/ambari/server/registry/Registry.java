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
package org.apache.ambari.server.registry;

import java.util.List;

import org.apache.ambari.server.AmbariException;

/**
 * Represents a single instance of a software registry
 */
public interface Registry {
  /**
   * Get software registry id
   * @return registry id
   */
  public Long getRegistryId();

  /**
   * Get software registry name
   * @return registry name
   */
  public String getRegistryName();

  /**
   * Get software registry type
   * @return registry type
   */
  public RegistryType getRegistryType();

  /**
   * Get software registry Uri
   * @return registry uri
   */
  public String getRegistryUri();

  /**
   * Get list of scenarios defined in the software registry
   * @return list of {@link RegistryScenario}'s
   */
  List<? extends RegistryScenario> getRegistryScenarios() throws AmbariException;

  /**
   *
   * @return
   */
  RegistryScenario getRegistryScenario(String scenarioName) throws AmbariException;

  /**
   * Get list of mpacks defined in the software registry
   * @return list of {@link RegistryMpack}'s
   */
  List<? extends RegistryMpack> getRegistryMpacks() throws AmbariException;

  /**
   * Get specific mpack from the software registry
   * @return {@link RegistryMpack}
   */
  RegistryMpack getRegistryMpack(String mpackName) throws AmbariException;

  /** Loads and validates the referenced registry document. */
  void validate() throws AmbariException;
}
