/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ambari.server.controller;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/** Immutable input for validating or applying one resumable Mpack install. */
public class MpackInstallPlanRequest {
  private Long repositoryVersionId;
  private String serviceName;
  private Map<String, List<String>> assignments;
  private Map<String, Map<String, String>> configurations;
  private boolean validateOnly;

  public MpackInstallPlanRequest() {
  }

  public MpackInstallPlanRequest(Long repositoryVersionId, String serviceName,
      Map<String, List<String>> assignments, Map<String, Map<String, String>> configurations,
      boolean validateOnly) {
    this.repositoryVersionId = repositoryVersionId;
    this.serviceName = serviceName;
    this.assignments = assignments;
    this.configurations = configurations;
    this.validateOnly = validateOnly;
  }

  public Long getRepositoryVersionId() {
    return repositoryVersionId;
  }

  public String getServiceName() {
    return serviceName;
  }

  public Map<String, List<String>> getAssignments() {
    return assignments == null ? Collections.emptyMap() : assignments;
  }

  public Map<String, Map<String, String>> getConfigurations() {
    return configurations == null ? Collections.emptyMap() : configurations;
  }

  public boolean isValidateOnly() {
    return validateOnly;
  }
}
