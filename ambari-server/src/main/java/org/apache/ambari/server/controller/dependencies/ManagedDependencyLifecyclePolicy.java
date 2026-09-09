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
package org.apache.ambari.server.controller.dependencies;

import java.util.Collection;

import org.apache.ambari.server.orm.dao.ServiceDependencyDAO;
import org.apache.ambari.server.state.Cluster;

import com.google.inject.Inject;
import com.google.inject.Singleton;

/** Enforces dependency ownership at the lower service lifecycle boundary. */
@Singleton
public class ManagedDependencyLifecyclePolicy {
  private static final String CONSUMER_SERVICE = "HBASE";

  private final ServiceDependencyDAO dependencyDAO;

  @Inject
  public ManagedDependencyLifecyclePolicy(ServiceDependencyDAO dependencyDAO) {
    this.dependencyDAO = dependencyDAO;
  }

  /**
   * Must run while the cluster write lock is held. Binding publication holds
   * both parent cluster read locks through commit, making this check and the
   * subsequent service removal one lifecycle boundary.
   */
  public void validateServiceDeletion(Cluster cluster, Collection<String> serviceNames) {
    long clusterId = cluster.getClusterId();
    for (String serviceName : serviceNames) {
      if (!dependencyDAO.findByProvider(clusterId, serviceName).isEmpty()) {
        throw conflict("DEPENDENCY_PROVIDER_DELETE_BLOCKED",
            "The service provides an active managed dependency; detach every dependent first.");
      }
      if (CONSUMER_SERVICE.equals(serviceName)
          && !dependencyDAO.findByConsumer(clusterId, serviceName).isEmpty()) {
        throw conflict("DEPENDENCY_CONSUMER_DELETE_REQUIRES_DETACH",
            "The HBASE service has an active managed dependency; detach it before deletion.");
      }
    }
  }

  private ManagedDependencyIntegrationException conflict(String code, String message) {
    return new ManagedDependencyIntegrationException(409, code, message);
  }
}
