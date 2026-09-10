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
package org.apache.ambari.server.orm.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;

/** Durable native ownership evidence, independent of service and task log retention. */
@Entity
@Table(name = "mpack_target_resource")
public class MpackTargetResourceEntity {
  @Id
  @Column(name = "target_key", length = 64, nullable = false)
  private String targetKey;
  @Column(name = "cluster_id", nullable = false)
  private Long clusterId;
  @Column(name = "service_name", nullable = false)
  private String serviceName;
  @Column(name = "target_incarnation", length = 36, nullable = false)
  private String targetIncarnation;
  @Column(name = "host_name", nullable = false)
  private String hostName;
  @Column(name = "component_name", nullable = false)
  private String componentName;
  @Column(name = "mpack_id")
  private Long mpackId;
  @Column(name = "materialized_mpack_id")
  private Long materializedMpackId;
  @Column(name = "task_id", nullable = false)
  private Long taskId;
  @Column(name = "resource_state", length = 32, nullable = false)
  private String resourceState;
  @Lob
  @Column(name = "task_binding", nullable = false)
  private String taskBinding;
  @Lob
  @Column(name = "resource_evidence")
  private String resourceEvidence;
  public String getTargetKey() { return targetKey; }
  public void setTargetKey(String value) { targetKey = value; }
  public Long getClusterId() { return clusterId; }
  public void setClusterId(Long value) { clusterId = value; }
  public String getServiceName() { return serviceName; }
  public void setServiceName(String value) { serviceName = value; }
  public String getTargetIncarnation() { return targetIncarnation; }
  public void setTargetIncarnation(String value) { targetIncarnation = value; }
  public String getHostName() { return hostName; }
  public void setHostName(String value) { hostName = value; }
  public String getComponentName() { return componentName; }
  public void setComponentName(String value) { componentName = value; }
  public Long getMpackId() { return mpackId; }
  public void setMpackId(Long value) { mpackId = value; }
  public Long getMaterializedMpackId() { return materializedMpackId; }
  public void setMaterializedMpackId(Long value) { materializedMpackId = value; }
  public Long getTaskId() { return taskId; }
  public void setTaskId(Long value) { taskId = value; }
  public String getResourceState() { return resourceState; }
  public void setResourceState(String value) { resourceState = value; }
  public String getTaskBinding() { return taskBinding; }
  public void setTaskBinding(String value) { taskBinding = value; }
  public String getResourceEvidence() { return resourceEvidence; }
  public void setResourceEvidence(String value) { resourceEvidence = value; }
}
