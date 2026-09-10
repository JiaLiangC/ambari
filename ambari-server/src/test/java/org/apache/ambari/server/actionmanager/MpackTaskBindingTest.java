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
package org.apache.ambari.server.actionmanager;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import org.apache.ambari.server.RoleCommand;
import org.apache.ambari.server.agent.ExecutionCommand;
import org.apache.ambari.server.api.services.AmbariMetaInfo;
import org.apache.ambari.server.events.publishers.AmbariEventPublisher;
import org.apache.ambari.server.orm.dao.ClusterServiceDAO;
import org.apache.ambari.server.orm.dao.MpackDAO;
import org.apache.ambari.server.orm.entities.ClusterServiceEntity;
import org.apache.ambari.server.orm.entities.MpackEntity;
import org.apache.ambari.server.orm.entities.RepositoryVersionEntity;
import org.apache.ambari.server.orm.entities.ServiceDesiredStateEntity;
import org.apache.ambari.server.orm.entities.StackEntity;
import org.apache.ambari.server.state.Cluster;
import org.apache.ambari.server.state.Clusters;
import org.apache.ambari.server.state.ConfigHelper;
import org.apache.ambari.server.state.Mpack;
import org.apache.ambari.server.state.ServiceInfo;
import org.junit.Test;

/** The same producer is invoked immediately before execution_command persistence. */
public class MpackTaskBindingTest {
  @Test
  public void testPersistedCommandPinsIdentityAndOnlyItsServiceConfig() throws Exception {
    ActionDBAccessorImpl accessor = new ActionDBAccessorImpl(10, mock(AmbariEventPublisher.class));
    accessor.mpackServiceDAO = mock(ClusterServiceDAO.class);
    accessor.mpackDAO = mock(MpackDAO.class);
    AmbariMetaInfo metaInfo = mock(AmbariMetaInfo.class);
    accessor.mpackMetaInfo = () -> metaInfo;
    ConfigHelper configHelper = mock(ConfigHelper.class);
    accessor.mpackConfigHelper = () -> configHelper;
    accessor.clusters = mock(Clusters.class);
    Cluster cluster = mock(Cluster.class);
    ServiceInfo info = mock(ServiceInfo.class);
    StackEntity stack = new StackEntity();
    stack.setStackName("HOST_PACKAGE");
    stack.setStackVersion("1");
    stack.setMpackId(4L);
    RepositoryVersionEntity repository = new RepositoryVersionEntity();
    repository.setStack(stack);
    ServiceDesiredStateEntity desired = new ServiceDesiredStateEntity();
    desired.setDesiredRepositoryVersion(repository);
    ClusterServiceEntity service = new ClusterServiceEntity();
    service.setServiceDesiredStateEntity(desired);
    MpackEntity pack = new MpackEntity();
    String digest = "a".repeat(64);
    String fixtureRoot = System.getProperty("mpack.host.fixture");
    if (fixtureRoot != null) {
      digest = new com.google.gson.Gson().fromJson(java.nio.file.Files.readString(
          java.nio.file.Path.of(fixtureRoot, "mpack.json")), Mpack.class).getPackageDigest();
    }
    pack.setContentDigest(digest);
    when(accessor.mpackServiceDAO.findByPKForUpdate(any())).thenReturn(service);
    when(accessor.mpackServiceDAO.getOrCreateMpackTargetIncarnation(1L, "HTTP_ECHO"))
        .thenReturn("00000000-0000-0000-0000-000000000001");
    when(accessor.mpackDAO.findById(4L)).thenReturn(pack);
    when(accessor.clusters.getClusterById(1L)).thenReturn(cluster);
    when(cluster.getDesiredConfigs()).thenReturn(Collections.emptyMap());
    Map<String, Map<String, String>> tags = Map.of("http", Map.of("tag", "v1"));
    when(configHelper.getEffectiveDesiredTags(cluster, "host1", Collections.emptyMap())).thenReturn(tags);
    when(configHelper.getEffectiveConfigProperties(cluster, tags)).thenReturn(
        Map.of("http", Map.of("port", "18080"), "unrelated", Map.of("private", "not-forwarded")));
    when(metaInfo.getService("HOST_PACKAGE", "1", "HTTP_ECHO")).thenReturn(info);
    when(info.getConfigTypeAttributes()).thenReturn(Map.of("http", Collections.emptyMap()));
    ExecutionCommand command = new ExecutionCommand();
    command.setClusterId("1");
    command.setTaskId(5L);
    command.setServiceName("HTTP_ECHO");
    command.setHostname("host1");
    command.setRole("HTTP_ECHO_SERVER");
    command.setRoleCommand(RoleCommand.START);
    command.setCommandParams(new TreeMap<>());
    command.setOverrideConfigs(true);
    accessor.pinMpackTask(command, 1L);
    com.google.gson.Gson gson = new com.google.gson.Gson();
    ExecutionCommand restored = gson.fromJson(gson.toJson(command), ExecutionCommand.class);
    assertEquals(Map.of("http", Map.of("port", "18080")), restored.getConfigurations());
    assertFalse(restored.isOverrideConfigs());
    Map<?, ?> binding = gson.fromJson(restored.getCommandParams().get("mpack_task_binding"), Map.class);
    assertEquals("HTTP_ECHO", binding.get("serviceName"));
    assertEquals(digest, binding.get("packageDigest"));
    Map<?, ?> hashes = (Map<?, ?>) binding.get("configurationHashes");
    assertEquals(org.apache.commons.codec.digest.DigestUtils.sha256Hex("18080"), ((Map<?, ?>) hashes.get("http")).get("port"));
    assertFalse(gson.toJson(binding).contains("not-forwarded"));
    String output = System.getProperty("mpack.task.fixture");
    if (output != null) {
      org.apache.ambari.server.agent.stomp.dto.MetadataServiceInfo metadata =
          new org.apache.ambari.server.agent.stomp.dto.MetadataServiceInfo("1", false, null, 60L, "package");
      metadata.setMpackTarget(digest, restored.getCommandParams().get("mpack_target_incarnation"));
      Map<String, Object> envelope = Map.of("command", new com.fasterxml.jackson.databind.ObjectMapper().readTree(gson.toJson(restored)),
          "serviceMetadata", new com.fasterxml.jackson.databind.ObjectMapper().valueToTree(metadata));
      java.nio.file.Files.writeString(java.nio.file.Path.of(output),
          new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(envelope));
    }
    command.setClusterId("2");
    assertThrows(org.apache.ambari.server.AmbariException.class, () -> accessor.pinMpackTask(command, 1L));
  }
}
