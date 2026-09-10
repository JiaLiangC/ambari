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
package org.apache.ambari.server.mpack;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.util.Map;
import java.util.Set;

import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.agent.ExecutionCommand;
import org.apache.ambari.server.security.credential.GenericKeyCredential;
import org.apache.ambari.server.security.encryption.AESEncryptionService;
import org.apache.ambari.server.security.encryption.AgentConfigUpdateEncryptor;
import org.apache.ambari.server.security.encryption.AgentEncryptionCapabilities;
import org.apache.ambari.server.security.encryption.CredentialStoreService;
import org.apache.ambari.server.state.Cluster;
import org.apache.ambari.server.state.Clusters;
import org.apache.ambari.server.state.Host;
import org.apache.ambari.server.state.Service;
import org.apache.ambari.server.state.ServiceComponent;
import org.junit.Test;

import com.google.gson.Gson;

public class MpackSecretsTest {
  private static void inject(Object target, String name, Object value) throws Exception {
    Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true); field.set(target, value);
  }

  @Test
  public void testScopedDispatchEncryptsDetachedCopyAndRejectsRotatedCredential() throws Exception {
    MpackSecrets resolver = new MpackSecrets();
    CredentialStoreService store = mock(CredentialStoreService.class);
    AgentConfigUpdateEncryptor encryptor = mock(AgentConfigUpdateEncryptor.class);
    AgentEncryptionCapabilities capabilities = mock(AgentEncryptionCapabilities.class);
    Clusters clusters = mock(Clusters.class); Cluster cluster = mock(Cluster.class);
    org.apache.ambari.server.orm.dao.ClusterServiceDAO services = mock(org.apache.ambari.server.orm.dao.ClusterServiceDAO.class);
    org.apache.ambari.server.orm.entities.ClusterServiceEntity persisted = new org.apache.ambari.server.orm.entities.ClusterServiceEntity();
    persisted.setMpackTargetIncarnation("00000000-0000-0000-0000-000000000001");
    when(services.findByPK(any())).thenReturn(persisted);
    org.apache.ambari.server.orm.entities.StackEntity stack = new org.apache.ambari.server.orm.entities.StackEntity();
    stack.setMpackId(4L);
    org.apache.ambari.server.orm.entities.RepositoryVersionEntity repository = new org.apache.ambari.server.orm.entities.RepositoryVersionEntity();
    repository.setStack(stack);
    Host host = mock(Host.class); Service service = mock(Service.class); ServiceComponent component = mock(ServiceComponent.class);
    String key = java.util.UUID.randomUUID().toString();
    String value = java.util.UUID.randomUUID().toString();
    String reference = "secret://mpack.HTTP_ECHO.password";
    when(store.getCredential("consumer", "mpack.HTTP_ECHO.password")).thenReturn(
        new org.apache.ambari.server.security.credential.PrincipalKeyCredential("mpack", value));
    when(encryptor.getEncryptionKey()).thenReturn(key);
    when(capabilities.supportsAesGcm(10L)).thenReturn(true);
    when(clusters.getClusterById(1L)).thenReturn(cluster);
    when(cluster.getClusterName()).thenReturn("consumer");
    when(cluster.getService("HTTP_ECHO")).thenReturn(service);
    when(service.getServiceComponent("HTTP_ECHO_SERVER")).thenReturn(component);
    when(component.getDesiredRepositoryVersion()).thenReturn(repository);
    when(component.getServiceComponentHost("host1")).thenReturn(mock(org.apache.ambari.server.state.ServiceComponentHost.class));
    when(clusters.getHostById(10L)).thenReturn(host); when(host.getHostName()).thenReturn("host1");
    inject(resolver, "credentials", store); inject(resolver, "agentEncryption", encryptor);
    inject(resolver, "capabilities", capabilities); inject(resolver, "clusters", clusters);
    inject(resolver, "services", services);
    inject(resolver, "encryption", new AESEncryptionService()); inject(resolver, "gson", new Gson());
    Map<String, String> generations = resolver.pin(cluster, "HTTP_ECHO", Map.of("http", Map.of("password", reference)), Set.of());
    assertEquals(64, generations.get(reference).length());
    assertThrows(AmbariException.class, () -> resolver.pin(cluster, "OTHER", Map.of(), Set.of(reference)));
    ExecutionCommand command = new ExecutionCommand(); command.setClusterId("1"); command.setServiceName("HTTP_ECHO");
    command.setHostname("host1"); command.setRole("HTTP_ECHO_SERVER"); command.setTaskId(5L);
    Map<String, Object> binding = Map.of("clusterId", 1, "serviceName", "HTTP_ECHO", "role", "HTTP_ECHO_SERVER",
        "hostName", "host1", "secretGenerations", generations, "packageId", 4L,
        "targetIncarnation", persisted.getMpackTargetIncarnation());
    command.setCommandParams(Map.of("mpack_task_binding", new Gson().toJson(binding)));
    command.setConfigurations(Map.of("http", Map.of("password", reference)));
    ExecutionCommand detached = resolver.forDispatch(command, 10L);
    assertNotSame(command, detached); assertNull(command.getMpackSecretMaterial());
    assertFalse(new Gson().toJson(command).contains(value));
    assertFalse(new Gson().toJson(detached).contains(value));
    assertTrue(detached.getMpackSecretMaterial().get(reference).startsWith("${enc=aes256_gcm_hex, value="));
    String fixture = System.getProperty("mpack.secret.fixture");
    if (fixture != null) {
      java.nio.file.Files.writeString(java.nio.file.Path.of(fixture), new Gson().toJson(Map.of(
          "command", detached, "encryptionKey", key, "expectedValue", value)));
    }
    when(store.getCredential("consumer", "mpack.HTTP_ECHO.password"))
        .thenReturn(new GenericKeyCredential(java.util.UUID.randomUUID().toString().toCharArray()));
    ExecutionCommand stale = resolver.forDispatch(command, 10L);
    assertEquals("PLAN_STALE", stale.getMpackSecretError()); assertNull(stale.getMpackSecretMaterial());
    assertNull(command.getMpackSecretError());
    clearInvocations(store);
    persisted.setMpackTargetIncarnation("00000000-0000-0000-0000-000000000002");
    ExecutionCommand recreated = resolver.forDispatch(command, 10L);
    assertEquals("PLAN_STALE", recreated.getMpackSecretError());
    assertNull(recreated.getMpackSecretMaterial());
    verifyNoInteractions(store);
    persisted.setMpackTargetIncarnation("00000000-0000-0000-0000-000000000001");
    stack.setMpackId(5L);
    ExecutionCommand changedPackage = resolver.forDispatch(command, 10L);
    assertEquals("PLAN_STALE", changedPackage.getMpackSecretError());
    assertNull(changedPackage.getMpackSecretMaterial());
    verifyNoInteractions(store);
  }
}
