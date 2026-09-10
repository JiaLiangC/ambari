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

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.agent.ExecutionCommand;
import org.apache.ambari.server.orm.dao.ClusterServiceDAO;
import org.apache.ambari.server.orm.entities.ClusterServiceEntity;
import org.apache.ambari.server.orm.entities.ClusterServiceEntityPK;
import org.apache.ambari.server.orm.entities.RepositoryVersionEntity;
import org.apache.ambari.server.security.credential.Credential;
import org.apache.ambari.server.security.credential.GenericKeyCredential;
import org.apache.ambari.server.security.credential.PrincipalKeyCredential;
import org.apache.ambari.server.security.encryption.AgentConfigUpdateEncryptor;
import org.apache.ambari.server.security.encryption.AgentEncryptionCapabilities;
import org.apache.ambari.server.security.encryption.CredentialStoreService;
import org.apache.ambari.server.security.encryption.EncryptionService;
import org.apache.ambari.server.security.encryption.Encryptor;
import org.apache.ambari.server.state.Cluster;
import org.apache.ambari.server.state.Clusters;
import org.apache.ambari.server.state.ServiceComponent;
import org.apache.ambari.server.utils.TextEncoding;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.inject.Inject;
import com.google.inject.Singleton;

/** Resolve scoped references using existing credentials and Agent encryption at dispatch. */
@Singleton
public class MpackSecrets {
  @Inject
  private CredentialStoreService credentials;
  @Inject
  private AgentConfigUpdateEncryptor agentEncryption;
  @Inject
  private AgentEncryptionCapabilities capabilities;
  @Inject
  private EncryptionService encryption;
  @Inject
  private Clusters clusters;
  @Inject
  private ClusterServiceDAO services;
  @Inject
  private Gson gson;

  public Map<String, String> pin(Cluster cluster, String service, Map<String, Map<String, String>> configs,
      Set<String> declared) throws AmbariException {
    Set<String> references = new TreeSet<>(declared);
    configs.values().forEach(fields -> fields.values().forEach(value -> {
      if (value != null && value.startsWith("secret://")) { references.add(value); }
    }));
    if (references.size() > 32) {
      throw new AmbariException("Secret reference limit exceeded");
    }
    Map<String, String> generations = new TreeMap<>();
    for (String reference : references) {
      generations.put(reference, fingerprint(reference, read(cluster.getClusterName(), service, reference)));
    }
    return generations;
  }

  public ExecutionCommand forDispatch(ExecutionCommand original, Long hostId) {
    String serialized = original.getCommandParams() == null ? null : original.getCommandParams().get("mpack_task_binding");
    if (serialized == null) { return original; }
    JsonObject binding = JsonParser.parseString(serialized).getAsJsonObject();
    JsonObject generations = binding.getAsJsonObject("secretGenerations");
    if (generations == null || generations.size() == 0) { return original; }
    ExecutionCommand detached = gson.fromJson(gson.toJson(original), ExecutionCommand.class);
    try {
      Cluster cluster = clusters.getClusterById(binding.get("clusterId").getAsLong());
      String service = binding.get("serviceName").getAsString();
      String host = clusters.getHostById(hostId).getHostName();
      if (!host.equals(binding.get("hostName").getAsString()) || !capabilities.supportsAesGcm(hostId)) {
        throw new AmbariException("Scoped AES-GCM Agent delivery is unavailable");
      }
      ClusterServiceEntityPK serviceKey = new ClusterServiceEntityPK();
      serviceKey.setClusterId(binding.get("clusterId").getAsLong());
      serviceKey.setServiceName(service);
      ClusterServiceEntity persisted = services.findByPK(serviceKey);
      ServiceComponent component = cluster.getService(service).getServiceComponent(binding.get("role").getAsString());
      RepositoryVersionEntity repository = component.getDesiredRepositoryVersion();
      if (persisted == null || !binding.get("targetIncarnation").getAsString().equals(persisted.getMpackTargetIncarnation())
          || repository == null || repository.getStack() == null
          || !Long.valueOf(binding.get("packageId").getAsLong()).equals(repository.getStack().getMpackId())) {
        detached.setMpackSecretError("PLAN_STALE");
        return detached;
      }
      if (component.getServiceComponentHost(host) == null) {
        throw new AmbariException("Task host is no longer assigned to the service");
      }
      Map<String, String> material = new TreeMap<>();
      for (Map.Entry<String, com.google.gson.JsonElement> entry : generations.entrySet()) {
        String reference = entry.getKey();
        String value = read(cluster.getClusterName(), service, reference);
        String generation = fingerprint(reference, value);
        if (!generation.equals(entry.getValue().getAsString())) {
          detached.setMpackSecretError("PLAN_STALE");
          return detached;
        }
        String payload = gson.toJson(Map.of("reference", reference, "generation", generation, "value", value));
        material.put(reference, String.format(Encryptor.ENCRYPTED_PROPERTY_GCM_SCHEME,
            encryption.encryptGcm(payload, agentEncryption.getEncryptionKey(), TextEncoding.BIN_HEX)));
      }
      detached.setMpackSecretMaterial(material);
    } catch (AmbariException | RuntimeException unavailable) {
      detached.setMpackSecretError("DEPENDENCY_UNRESOLVED");
    }
    return detached;
  }

  private String read(String cluster, String service, String reference) throws AmbariException {
    String prefix = "secret://mpack." + service + ".";
    if (!reference.startsWith(prefix) || !reference.substring(prefix.length()).matches("[A-Za-z0-9_.-]{1,128}")) {
      throw new AmbariException("Secret reference is outside this service's credential namespace");
    }
    Credential credential = credentials.getCredential(cluster, reference.substring("secret://".length()));
    char[] value = credentialKey(credential);
    if (value == null || value.length == 0 || value.length > 8192) {
      throw new AmbariException("Referenced service credential has an invalid size");
    }
    return new String(value);
  }

  static char[] credentialKey(Credential credential) {
    if (credential instanceof GenericKeyCredential) {
      return ((GenericKeyCredential) credential).getKey();
    }
    // The existing cluster credentials REST API stores PrincipalKeyCredential.
    // Its principal is descriptive; alias and cluster remain the access scope.
    if (credential instanceof PrincipalKeyCredential) {
      return ((PrincipalKeyCredential) credential).getKey();
    }
    return null;
  }

  private String fingerprint(String reference, String value) throws AmbariException {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(agentEncryption.getEncryptionKey().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
      return java.util.HexFormat.of().formatHex(mac.doFinal((reference + "\n" + value).getBytes(StandardCharsets.UTF_8)));
    } catch (GeneralSecurityException failure) {
      throw new AmbariException("Secret generation could not be established");
    }
  }
}
