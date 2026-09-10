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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;
import java.util.HexFormat;

import org.apache.ambari.server.configuration.Configuration;
import org.apache.ambari.server.state.Mpack;
import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class MpackTrustTest {
  @Rule
  public TemporaryFolder temporary = new TemporaryFolder();
  private Path archive;
  private Path trustPath;
  private JsonObject metadata;
  private JsonObject trust;
  private JsonObject keyEntry;
  private KeyPair key;
  private Configuration configuration;

  @Before
  public void prepare() throws Exception {
    archive = temporary.newFile("definition.tar.gz").toPath();
    Files.writeString(archive, "signed archive fixture");
    key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String keyId = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key.getPublic().getEncoded()));
    metadata = new JsonObject();
    metadata.addProperty("id", "publisher-4-team-example");
    metadata.addProperty("name", "publisher-4-team-example");
    metadata.addProperty("publisher", "team");
    metadata.addProperty("packageName", "example");
    metadata.addProperty("version", "1");
    metadata.addProperty("displayName", "Example \u4e2d\u6587");
    metadata.addProperty("signatureKeyId", keyId);
    metadata.addProperty("signatureAlgorithm", "Ed25519");
    metadata.addProperty("signatureFormat", "mpack-publisher/v1");
    metadata.addProperty("authoringFormat", "mpack.ambari.apache.org/host-service/v1");
    metadata.addProperty("packageDigest", "a".repeat(64));
    metadata.addProperty("manifestDigest", "b".repeat(64));
    metadata.addProperty("definitionSha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(archive))));
    sign();
    keyEntry = new JsonObject();
    keyEntry.addProperty("publicKey", Base64.getEncoder().encodeToString(key.getPublic().getEncoded()));
    keyEntry.addProperty("status", "active");
    JsonObject keys = new JsonObject();
    keys.add(keyId, keyEntry);
    JsonObject publisher = new JsonObject();
    publisher.add("keys", keys);
    JsonObject publishers = new JsonObject();
    publishers.add("team", publisher);
    trust = new JsonObject();
    trust.addProperty("version", 1);
    trust.add("publishers", publishers);
    trustPath = temporary.newFile("trust.json").toPath();
    configuration = EasyMock.createNiceMock(Configuration.class);
    EasyMock.expect(configuration.getProperty("mpack.trust.store.file")).andReturn(trustPath.toString()).anyTimes();
    EasyMock.expect(configuration.getServerVersion()).andReturn("3.1.0.0-SNAPSHOT").anyTimes();
    EasyMock.replay(configuration);
  }

  private void sign() throws Exception {
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(key.getPrivate());
    signer.update(MpackTrust.envelope(metadata));
    metadata.addProperty("signature", Base64.getEncoder().encodeToString(signer.sign()));
  }

  private void verify() throws Exception {
    Files.writeString(trustPath, trust.toString());
    Mpack mpack = new Gson().fromJson(metadata, Mpack.class);
    mpack.setAuthoringMetadata(metadata);
    MpackTrust.verify(mpack, archive, configuration);
  }

  @Test
  public void rejectsMetadataAndArtifactTampering() throws Exception {
    verify();
    metadata.addProperty("displayName", "changed");
    Assert.assertThrows(IOException.class, this::verify);
    sign();
    verify();
    Files.writeString(archive, "changed bytes");
    Assert.assertThrows(IOException.class, this::verify);
  }

  @Test
  public void rejectsRevokedExpiredAndForeignPublisherKeys() throws Exception {
    keyEntry.addProperty("status", "revoked");
    Assert.assertThrows(IOException.class, this::verify);
    keyEntry.addProperty("status", "active");
    keyEntry.addProperty("notAfter", "2000-01-01T00:00:00Z");
    Assert.assertThrows(IOException.class, this::verify);
    keyEntry.remove("notAfter");
    metadata.addProperty("publisher", "other");
    metadata.addProperty("name", "publisher-5-other-example");
    metadata.addProperty("id", "publisher-5-other-example");
    sign();
    Assert.assertThrows(IOException.class, this::verify);
  }

  @Test
  public void verifiesVersionRequirements() throws Exception {
    MpackTrust.requireVersion("3.1.0.0-SNAPSHOT", ">=3.1,<4");
    Assert.assertThrows(IOException.class, () -> MpackTrust.requireVersion("3.1", ">=4"));
    Assert.assertThrows(IOException.class, () -> MpackTrust.requireVersion("3.1", "^3"));
    Assert.assertThrows(IOException.class, () -> MpackTrust.requireVersion(null, ">=3"));
  }

  @Test
  public void verifiesActualPythonPublisherEnvelopeWhenProvided() throws Exception {
    String fixture = System.getProperty("mpack.publisher.fixture");
    org.junit.Assume.assumeNotNull(fixture);
    Path directory = Path.of(fixture);
    metadata = JsonParser.parseString(Files.readString(directory.resolve("mpack.json"))).getAsJsonObject();
    archive = directory.resolve("definition.tar.gz");
    trust = JsonParser.parseString(Files.readString(directory.resolve("../trust.json"))).getAsJsonObject();
    verify();
  }
}
