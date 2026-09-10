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
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;

import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.controller.MpackRequest;
import org.apache.ambari.server.controller.MpackResponse;
import org.apache.ambari.server.orm.dao.MpackDAO;
import org.apache.ambari.server.orm.dao.StackDAO;
import org.apache.ambari.server.orm.entities.MpackEntity;
import org.apache.ambari.server.orm.entities.StackEntity;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class MpackManagerTest {
  private static final String MPACK_NAME = "TEST";
  private static final String MPACK_VERSION = "1.0";
  private static final String DEFINITION = "test-definition.tar.gz";

  @Rule
  public TemporaryFolder temporaryFolder = new TemporaryFolder();

  private Path repository;
  private Path staging;
  private Path stackRoot;
  private MpackDAO mpackDAO;
  private StackDAO stackDAO;
  private MpackManager manager;

  @Before
  public void setUp() throws IOException {
    repository = temporaryFolder.newFolder("repository").toPath();
    staging = temporaryFolder.newFolder("staging").toPath();
    stackRoot = temporaryFolder.newFolder("stacks").toPath();
    mpackDAO = EasyMock.createMock(MpackDAO.class);
    stackDAO = EasyMock.createMock(StackDAO.class);
    manager = new MpackManager(staging.toFile(), stackRoot.toFile(), mpackDAO, stackDAO);
  }

  @Test
  public void testExtractTarRejectsTraversal() throws Exception {
    Path archive = repository.resolve("traversal.tar.gz");
    writeArchive(archive, "../outside.txt", "outside");

    IOException error = Assert.assertThrows(IOException.class,
        () -> manager.extractTar(archive, staging.resolve("extract")));

    Assert.assertTrue(error.getMessage().contains("escapes the destination"));
    Assert.assertFalse(Files.exists(staging.getParent().resolve("outside.txt")));
  }

  @Test
  public void testRegisterPublishesPreparedMpack() throws Exception {
    Path metadata = createRepositoryMpack();
    expectAvailableChecks();
    EasyMock.expect(mpackDAO.create(EasyMock.anyObject(MpackEntity.class))).andAnswer(() -> 41L);
    EasyMock.expect(stackDAO.find(MPACK_NAME, MPACK_VERSION)).andReturn(null);
    stackDAO.create(EasyMock.anyObject(StackEntity.class));
    EasyMock.expectLastCall();
    EasyMock.replay(mpackDAO, stackDAO);

    MpackResponse response = manager.registerMpack(requestFor(metadata));

    Path installed = staging.resolve(MPACK_NAME).resolve(MPACK_VERSION);
    Path stackLink = stackRoot.resolve(MPACK_NAME).resolve(MPACK_VERSION);
    Assert.assertEquals(Long.valueOf(41), response.getId());
    Assert.assertTrue(Files.isRegularFile(installed.resolve("mpack.json")));
    Assert.assertTrue(Files.isRegularFile(installed.resolve("metainfo.xml")));
    Assert.assertTrue(Files.isRegularFile(installed.resolve("README.txt")));
    Assert.assertTrue(Files.isSymbolicLink(stackLink));
    Assert.assertEquals(installed, Files.readSymbolicLink(stackLink));
    Assert.assertEquals(response.getMpackName(), manager.getMpackMap().get(41L).getName());
    assertRequestStagingEmpty();
    EasyMock.verify(mpackDAO, stackDAO);
  }

  @Test
  public void testRegisterRollsBackFilesystemWhenStackPersistenceFails() throws Exception {
    Path metadata = createRepositoryMpack();
    expectAvailableChecks();
    EasyMock.expect(mpackDAO.create(EasyMock.anyObject(MpackEntity.class))).andReturn(42L);
    EasyMock.expect(stackDAO.find(MPACK_NAME, MPACK_VERSION)).andReturn(null);
    stackDAO.create(EasyMock.anyObject(StackEntity.class));
    EasyMock.expectLastCall().andThrow(new AmbariException("database failure"));
    mpackDAO.removeById(42L);
    EasyMock.expectLastCall();
    EasyMock.replay(mpackDAO, stackDAO);

    Assert.assertThrows(IOException.class, () -> manager.registerMpack(requestFor(metadata)));

    Assert.assertFalse(Files.exists(staging.resolve(MPACK_NAME)));
    Assert.assertFalse(Files.exists(stackRoot.resolve(MPACK_NAME)));
    Assert.assertTrue(manager.getMpackMap().isEmpty());
    assertRequestStagingEmpty();
    EasyMock.verify(mpackDAO, stackDAO);
  }

  @Test
  public void testRestartQuarantinesPublishedFilesWithoutDatabaseRow() throws Exception {
    Path metadata = createRepositoryMpack();
    expectAvailableChecks();
    EasyMock.expect(mpackDAO.create(EasyMock.anyObject(MpackEntity.class)))
        .andThrow(new AssertionError("simulated process interruption"));
    EasyMock.replay(mpackDAO, stackDAO);
    Assert.assertThrows(AssertionError.class, () -> manager.registerMpack(requestFor(metadata)));
    Assert.assertTrue(Files.exists(staging.resolve(MPACK_NAME).resolve(MPACK_VERSION)));
    EasyMock.reset(mpackDAO, stackDAO);
    EasyMock.expect(mpackDAO.findByNameVersion(MPACK_NAME, MPACK_VERSION))
        .andReturn(Collections.emptyList());
    EasyMock.replay(mpackDAO, stackDAO);
    MpackManager recovered = new MpackManager(staging.toFile(), stackRoot.toFile(), mpackDAO, stackDAO);
    Assert.assertTrue(recovered.getMpackMap().isEmpty());
    Assert.assertFalse(Files.exists(staging.resolve(MPACK_NAME).resolve(MPACK_VERSION)));
    Assert.assertFalse(Files.exists(stackRoot.resolve(MPACK_NAME).resolve(MPACK_VERSION)));
    try (java.util.stream.Stream<Path> entries = Files.list(staging.resolve("staging/quarantine"))) {
      Assert.assertEquals(1, entries.count());
    }
    EasyMock.verify(mpackDAO, stackDAO);
  }

  @Test
  public void testFailedCatalogDeletionRetainsFiles() throws Exception {
    Path directory = Files.createDirectories(staging.resolve(MPACK_NAME).resolve(MPACK_VERSION));
    Files.writeString(directory.resolve("retained.txt"), "retained definition");
    MpackEntity entity = new MpackEntity();
    entity.setId(60L);
    entity.setMpackName(MPACK_NAME);
    entity.setMpackVersion(MPACK_VERSION);
    mpackDAO.removeCatalog(60L);
    EasyMock.expectLastCall().andThrow(new IllegalStateException("concurrent reference"));
    EasyMock.replay(mpackDAO, stackDAO);
    Assert.assertThrows(IOException.class, () -> manager.removeMpack(entity, null));
    Assert.assertTrue(Files.exists(directory.resolve("retained.txt")));
    Assert.assertTrue(Files.exists(directory.resolve(".ambari-deletion-pending")));
    EasyMock.verify(mpackDAO, stackDAO);
  }

  @Test
  public void testCommittedDeletionRemovesProjectionAfterDatabaseCommit() throws Exception {
    Path directory = Files.createDirectories(staging.resolve(MPACK_NAME).resolve(MPACK_VERSION));
    Files.writeString(directory.resolve("retained.txt"), "retained definition");
    MpackEntity entity = new MpackEntity();
    entity.setId(61L);
    entity.setMpackName(MPACK_NAME);
    entity.setMpackVersion(MPACK_VERSION);
    mpackDAO.removeCatalog(61L);
    EasyMock.expectLastCall().andAnswer(() -> {
      Assert.assertTrue(Files.exists(directory.resolve("retained.txt")));
      return null;
    });
    EasyMock.replay(mpackDAO, stackDAO);
    manager.removeMpack(entity, null);
    Assert.assertFalse(Files.exists(directory));
    Assert.assertTrue(Files.isDirectory(staging.resolve("staging/quarantine")));
    EasyMock.verify(mpackDAO, stackDAO);
  }

  @Test
  public void testRestartCompletesDatabaseBackedPublication() throws Exception {
    Path metadata = createRepositoryMpack();
    expectAvailableChecks();
    EasyMock.expect(mpackDAO.create(EasyMock.anyObject(MpackEntity.class))).andReturn(51L);
    EasyMock.expect(stackDAO.find(MPACK_NAME, MPACK_VERSION)).andReturn(null);
    stackDAO.create(EasyMock.anyObject(StackEntity.class));
    EasyMock.expectLastCall().andThrow(new AssertionError("simulated process interruption"));
    EasyMock.replay(mpackDAO, stackDAO);
    Assert.assertThrows(AssertionError.class, () -> manager.registerMpack(requestFor(metadata)));
    EasyMock.reset(mpackDAO, stackDAO);
    MpackEntity entity = new MpackEntity();
    entity.setId(51L);
    entity.setMpackName(MPACK_NAME);
    entity.setMpackVersion(MPACK_VERSION);
    entity.setMpackUri(metadata.toUri().toString());
    EasyMock.expect(mpackDAO.findByNameVersion(MPACK_NAME, MPACK_VERSION))
        .andReturn(Collections.singletonList(entity));
    EasyMock.expect(stackDAO.find(MPACK_NAME, MPACK_VERSION)).andReturn(null).times(2);
    stackDAO.create(EasyMock.anyObject(StackEntity.class));
    EasyMock.expectLastCall();
    EasyMock.replay(mpackDAO, stackDAO);
    MpackManager recovered = new MpackManager(staging.toFile(), stackRoot.toFile(), mpackDAO, stackDAO);
    Assert.assertEquals(MPACK_NAME, recovered.getMpackMap().get(51L).getName());
    Assert.assertFalse(Files.exists(staging.resolve(MPACK_NAME).resolve(MPACK_VERSION)
        .resolve(".ambari-registration-pending")));
    EasyMock.verify(mpackDAO, stackDAO);
  }

  @Test
  public void testRollbackFailureRetainsDatabaseBackedDefinition() throws Exception {
    Path metadata = createRepositoryMpack();
    expectAvailableChecks();
    EasyMock.expect(mpackDAO.create(EasyMock.anyObject(MpackEntity.class))).andReturn(52L);
    EasyMock.expect(stackDAO.find(MPACK_NAME, MPACK_VERSION)).andReturn(null);
    stackDAO.create(EasyMock.anyObject(StackEntity.class));
    EasyMock.expectLastCall().andThrow(new AmbariException("database failure"));
    mpackDAO.removeById(52L);
    EasyMock.expectLastCall().andThrow(new IllegalStateException("rollback unavailable"));
    EasyMock.replay(mpackDAO, stackDAO);
    Assert.assertThrows(IOException.class, () -> manager.registerMpack(requestFor(metadata)));
    Assert.assertTrue(Files.exists(staging.resolve(MPACK_NAME).resolve(MPACK_VERSION).resolve("mpack.json")));
    Assert.assertTrue(Files.isSymbolicLink(stackRoot.resolve(MPACK_NAME).resolve(MPACK_VERSION)));
    EasyMock.verify(mpackDAO, stackDAO);
  }

  @Test
  public void testCompilerProducedHostArchiveImportsThroughRealManager() throws Exception {
    String fixture = System.getProperty("mpack.host.fixture");
    org.junit.Assume.assumeNotNull(fixture);
    Path fixtureRoot = Path.of(fixture);
    org.apache.ambari.server.configuration.Configuration configuration =
        EasyMock.createMock(org.apache.ambari.server.configuration.Configuration.class);
    EasyMock.expect(configuration.getProperty("mpack.signing.key.file"))
        .andReturn(fixtureRoot.resolve("../signing.key").normalize().toString()).times(2);
    java.lang.reflect.Field field = MpackManager.class.getDeclaredField("configuration");
    field.setAccessible(true);
    field.set(manager, configuration);
    EasyMock.expect(mpackDAO.findByNameVersion("http-authoring-example", "0.1.0"))
        .andReturn(Collections.emptyList()).times(2);
    EasyMock.expect(stackDAO.find("http-authoring-example", "0.1.0")).andReturn(null).times(3);
    EasyMock.expect(mpackDAO.create(EasyMock.anyObject(MpackEntity.class))).andAnswer(() -> {
      MpackEntity entity = (MpackEntity) EasyMock.getCurrentArguments()[0];
      Assert.assertEquals(64, entity.getContentDigest().length());
      return 70L;
    });
    stackDAO.create(EasyMock.anyObject(StackEntity.class));
    EasyMock.expectLastCall();
    MpackEntity registered = new MpackEntity();
    registered.setId(70L);
    registered.setMpackName("http-authoring-example");
    registered.setMpackVersion("0.1.0");
    registered.setContentDigest(new com.google.gson.Gson().fromJson(Files.readString(fixtureRoot.resolve("mpack.json")),
        org.apache.ambari.server.state.Mpack.class).getPackageDigest());
    EasyMock.expect(mpackDAO.findByNameVersion("http-authoring-example", "0.1.0"))
        .andReturn(Collections.singletonList(registered));
    StackEntity registeredStack = new StackEntity();
    registeredStack.setMpackId(70L);
    EasyMock.expect(stackDAO.find("http-authoring-example", "0.1.0")).andReturn(registeredStack);
    EasyMock.replay(mpackDAO, stackDAO, configuration);
    MpackResponse response = manager.registerMpack(requestFor(fixtureRoot.resolve("mpack.json")));
    Assert.assertEquals(Long.valueOf(70), response.getId());
    Path service = staging.resolve("http-authoring-example/0.1.0/services/HTTP_ECHO");
    Assert.assertTrue(Files.isRegularFile(service.resolve("metainfo.xml")));
    Assert.assertTrue(Files.isRegularFile(service.resolve("package/manifest-service.json")));
    Assert.assertTrue(Files.isRegularFile(service.resolve("configuration/http.xml")));
    MpackResponse replay = manager.registerMpack(requestFor(fixtureRoot.resolve("mpack.json")));
    Assert.assertEquals(response.getId(), replay.getId());
    EasyMock.verify(mpackDAO, stackDAO, configuration);
  }

  @Test
  public void testHostArchiveTamperingAndWrongTrustKeyAreRejected() throws Exception {
    String fixture = System.getProperty("mpack.host.fixture");
    org.junit.Assume.assumeNotNull(fixture);
    Path fixtureRoot = Path.of(fixture);
    org.apache.ambari.server.state.Mpack metadata = new com.google.gson.Gson().fromJson(
        Files.readString(fixtureRoot.resolve("mpack.json")), org.apache.ambari.server.state.Mpack.class);
    Path wrongKey = repository.resolve("wrong.key");
    Files.writeString(wrongKey, "deliberately-wrong-test-key");
    org.apache.ambari.server.configuration.Configuration configuration =
        EasyMock.createMock(org.apache.ambari.server.configuration.Configuration.class);
    EasyMock.expect(configuration.getProperty("mpack.signing.key.file"))
        .andReturn(wrongKey.toString()).times(2);
    java.lang.reflect.Field field = MpackManager.class.getDeclaredField("configuration");
    field.setAccessible(true);
    field.set(manager, configuration);
    EasyMock.replay(mpackDAO, stackDAO, configuration);
    Assert.assertThrows(IOException.class,
        () -> manager.verifyAuthoringArchive(metadata, fixtureRoot.resolve("definition.tar.gz")));
    Path modified = repository.resolve("modified.tar.gz");
    Files.writeString(modified, "not-the-authenticated-archive");
    Assert.assertThrows(IOException.class, () -> manager.verifyAuthoringArchive(metadata, modified));
    EasyMock.verify(mpackDAO, stackDAO, configuration);
  }

  private void expectAvailableChecks() {
    EasyMock.expect(mpackDAO.findByNameVersion(MPACK_NAME, MPACK_VERSION))
        .andReturn(Collections.emptyList()).times(2);
    EasyMock.expect(stackDAO.find(MPACK_NAME, MPACK_VERSION)).andReturn(null).times(2);
  }

  private Path createRepositoryMpack() throws IOException {
    Path metadata = repository.resolve("mpack.json");
    Files.writeString(metadata,
        "{\"id\":\"test\",\"name\":\"TEST\",\"version\":\"1.0\","
            + "\"definition\":\"test-definition.tar.gz\",\"modules\":[]}",
        StandardCharsets.UTF_8);
    writeArchive(repository.resolve(DEFINITION), "test-definition/README.txt", "test package");
    return metadata;
  }

  private MpackRequest requestFor(Path metadata) {
    MpackRequest request = new MpackRequest();
    request.setMpackUri(metadata.toUri().toString());
    return request;
  }

  private void assertRequestStagingEmpty() throws IOException {
    try (java.util.stream.Stream<Path> children = Files.list(staging.resolve("staging"))) {
      Assert.assertEquals(0, children.count());
    }
  }

  private void writeArchive(Path archive, String entryName, String contents) throws IOException {
    byte[] content = contents.getBytes(StandardCharsets.UTF_8);
    try (OutputStream fileOutput = Files.newOutputStream(archive);
        GzipCompressorOutputStream gzipOutput = new GzipCompressorOutputStream(fileOutput);
        TarArchiveOutputStream tarOutput = new TarArchiveOutputStream(gzipOutput)) {
      TarArchiveEntry entry = new TarArchiveEntry(entryName);
      entry.setSize(content.length);
      tarOutput.putArchiveEntry(entry);
      tarOutput.write(content);
      tarOutput.closeArchiveEntry();
    }
  }
}
