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
