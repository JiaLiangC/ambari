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
package org.apache.ambari.server.api.services;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.junit.Assert;
import org.junit.Test;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class MpackCollectionReaderTest {
  static byte[] collection(String[] paths, byte[][] bodies, boolean damaged) throws Exception {
    List<java.util.Map<String, Object>> records = new java.util.ArrayList<>();
    for (int i = 0; i < bodies.length; i++) {
      String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bodies[i]));
      records.add(java.util.Map.of("publisher", "team", "name", "demo-" + i,
          "version", "1.0.0", "path", String.format(java.util.Locale.ROOT, "packages/%04d.mpack", i + 1),
          "size", bodies[i].length, "sha256", damaged && i == 0 ? "0".repeat(64) : digest));
    }
    byte[] index = new Gson().toJson(java.util.Map.of("format", "mpack-collection/v1",
        "version", "1.0.0", "packages", records)).getBytes(StandardCharsets.UTF_8);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(output)) {
      store(zip, "collection.json", index);
      for (int i = 0; i < bodies.length; i++) {
        store(zip, paths[i], bodies[i]);
      }
    }
    return output.toByteArray();
  }

  static byte[] valid() throws Exception {
    return collection(new String[] {"packages/0001.mpack", "packages/0002.mpack"},
        new byte[][] {"first release".getBytes(StandardCharsets.UTF_8),
            "second release".getBytes(StandardCharsets.UTF_8)}, false);
  }

  private static byte[] altered(String field) throws Exception {
    byte[][] bodies = new byte[2][];
    JsonObject index;
    try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(valid()))) {
      zip.getNextEntry();
      index = JsonParser.parseString(new String(zip.readAllBytes(), StandardCharsets.UTF_8)).getAsJsonObject();
      for (int i = 0; i < bodies.length; i++) {
        zip.getNextEntry();
        bodies[i] = zip.readAllBytes();
      }
    }
    if ("duplicate".equals(field)) {
      index.getAsJsonArray("packages").get(1).getAsJsonObject().addProperty("name", "demo-0");
    } else {
      index.getAsJsonArray("packages").get(0).getAsJsonObject().addProperty("size", Long.MAX_VALUE);
    }
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(output)) {
      store(zip, "collection.json", new Gson().toJson(index).getBytes(StandardCharsets.UTF_8));
      store(zip, "packages/0001.mpack", bodies[0]);
      store(zip, "packages/0002.mpack", bodies[1]);
    }
    return output.toByteArray();
  }

  private static void store(ZipOutputStream zip, String name, byte[] content) throws IOException {
    CRC32 crc = new CRC32();
    crc.update(content);
    ZipEntry entry = new ZipEntry(name);
    entry.setMethod(ZipEntry.STORED);
    entry.setSize(content.length);
    entry.setCrc(crc.getValue());
    zip.putNextEntry(entry);
    zip.write(content);
    zip.closeEntry();
  }

  @Test
  public void readsOnlyDeclaredExactReleaseBytes() throws Exception {
    try (MpackCollectionReader.Stage stage = MpackCollectionReader.read(new ByteArrayInputStream(valid()))) {
      Assert.assertEquals(2, stage.packages.size());
      Assert.assertArrayEquals("first release".getBytes(StandardCharsets.UTF_8),
          java.nio.file.Files.readAllBytes(stage.packages.get(0).file));
    }
  }

  @Test
  public void rejectsWrongHashAndUntrustedPaths() throws Exception {
    byte[][] bodies = {"release".getBytes(StandardCharsets.UTF_8)};
    for (byte[] content : new byte[][] {
        collection(new String[] {"packages/0001.mpack"}, bodies, true),
        collection(new String[] {"../packages/0001.mpack"}, bodies, false),
        collection(new String[] {"packages/0001.mpack", "extra.mpack"},
            new byte[][] {bodies[0], bodies[0]}, false)
    }) {
      try {
        MpackCollectionReader.read(new ByteArrayInputStream(content)).close();
        Assert.fail("Undeclared or damaged package was accepted");
      } catch (IOException expected) {
        Assert.assertFalse(expected.getMessage().contains("release"));
      }
    }
  }

  @Test
  public void rejectsUnsupportedContractBeforeStaging() throws Exception {
    byte[] bytes = valid();
    // A ZIP with no index is not a collection even if it includes a signed release.
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(output)) {
      store(zip, "packages/0001.mpack", bytes);
    }
    Assert.assertThrows(IOException.class,
        () -> MpackCollectionReader.read(new ByteArrayInputStream(output.toByteArray())));
  }

  @Test
  public void rejectsDuplicateReleaseIdentityAndOversizedDeclaration() throws Exception {
    for (String field : new String[] {"duplicate", "size"}) {
      Assert.assertThrows(IOException.class,
          () -> MpackCollectionReader.read(new ByteArrayInputStream(altered(field))));
    }
  }
}
