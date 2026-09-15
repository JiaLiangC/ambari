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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/** Stages a bounded offline collection; the ordinary importer authenticates each inner release. */
final class MpackCollectionReader {
  private static final long MAX_INDEX = 1024 * 1024;
  private static final long MAX_PACKAGE = 513L * 1024 * 1024 + 65536;
  private static final long MAX_COLLECTION = 2L * 1024 * 1024 * 1024;
  private static final int MAX_PACKAGES = 32;

  private MpackCollectionReader() {
  }

  static final class PackageEntry {
    final String path;
    final Path file;

    PackageEntry(String path, Path file) {
      this.path = path;
      this.file = file;
    }
  }

  static final class Stage implements AutoCloseable {
    private final Path directory;
    final List<PackageEntry> packages = new ArrayList<>();

    Stage() throws IOException {
      directory = Files.createTempDirectory("mpack-collection-");
    }

    @Override
    public void close() throws IOException {
      for (PackageEntry entry : packages) {
        Files.deleteIfExists(entry.file);
      }
      Files.deleteIfExists(directory);
    }
  }

  private static final class LimitedInput extends InputStream {
    private final InputStream delegate;
    private long bytes;
    private final long deadline = System.nanoTime() + TimeUnit.MINUTES.toNanos(10);

    LimitedInput(InputStream delegate) {
      this.delegate = delegate;
    }

    @Override
    public int read() throws IOException {
      byte[] single = new byte[1];
      return read(single, 0, 1) == -1 ? -1 : single[0] & 255;
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
      if (bytes > MAX_COLLECTION || System.nanoTime() > deadline) {
        throw new IOException("Collection exceeds transfer limits");
      }
      int count = delegate.read(buffer, offset, length);
      if (count > 0 && (bytes += count) > MAX_COLLECTION) {
        throw new IOException("Collection exceeds transfer limits");
      }
      return count;
    }
  }

  private static boolean keys(JsonObject object, String... names) {
    return object.keySet().equals(Set.of(names));
  }

  private static JsonArray index(ZipInputStream zip) throws IOException {
    ZipEntry entry = zip.getNextEntry();
    if (entry == null || !"collection.json".equals(entry.getName())
        || entry.isDirectory() || entry.getMethod() != ZipEntry.STORED
        || entry.getSize() < 1 || entry.getSize() > MAX_INDEX) {
      throw new IOException("Invalid collection inventory");
    }
    ByteArrayOutputStream content = new ByteArrayOutputStream();
    copy(zip, content, MAX_INDEX, null);
    zip.closeEntry();
    try {
      JsonObject document = JsonParser.parseString(content.toString(java.nio.charset.StandardCharsets.UTF_8))
          .getAsJsonObject();
      if (!keys(document, "format", "version", "packages")
          || !"mpack-collection/v1".equals(document.get("format").getAsString())
          || !document.get("version").getAsString().matches("[0-9]+(\\.[0-9]+){1,3}([-+][A-Za-z0-9.-]+)?")) {
        throw new IOException("Unsupported collection contract");
      }
      JsonArray packages = document.getAsJsonArray("packages");
      if (packages == null || packages.size() == 0 || packages.size() > MAX_PACKAGES) {
        throw new IOException("Invalid collection size");
      }
      return packages;
    } catch (RuntimeException error) {
      throw new IOException("Invalid collection metadata");
    }
  }

  static Stage read(InputStream source) throws IOException {
    // ZipInputStream never writes untrusted entry names as filesystem paths.
    try (ZipInputStream zip = new ZipInputStream(new LimitedInput(source))) {
      JsonArray inventory = index(zip);
      Stage stage = new Stage();
      try {
        Set<String> identities = new HashSet<>();
        long total = 0;
        for (int number = 0; number < inventory.size(); number++) {
          JsonObject expected = inventory.get(number).getAsJsonObject();
          if (!keys(expected, "publisher", "name", "version", "path", "sha256", "size")) {
            throw new IOException("Invalid package inventory");
          }
          String path = String.format(java.util.Locale.ROOT, "packages/%04d.mpack", number + 1);
          String publisher = expected.get("publisher").getAsString();
          String name = expected.get("name").getAsString();
          String version = expected.get("version").getAsString();
          String digest = expected.get("sha256").getAsString();
          long size = expected.get("size").getAsLong();
          if (!path.equals(expected.get("path").getAsString())
              || !publisher.matches("[a-z][a-z0-9-]{0,62}")
              || !name.matches("[A-Za-z][A-Za-z0-9_.-]{0,99}")
              || !version.matches("[A-Za-z0-9][A-Za-z0-9_.-]*")
              || !digest.matches("[a-f0-9]{64}") || size < 1 || size > MAX_PACKAGE
              || (total += size) > MAX_COLLECTION
              || !identities.add(publisher + "/" + name + "/" + version)) {
            throw new IOException("Invalid package identity or limits");
          }
          ZipEntry entry = zip.getNextEntry();
          if (entry == null || !path.equals(entry.getName()) || entry.isDirectory()
              || entry.getMethod() != ZipEntry.STORED || entry.getSize() != size) {
            throw new IOException("Collection package does not match inventory");
          }
          Path file = Files.createTempFile(stage.directory, "release-", ".mpack");
          stage.packages.add(new PackageEntry(path, file));
          MessageDigest hash;
          try {
            hash = MessageDigest.getInstance("SHA-256");
          } catch (NoSuchAlgorithmException error) {
            throw new IOException("SHA-256 unavailable", error);
          }
          try (OutputStream output = Files.newOutputStream(file)) {
            if (copy(zip, output, size, hash) != size
                || !java.util.HexFormat.of().formatHex(hash.digest()).equals(digest)) {
              throw new IOException("Collection package digest or length mismatch");
            }
          }
          zip.closeEntry();
        }
        if (zip.getNextEntry() != null) {
          throw new IOException("Collection contains undeclared content");
        }
        return stage;
      } catch (IOException | RuntimeException error) {
        stage.close();
        throw error instanceof IOException ? (IOException) error : new IOException("Invalid collection metadata");
      }
    }
  }

  private static long copy(InputStream input, OutputStream output, long limit, MessageDigest hash) throws IOException {
    byte[] buffer = new byte[64 * 1024];
    long bytes = 0;
    int count;
    while ((count = input.read(buffer)) != -1) {
      if ((bytes += count) > limit) {
        throw new IOException("Collection entry exceeds its declared size");
      }
      output.write(buffer, 0, count);
      if (hash != null) {
        hash.update(buffer, 0, count);
      }
    }
    return bytes;
  }
}
