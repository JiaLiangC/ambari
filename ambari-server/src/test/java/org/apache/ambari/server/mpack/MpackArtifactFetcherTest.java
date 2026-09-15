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
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

public class MpackArtifactFetcherTest {
  private final MpackArtifactFetcher fetcher = new MpackArtifactFetcher();

  @Test
  public void testParsesOnlyUnambiguousSupportedSources() {
    Assert.assertEquals(URI.create("https://store.example/releases/package.mpack"),
        fetcher.parse("https://store.example/releases/./package.mpack"));
    for (String source : List.of("relative.mpack", "ftp://store.example/package.mpack",
        "https://user@store.example/package.mpack", "https://store.example/package.mpack?token=x",
        "https://store.example/package.mpack#release", "file://remote.example/package.mpack")) {
      Assert.assertThrows(IllegalArgumentException.class, () -> fetcher.parse(source));
    }
  }

  @Test
  public void testFileTransferEnforcesDeclaredLimit() throws Exception {
    Path directory = Files.createTempDirectory("mpack-fetcher-");
    Path source = directory.resolve("source.mpack");
    Path target = directory.resolve("target.mpack");
    Path rejected = directory.resolve("rejected.mpack");
    try {
      Files.writeString(source, "test");
      fetcher.download(source.toUri(), target, 4, null, null);
      Assert.assertEquals("test", Files.readString(target));
      Assert.assertThrows(IOException.class,
          () -> fetcher.download(source.toUri(), rejected, 3, null, null));
      Assert.assertFalse(Files.exists(rejected));
    } finally {
      Files.deleteIfExists(rejected);
      Files.deleteIfExists(target);
      Files.deleteIfExists(source);
      Files.deleteIfExists(directory);
    }
  }
}
