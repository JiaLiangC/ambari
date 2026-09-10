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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.ambari.server.configuration.Configuration;
import org.apache.ambari.server.state.Mpack;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/** Verifies immutable publisher releases against administrator-owned trust configuration. */
public final class MpackTrust {
  private static final Gson JSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();

  private MpackTrust() {
  }

  public static void verify(Mpack mpack, Path archive, Configuration configuration) throws IOException {
    try {
      String publisher = mpack.getPublisher();
      String packageName = mpack.getPackageName();
      if (publisher == null || !publisher.matches("[a-z][a-z0-9-]{0,62}")
          || packageName == null || !packageName.matches("[A-Za-z][A-Za-z0-9_.-]{0,99}")
          || !mpack.getName().equals("publisher-" + publisher.length() + "-" + publisher + "-" + packageName)
          || !mpack.getName().equals(mpack.getMpackId())
          || !"Ed25519".equals(mpack.getSignatureAlgorithm())
          || !"mpack-publisher/v1".equals(mpack.getSignatureFormat())
          || !"mpack.ambari.apache.org/host-service/v1".equals(mpack.getAuthoringFormat())
          || !isDigest(mpack.getDefinitionSha256()) || !isDigest(mpack.getPackageDigest())
          || !isDigest(mpack.getManifestDigest()) || !isDigest(mpack.getSignatureKeyId())
          || mpack.getAuthoringMetadata() == null) {
        throw new IOException("Invalid publisher release identity or format");
      }
      String trustFile = configuration == null ? null : configuration.getProperty("mpack.trust.store.file");
      if (trustFile == null || trustFile.isBlank()) {
        throw new IOException("Publisher import requires mpack.trust.store.file");
      }
      Path path = Path.of(trustFile);
      if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) > 1024 * 1024) {
        throw new IOException("Invalid publisher trust store");
      }
      JsonObject trust = JsonParser.parseString(Files.readString(path, StandardCharsets.UTF_8)).getAsJsonObject();
      if (trust.get("version").getAsInt() != 1) {
        throw new IOException("Unsupported publisher trust store format");
      }
      JsonObject key = trust.getAsJsonObject("publishers").getAsJsonObject(publisher)
          .getAsJsonObject("keys").getAsJsonObject(mpack.getSignatureKeyId());
      Instant now = Instant.now();
      if (key == null || !"active".equals(key.get("status").getAsString())
          || key.has("notBefore") && now.isBefore(Instant.parse(key.get("notBefore").getAsString()))
          || key.has("notAfter") && !now.isBefore(Instant.parse(key.get("notAfter").getAsString()))) {
        throw new IOException("Publisher key is unknown, revoked or outside its validity interval");
      }
      byte[] publicKey = Base64.getDecoder().decode(key.get("publicKey").getAsString());
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      if (!HexFormat.of().formatHex(digest.digest(publicKey)).equals(mpack.getSignatureKeyId())) {
        throw new IOException("Publisher key identity mismatch");
      }
      try (InputStream input = Files.newInputStream(archive)) {
        byte[] buffer = new byte[64 * 1024];
        int count;
        while ((count = input.read(buffer)) != -1) {
          digest.update(buffer, 0, count);
        }
      }
      if (!MessageDigest.isEqual(digest.digest(), HexFormat.of().parseHex(mpack.getDefinitionSha256()))) {
        throw new IOException("Publisher artifact digest mismatch");
      }
      Signature verifier = Signature.getInstance("Ed25519");
      verifier.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(publicKey)));
      verifier.update(envelope(mpack.getAuthoringMetadata()));
      byte[] signature = Base64.getDecoder().decode(mpack.getSignature());
      if (signature.length != 64 || !verifier.verify(signature)) {
        throw new IOException("Publisher signature verification failed");
      }
      Map<String, String> compatibility = mpack.getCompatibility();
      if (compatibility != null) {
        if (compatibility.containsKey("ambari")) {
          requireVersion(configuration.getServerVersion(), compatibility.get("ambari"));
        }
        if (compatibility.containsKey("agentSdk")) {
          requireVersion("1", compatibility.get("agentSdk"));
        }
        if (compatibility.containsKey("dependencyProtocol")
            && !"binding/v1".equals(compatibility.get("dependencyProtocol"))) {
          throw new IOException("Unsupported dependency protocol");
        }
      }
    } catch (GeneralSecurityException | RuntimeException error) {
      // Do not expose key material, input metadata or trust-store paths in diagnostics.
      throw new IOException("Publisher authentication failed");
    }
  }

  private static boolean isDigest(String value) {
    return value != null && value.matches("[a-f0-9]{64}");
  }

  static void requireVersion(String actual, String requirement) throws IOException {
    if ("*".equals(requirement)) {
      return;
    }
    if (actual == null || !actual.matches("[0-9]+(\\.[0-9]+){0,3}([-+].*)?")) {
      throw new IOException("Runtime version cannot be established");
    }
    String[] current = actual.split("[-+]", 2)[0].split("\\.");
    for (String clause : requirement.split(",", -1)) {
      Matcher matcher = Pattern.compile("(>=|<=|>|<|=)?([0-9]+(?:\\.[0-9]+){0,3})").matcher(clause.trim());
      if (!matcher.matches()) {
        throw new IOException("Unsupported version requirement");
      }
      String[] requested = matcher.group(2).split("\\.");
      int comparison = 0;
      for (int index = 0; index < Math.max(current.length, requested.length) && comparison == 0; index++) {
        comparison = new java.math.BigInteger(index < current.length ? current[index] : "0")
            .compareTo(new java.math.BigInteger(index < requested.length ? requested[index] : "0"));
      }
      String operator = matcher.group(1) == null ? "=" : matcher.group(1);
      boolean compatible = switch (operator) {
        case ">=" -> comparison >= 0;
        case "<=" -> comparison <= 0;
        case ">" -> comparison > 0;
        case "<" -> comparison < 0;
        default -> comparison == 0;
      };
      if (!compatible) {
        throw new IOException("Package runtime compatibility requirement is not satisfied");
      }
    }
  }

  static byte[] envelope(JsonObject metadata) throws IOException {
    JsonObject unsigned = metadata.deepCopy();
    unsigned.remove("signature");
    return ("mpack-publisher/v1\n" + canonical(unsigned) + "\n").getBytes(StandardCharsets.US_ASCII);
  }

  private static String canonical(JsonElement value) throws IOException {
    if (value.isJsonObject()) {
      Map<String, JsonElement> sorted = new TreeMap<>();
      value.getAsJsonObject().entrySet().forEach(entry -> sorted.put(entry.getKey(), entry.getValue()));
      StringBuilder result = new StringBuilder("{");
      for (Map.Entry<String, JsonElement> entry : sorted.entrySet()) {
        if (result.length() > 1) {
          result.append(',');
        }
        result.append(ascii(JSON.toJson(entry.getKey()))).append(':').append(canonical(entry.getValue()));
      }
      return result.append('}').toString();
    }
    if (value.isJsonArray()) {
      StringBuilder result = new StringBuilder("[");
      for (JsonElement item : value.getAsJsonArray()) {
        if (result.length() > 1) {
          result.append(',');
        }
        result.append(canonical(item));
      }
      return result.append(']').toString();
    }
    if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()
        && !value.toString().matches("-?(0|[1-9][0-9]*)")) {
      throw new IOException("Release metadata numbers must be integers");
    }
    return ascii(JSON.toJson(value));
  }

  private static String ascii(String value) {
    StringBuilder result = new StringBuilder();
    for (char character : value.toCharArray()) {
      if (character > 127) {
        result.append(String.format("\\u%04x", (int) character));
      } else {
        result.append(character);
      }
    }
    return result.toString();
  }
}
